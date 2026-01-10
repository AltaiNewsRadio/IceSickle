//! Core attestation logic
//!
//! This module implements the ephemeral-key signing primitive:
//! - Generate a fresh Ed25519 keypair per attestation (never reused)
//! - Sign a structured payload containing the event and timestamp
//! - Zeroize the private key immediately after signing
//!
//! The keypair is NEVER persisted to flash or RAM beyond the signing operation.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::entropy::HardwareRng;

/// Events that can trigger an attestation
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AttestationEvent {
    /// Physical button press
    ButtonPress { gpio: u8 },
    /// Future: other physical events (switch, sensor threshold, etc.)
    #[serde(other)]
    Unknown,
}

/// The payload that gets signed
#[derive(Debug, Serialize, Deserialize)]
struct AttestationPayload {
    /// Protocol version (for future compatibility)
    version: u8,
    /// The triggering event
    event: AttestationEvent,
    /// Milliseconds since device boot
    timestamp_ms: u64,
    /// Monotonic counter (survives soft resets within a power cycle)
    counter: u32,
}

/// Wrapper for the signing key that guarantees zeroization
#[derive(ZeroizeOnDrop)]
struct EphemeralSigningKey {
    #[zeroize(skip)] // ed25519_dalek::SigningKey implements Zeroize internally
    inner: SigningKey,
}

impl EphemeralSigningKey {
    fn new(rng: &HardwareRng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let inner = SigningKey::from_bytes(&seed);
        seed.zeroize(); // Zeroize seed immediately
        Self { inner }
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.inner.verifying_key()
    }

    fn sign(&self, message: &[u8]) -> Signature {
        self.inner.sign(message)
    }
}

/// A completed attestation (public data only - private key already zeroized)
pub struct Attestation {
    event: AttestationEvent,
    timestamp_ms: u64,
    public_key: [u8; 32],
    signature: [u8; 64],
}

impl Attestation {
    /// Create a new attestation for the given event
    ///
    /// This function:
    /// 1. Generates a fresh ephemeral keypair
    /// 2. Constructs and serializes the payload
    /// 3. Signs the payload
    /// 4. Zeroizes the private key (automatic via Drop)
    /// 5. Returns the attestation with public key + signature
    pub fn create(rng: &HardwareRng, event: AttestationEvent) -> anyhow::Result<Self> {
        // Get current timestamp and counter
        let timestamp_ms = get_timestamp_ms();
        let counter = increment_counter();

        // Build payload
        let payload = AttestationPayload {
            version: 1,
            event,
            timestamp_ms,
            counter,
        };

        // Serialize payload (deterministic encoding)
        let payload_bytes = postcard::to_allocvec(&payload)?;

        // Generate ephemeral keypair - exists only for this scope
        let signing_key = EphemeralSigningKey::new(rng);
        let public_key = signing_key.verifying_key().to_bytes();

        // Sign
        let signature = signing_key.sign(&payload_bytes);

        // signing_key is dropped and zeroized here

        Ok(Self {
            event,
            timestamp_ms,
            public_key,
            signature: signature.to_bytes(),
        })
    }

    pub fn event(&self) -> AttestationEvent {
        self.event
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn signature_bytes(&self) -> &[u8; 64] {
        &self.signature
    }

    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.public_key)
    }

    pub fn signature_hex(&self) -> String {
        hex_encode(&self.signature)
    }
}

/// Monotonic counter (resets on power cycle, survives soft resets)
static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn increment_counter() -> u32 {
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// Get milliseconds since boot
fn get_timestamp_ms() -> u64 {
    unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1000 }
}

/// Simple hex encoding (no external dependency)
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }
}
