//! Ephemeral-key event attestation, ported to no_std.
//!
//! Same primitive as the esp-idf prototype -- derive a fresh Ed25519 keypair,
//! sign a structured payload, zeroize the private key -- with three changes
//! that the bare-metal environment either forces or makes worth taking:
//!
//! 1. Entropy comes from a borrowed [`Entropy`] handle, so the key cannot be
//!    derived unless a true-entropy source is provably live. See
//!    [`crate::entropy`].
//! 2. No allocator. The payload is encoded with `postcard::to_slice` into a
//!    stack buffer and hex is rendered into `heapless::String`. `to_allocvec`
//!    is not even reachable: postcard is built without its `alloc` feature.
//! 3. Every attestation signs a fixed-length payload regardless of event type.
//!    See [`ATTESTATION_PAYLOAD_LEN`].

use core::sync::atomic::{AtomicU32, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use esp_hal::time::Instant;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::entropy::Entropy;

/// Length of the signed payload, identical for every attestation.
///
/// Traffic-analysis hygiene. A postcard encoding of [`AttestationPayload`] is
/// variable-length: varint fields shrink for small timestamps and counters, and
/// future event variants will carry different field counts. If we signed the
/// natural encoding, the length of an attestation would leak which event
/// produced it and roughly how long the device had been powered -- before any
/// transport tier gets a chance to hide anything.
///
/// So the encoder writes into a zero-filled buffer of this size and the whole
/// buffer is signed. The padding is *inside* the signed region, so it cannot be
/// stripped or rewritten without invalidating the signature.
///
/// Two limits worth stating plainly:
///
/// - This fixes the *emitted* length only. If a transport ever carries the
///   payload in cleartext, the trailing zero run still reveals the true encoded
///   length to anyone who can read the bytes. Concealing that is the transport
///   layer's problem, not this one -- see `docs/NOSTD_ENTROPY_SPIKE.md`.
/// - 32 bytes is headroom, not a measurement: the current worst case is 18
///   bytes (1 version + 2 event + 10 timestamp varint + 5 counter varint).
///   `create` fails closed if a future variant overflows it.
pub const ATTESTATION_PAYLOAD_LEN: usize = 32;

/// Events that can trigger an attestation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AttestationEvent {
    /// Physical button press.
    ButtonPress { gpio: u8 },
    /// Future: other physical events (switch, sensor threshold, etc.)
    Unknown,
}

/// The payload that gets signed.
#[derive(Debug, Serialize, Deserialize)]
struct AttestationPayload {
    /// Protocol version (for future compatibility).
    version: u8,
    /// The triggering event.
    event: AttestationEvent,
    /// Milliseconds since device boot.
    timestamp_ms: u64,
    /// Monotonic counter (resets on power cycle).
    counter: u32,
}

/// Failure modes of [`Attestation::create`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationError {
    /// The encoded payload did not fit in [`ATTESTATION_PAYLOAD_LEN`] bytes.
    ///
    /// Fails closed: a payload we cannot pad to the fixed length would leak its
    /// event type by length, so we decline to sign it at all.
    PayloadTooLong,
}

/// Ephemeral signing key.
///
/// Deliberately *not* `#[derive(ZeroizeOnDrop)]`. The esp-idf prototype derived
/// it and then marked its only field `#[zeroize(skip)]`, so the derive zeroized
/// nothing. That was harmless only because dalek already does the work:
/// ed25519-dalek 2.2.0 `signing.rs:659` implements `Drop for SigningKey` as
/// `self.secret_key.zeroize()`, gated on the `zeroize` feature, which this
/// crate enables. Reproducing the derive here would restate a guarantee we do
/// not provide. This newtype exists only to keep the key's scope visibly narrow.
struct EphemeralSigningKey(SigningKey);

impl EphemeralSigningKey {
    /// Derive a fresh keypair from the true-entropy source.
    fn new(entropy: &Entropy<'_>) -> Self {
        let mut seed = [0u8; 32];
        entropy.read(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        // The seed is ours to clear; the key clears itself on drop.
        seed.zeroize();
        Self(key)
    }
}

/// A completed attestation. Public data only -- the private key is already gone.
pub struct Attestation {
    event: AttestationEvent,
    timestamp_ms: u64,
    public_key: [u8; 32],
    signature: [u8; 64],
    /// The exact bytes that were signed, padding included. A verifier needs
    /// these verbatim; it should decode the event with
    /// `postcard::take_from_bytes`, which stops at the end of the struct and
    /// returns the padding as the remainder.
    signed_payload: [u8; ATTESTATION_PAYLOAD_LEN],
}

impl Attestation {
    /// Create an attestation for `event`.
    ///
    /// The `entropy` borrow is the point of the whole spike: this function
    /// cannot be called without a live true-entropy source, and that is checked
    /// by the compiler rather than at runtime.
    pub fn create(
        entropy: &Entropy<'_>,
        event: AttestationEvent,
    ) -> Result<Self, AttestationError> {
        let timestamp_ms = now_ms();
        let counter = increment_counter();

        let payload = AttestationPayload {
            version: 1,
            event,
            timestamp_ms,
            counter,
        };

        // Zero-filled canvas; the encoder fills the front, the rest stays zero.
        // Signing covers the whole canvas, so every attestation signs exactly
        // ATTESTATION_PAYLOAD_LEN bytes whatever the event was.
        let mut signed_payload = [0u8; ATTESTATION_PAYLOAD_LEN];
        postcard::to_slice(&payload, &mut signed_payload)
            .map_err(|_| AttestationError::PayloadTooLong)?;

        // The key exists only for the next three lines.
        let signing_key = EphemeralSigningKey::new(entropy);
        let public_key = signing_key.0.verifying_key().to_bytes();
        let signature = signing_key.0.sign(&signed_payload).to_bytes();
        drop(signing_key);

        Ok(Self {
            event,
            timestamp_ms,
            public_key,
            signature,
            signed_payload,
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

    pub fn signed_payload_bytes(&self) -> &[u8; ATTESTATION_PAYLOAD_LEN] {
        &self.signed_payload
    }

    pub fn public_key_hex(&self) -> heapless::String<64> {
        hex_encode(&self.public_key)
    }

    pub fn signature_hex(&self) -> heapless::String<128> {
        hex_encode(&self.signature)
    }

    pub fn signed_payload_hex(&self) -> heapless::String<64> {
        hex_encode(&self.signed_payload)
    }
}

/// Monotonic counter (resets on power cycle).
static COUNTER: AtomicU32 = AtomicU32::new(0);

fn increment_counter() -> u32 {
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Milliseconds since boot.
fn now_ms() -> u64 {
    Instant::now().duration_since_epoch().as_millis()
}

/// Hex encoding into a fixed-capacity string.
///
/// `N` is `2 * bytes.len()` at every call site, so the pushes cannot fail; the
/// debug assertion documents that rather than trusting it silently.
fn hex_encode<const N: usize>(bytes: &[u8]) -> heapless::String<N> {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    debug_assert_eq!(N, bytes.len() * 2, "hex buffer must be exactly 2x input");

    let mut s = heapless::String::new();
    for &b in bytes {
        let _ = s.push(HEX_CHARS[(b >> 4) as usize] as char);
        let _ = s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}
