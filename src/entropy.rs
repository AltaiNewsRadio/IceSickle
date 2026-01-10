//! Hardware Random Number Generator wrapper
//!
//! The ESP32-S3 has a true hardware RNG that sources entropy from:
//! - RF noise (when WiFi/BT enabled)
//! - Thermal noise (always available)
//!
//! We use the ESP-IDF `esp_fill_random()` which handles the underlying
//! hardware and provides cryptographically suitable randomness.
//!
//! IMPORTANT: We disable WiFi/BT in this project, so entropy comes solely
//! from thermal noise. This is still considered cryptographically secure
//! per Espressif documentation, but the rate is lower.

use rand_core::{CryptoRng, RngCore};

/// Hardware RNG backed by ESP32 true random number generator
pub struct HardwareRng {
    // Zero-sized - all state is in hardware
    _private: (),
}

impl HardwareRng {
    /// Initialize the hardware RNG
    ///
    /// This doesn't actually need initialization on ESP32, but we keep
    /// the constructor pattern for API consistency and future portability.
    pub fn new() -> anyhow::Result<Self> {
        // Verify RNG is functional by reading a test value
        let mut test = [0u8; 4];
        unsafe {
            esp_idf_sys::esp_fill_random(test.as_mut_ptr() as *mut _, test.len());
        }

        // Basic sanity check (not all zeros - would indicate RNG failure)
        if test == [0, 0, 0, 0] {
            anyhow::bail!("Hardware RNG sanity check failed - returned all zeros");
        }

        Ok(Self { _private: () })
    }

    /// Fill a buffer with random bytes from hardware RNG
    pub fn fill_bytes(&self, dest: &mut [u8]) {
        unsafe {
            esp_idf_sys::esp_fill_random(dest.as_mut_ptr() as *mut _, dest.len());
        }
    }
}

// Implement rand_core traits for compatibility with ed25519-dalek
impl RngCore for HardwareRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        HardwareRng::fill_bytes(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// Mark as cryptographically secure
impl CryptoRng for HardwareRng {}

// Also implement for &HardwareRng so we can use shared references
impl RngCore for &HardwareRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        HardwareRng::fill_bytes(self, &mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        HardwareRng::fill_bytes(self, &mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        HardwareRng::fill_bytes(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        HardwareRng::fill_bytes(self, dest);
        Ok(())
    }
}

impl CryptoRng for &HardwareRng {}
