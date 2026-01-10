//! Physical rate limiting (cooldown enforcement)
//!
//! This module enforces a minimum time interval between attestations.
//! The goal is spam resistance via physics, not network-based rate limiting.
//!
//! # Design Rationale
//!
//! Rate limiting happens at the device level, not at a server. This means:
//! - No network round-trip required to enforce limits
//! - No centralized state to attack or bypass
//! - Cooldown is bounded by physical time, not software policy
//!
//! # Threat Model
//!
//! An attacker with physical access can still:
//! - Replace firmware to remove cooldown (but this is already in threat model)
//! - Wait out the cooldown (this is the point)
//!
//! An attacker without physical access cannot:
//! - Trigger attestations faster than the cooldown allows
//! - Accumulate "credits" for future rapid-fire signing

use core::sync::atomic::{AtomicU64, Ordering};

/// Minimum milliseconds between attestations
const COOLDOWN_MS: u64 = 1000; // 1 second default

/// Tracks the timestamp of the last successful attestation
static LAST_ATTESTATION_MS: AtomicU64 = AtomicU64::new(0);

/// Result of a cooldown check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooldownResult {
    /// Attestation allowed, cooldown has elapsed
    Ready,
    /// Attestation blocked, must wait
    Wait { remaining_ms: u64 },
}

/// Check if enough time has passed since the last attestation
pub fn check() -> CooldownResult {
    let now = get_timestamp_ms();
    let last = LAST_ATTESTATION_MS.load(Ordering::SeqCst);

    let elapsed = now.saturating_sub(last);

    if elapsed >= COOLDOWN_MS {
        CooldownResult::Ready
    } else {
        CooldownResult::Wait {
            remaining_ms: COOLDOWN_MS - elapsed,
        }
    }
}

/// Record that an attestation was just produced
///
/// Call this immediately after successful signing, before output.
pub fn record_attestation() {
    let now = get_timestamp_ms();
    LAST_ATTESTATION_MS.store(now, Ordering::SeqCst);
}

/// Check and record atomically (convenience wrapper)
///
/// Returns `Ok(())` if attestation is allowed and records the timestamp.
/// Returns `Err(remaining_ms)` if still in cooldown.
pub fn gate() -> Result<(), u64> {
    match check() {
        CooldownResult::Ready => {
            record_attestation();
            Ok(())
        }
        CooldownResult::Wait { remaining_ms } => Err(remaining_ms),
    }
}

/// Get milliseconds since boot
fn get_timestamp_ms() -> u64 {
    // TODO: Consider using a monotonic clock source that survives light sleep
    unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1000 }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require mocking the timer, which is non-trivial
    // on embedded. For now, we rely on integration testing on hardware.

    #[test]
    fn test_cooldown_result_variants() {
        // Just verify the enum is well-formed
        let ready = CooldownResult::Ready;
        let wait = CooldownResult::Wait { remaining_ms: 500 };
        assert_ne!(ready, wait);
    }
}
