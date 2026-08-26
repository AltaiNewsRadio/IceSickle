//! Physical rate limiting.
//!
//! A minimum interval between attestations, enforced on the device. Spam
//! resistance via physics rather than a server: no network round trip, no
//! central state to attack, and the bound is wall-clock time rather than
//! software policy.
//!
//! # Threat model
//!
//! An attacker with physical access can reflash to remove this, which the
//! threat model already concedes, or wait the cooldown out — which is the
//! point. An attacker *without* physical access cannot trigger attestations
//! faster than the interval allows, and cannot bank unused time for a later
//! burst: [`Cooldown::check`] compares against the last attestation only, so
//! idling earns nothing.
//!
//! # Two changes from the esp-idf prototype
//!
//! The prototype held its state in a `static AtomicU32`, which forced both a
//! global and a 32-bit millisecond counter — xtensa-esp32s3 has no 64-bit
//! atomics. It also made the thing untestable, since there was no way to
//! advance its clock.
//!
//! This is an owned value taking `now_ms` as a parameter, so:
//!
//! - **u64 milliseconds, no wrapping arithmetic.** The `wrapping_sub` and its
//!   ~49.7-day wrap existed only to serve `AtomicU32`. A u64 millisecond
//!   counter wraps on a scale no device will see.
//! - **The first attestation is never blocked.** `LAST_ATTESTATION_MS` started
//!   at 0, indistinguishable from "attested at boot", so the prototype refused
//!   to attest for the first second after power-on. [`Cooldown`] starts with no
//!   recorded attestation instead.

/// Default minimum interval between attestations. Matches the esp-idf
/// prototype.
pub const DEFAULT_COOLDOWN_MS: u32 = 1000;

/// Result of a cooldown check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooldownResult {
    /// Attestation allowed; the interval has elapsed.
    Ready,
    /// Attestation blocked.
    Wait {
        /// Milliseconds still to go.
        remaining_ms: u32,
    },
}

/// Tracks when the last attestation was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cooldown {
    interval_ms: u32,
    /// `None` until the first attestation. See the module docs.
    last_ms: Option<u64>,
}

impl Cooldown {
    /// A cooldown that has never fired, so the first attestation is allowed.
    pub const fn new(interval_ms: u32) -> Self {
        Self {
            interval_ms,
            last_ms: None,
        }
    }

    /// Whether an attestation is allowed now. Does not record anything.
    pub fn check(&self, now_ms: u64) -> CooldownResult {
        let Some(last) = self.last_ms else {
            return CooldownResult::Ready;
        };

        // checked_sub, not saturating: a clock reading before the recorded
        // attestation means the clock moved backwards, and the prototype's
        // choice was to fail *open* rather than latch the device shut. A
        // device that refuses to attest is worse than one that attests twice.
        match now_ms.checked_sub(last) {
            None => CooldownResult::Ready,
            Some(elapsed) if elapsed >= self.interval_ms as u64 => CooldownResult::Ready,
            Some(elapsed) => CooldownResult::Wait {
                // elapsed < interval_ms, which is a u32, so this cannot truncate.
                remaining_ms: self.interval_ms - elapsed as u32,
            },
        }
    }

    /// Record that an attestation was just produced.
    ///
    /// Call this immediately after signing and before emitting, so a slow
    /// transport cannot widen the window in which a second press slips past.
    pub fn record(&mut self, now_ms: u64) {
        self.last_ms = Some(now_ms);
    }

    /// Check and record in one step.
    ///
    /// `Ok(())` means attest; `Err(remaining_ms)` means the caller is early.
    pub fn gate(&mut self, now_ms: u64) -> Result<(), u32> {
        match self.check(now_ms) {
            CooldownResult::Ready => {
                self.record(now_ms);
                Ok(())
            }
            CooldownResult::Wait { remaining_ms } => Err(remaining_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cooldown() -> Cooldown {
        Cooldown::new(DEFAULT_COOLDOWN_MS)
    }

    /// The prototype blocked this one: its zero-initialised static read as
    /// "attested at boot".
    #[test]
    fn the_first_attestation_is_allowed_immediately() {
        let mut c = cooldown();
        assert_eq!(c.check(0), CooldownResult::Ready);
        assert_eq!(c.gate(0), Ok(()));
    }

    #[test]
    fn a_second_attestation_inside_the_interval_is_blocked() {
        let mut c = cooldown();
        assert_eq!(c.gate(0), Ok(()));
        assert_eq!(c.gate(400), Err(600));
        assert_eq!(c.gate(999), Err(1));
    }

    #[test]
    fn the_boundary_is_inclusive() {
        let mut c = cooldown();
        c.gate(0).unwrap();
        assert_eq!(c.check(999), CooldownResult::Wait { remaining_ms: 1 });
        assert_eq!(c.check(1000), CooldownResult::Ready);
    }

    /// Idling does not bank credit for a burst.
    #[test]
    fn waiting_a_long_time_still_buys_only_one_attestation() {
        let mut c = cooldown();
        c.gate(0).unwrap();
        assert_eq!(c.gate(60_000), Ok(()));
        assert_eq!(c.gate(60_001), Err(999));
    }

    #[test]
    fn a_blocked_gate_does_not_move_the_deadline() {
        let mut c = cooldown();
        c.gate(0).unwrap();
        assert_eq!(c.gate(500), Err(500));
        assert_eq!(
            c.gate(700),
            Err(300),
            "a rejected attempt reset the interval"
        );
        assert_eq!(c.gate(1000), Ok(()));
    }

    #[test]
    fn check_does_not_record() {
        let mut c = cooldown();
        assert_eq!(c.check(0), CooldownResult::Ready);
        assert_eq!(c.check(0), CooldownResult::Ready);
        assert_eq!(c.gate(0), Ok(()));
        assert_eq!(c.check(0), CooldownResult::Wait { remaining_ms: 1000 });
    }

    /// Fail open, not shut. A latched device produces nothing at all.
    #[test]
    fn a_backwards_clock_allows_the_attestation() {
        let mut c = cooldown();
        c.gate(10_000).unwrap();
        assert_eq!(c.check(9_000), CooldownResult::Ready);
    }

    #[test]
    fn a_zero_interval_never_blocks() {
        let mut c = Cooldown::new(0);
        assert_eq!(c.gate(0), Ok(()));
        assert_eq!(c.gate(0), Ok(()));
    }

    /// The u32 arithmetic in `check` must not truncate at the far end of a u64
    /// clock. The prototype's u32 counter could not represent this at all.
    #[test]
    fn a_far_future_clock_does_not_truncate() {
        let mut c = cooldown();
        c.gate(0).unwrap();
        assert_eq!(c.check(u64::MAX), CooldownResult::Ready);

        c.record(u64::MAX - 500);
        assert_eq!(
            c.check(u64::MAX),
            CooldownResult::Wait { remaining_ms: 500 }
        );
    }
}
