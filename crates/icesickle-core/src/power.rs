//! Power budget: survival days against events per day.
//!
//! Turns the standby-power question from an argument into a number. The model
//! is deliberately small — a battery, a leak, and a per-event cost — because the
//! useful output is not precision but a **threshold**, and the threshold turns
//! out to be dominated by one term.
//!
//! # The finding, stated up front
//!
//! At the reference configuration ([`FEATHER_CAPACITY_MAH`], a
//! [`TARGET_SURVIVAL_DAYS`]-day target), the average current the device may draw
//! is:
//!
//! ```text
//! 500 mAh / (21 x 24 h) = 992 uA
//! ```
//!
//! A plausible per-attestation cost is single-digit microamp-hours, so **even a
//! hundred attestations a day spend less than a percent of that budget**. The
//! events do not matter. What matters is whether the assembled board leaks under
//! roughly one milliamp while asleep.
//!
//! That reframes the hardware decision. The question is not "how expensive is an
//! attestation" but "does this board sleep under 1 mA", and only a multimeter
//! answers it.
//!
//! # Why provenance is part of the type
//!
//! Every field carries a [`Provenance`]. A chip datasheet quotes single-digit
//! microamps for ESP32-S3 deep sleep; an assembled Feather also has a charger
//! IC, a regulator, a NeoPixel and a USB-serial bridge, and those dominate. A
//! model that cannot tell a measurement from a guess will happily report a
//! survival figure derived from the wrong number, and it will look identical to
//! a real one.
//!
//! So [`PowerBudget::is_fully_measured`] exists, and a test asserts the shipped
//! placeholder is *not* measured. When someone fills in a bench reading, that
//! test fails — which forces a look at the threshold rather than a quiet pass.

/// Where a number came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Read off a meter, on the assembled board, in the state being modelled.
    MeasuredOnHardware,
    /// Anything else: datasheet figures, arithmetic, informed guesses.
    Estimated,
}

/// Battery on the reference hardware.
pub const FEATHER_CAPACITY_MAH: f32 = 500.0;

/// Survival target. A parameter, not a decision — the final figure is still
/// open, and 21 days is what the current planning assumes.
pub const TARGET_SURVIVAL_DAYS: f32 = 21.0;

const HOURS_PER_DAY: f32 = 24.0;
const UAH_PER_MAH: f32 = 1000.0;

/// A battery, a continuous leak, and a cost per attestation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PowerBudget {
    /// Usable battery capacity, milliamp-hours.
    pub capacity_mah: f32,
    /// Current drawn while asleep, microamps. **The term that decides
    /// everything** — see the module docs.
    pub standby_ua: f32,
    pub standby_provenance: Provenance,
    /// Charge spent waking, signing and emitting once, microamp-hours.
    pub per_attestation_uah: f32,
    pub per_attestation_provenance: Provenance,
}

impl PowerBudget {
    /// The reference configuration, pending measurement.
    ///
    /// **Both figures are estimates and neither should be quoted.** The standby
    /// number in particular is a placeholder: reported deep-sleep draw for
    /// stock Feather-class boards spans more than an order of magnitude
    /// depending on whether the NeoPixel, the regulator and the USB bridge are
    /// awake, which is exactly why a bench reading is a prerequisite rather
    /// than a nicety.
    pub const PLACEHOLDER: Self = Self {
        capacity_mah: FEATHER_CAPACITY_MAH,
        standby_ua: 200.0,
        standby_provenance: Provenance::Estimated,
        per_attestation_uah: 4.0,
        per_attestation_provenance: Provenance::Estimated,
    };

    /// Charge consumed in one day at a given attestation rate, microamp-hours.
    pub fn daily_uah(&self, events_per_day: f32) -> f32 {
        self.standby_ua * HOURS_PER_DAY + self.per_attestation_uah * events_per_day
    }

    /// Days the battery lasts at a given attestation rate.
    ///
    /// Returns [`f32::INFINITY`] for a budget that consumes nothing, which is
    /// not physical but is the honest answer to the arithmetic and keeps the
    /// caller from having to special-case a zero.
    pub fn survival_days(&self, events_per_day: f32) -> f32 {
        let daily = self.daily_uah(events_per_day);
        if daily <= 0.0 {
            return f32::INFINITY;
        }
        (self.capacity_mah * UAH_PER_MAH) / daily
    }

    /// Whether the target is met at a given rate.
    pub fn meets_target(&self, target_days: f32, events_per_day: f32) -> bool {
        self.survival_days(events_per_day) >= target_days
    }

    /// Days short of the target. Zero or negative means the target is met.
    ///
    /// Reported rather than a bare boolean so a near miss and a hopeless miss
    /// look different — the hardware decision between a cutoff and a different
    /// module depends on which one it is.
    pub fn shortfall_days(&self, target_days: f32, events_per_day: f32) -> f32 {
        target_days - self.survival_days(events_per_day)
    }

    /// The highest standby current that still meets the target at a given rate.
    ///
    /// This is the number to take to the bench: measure, compare, decide. It
    /// depends on the event rate only weakly, which is the module's central
    /// point.
    pub fn permissible_standby_ua(&self, target_days: f32, events_per_day: f32) -> f32 {
        let total_budget_uah = self.capacity_mah * UAH_PER_MAH;
        let event_cost_uah = self.per_attestation_uah * events_per_day * target_days;
        let standby_budget_uah = total_budget_uah - event_cost_uah;

        if standby_budget_uah <= 0.0 {
            return 0.0;
        }
        standby_budget_uah / (target_days * HOURS_PER_DAY)
    }

    /// True only when every input came off a meter.
    ///
    /// A survival figure derived from an estimate is a projection. It should
    /// never be reported as a measurement, and the type is the only thing
    /// standing between the two.
    pub fn is_fully_measured(&self) -> bool {
        matches!(self.standby_provenance, Provenance::MeasuredOnHardware)
            && matches!(
                self.per_attestation_provenance,
                Provenance::MeasuredOnHardware
            )
    }
}

/// Event rates the table is reported at.
pub const REPORTED_EVENT_RATES: [f32; 6] = [0.0, 1.0, 5.0, 20.0, 100.0, 1000.0];

#[cfg(test)]
mod tests {
    use super::*;

    /// Within a tenth of a day is close enough for a battery model.
    fn close(a: f32, b: f32) {
        assert!(
            (a - b).abs() < 0.1,
            "expected ~{b}, got {a} (difference {})",
            (a - b).abs()
        );
    }

    #[test]
    fn daily_consumption_is_standby_plus_events() {
        let b = PowerBudget::PLACEHOLDER;
        // 200 uA * 24 h = 4800 uAh of leak, plus 4 uAh per event.
        close(b.daily_uah(0.0), 4800.0);
        close(b.daily_uah(10.0), 4840.0);
        close(b.daily_uah(100.0), 5200.0);
    }

    #[test]
    fn survival_is_capacity_over_daily_draw() {
        let b = PowerBudget::PLACEHOLDER;
        // 500_000 uAh / 4800 uAh per day.
        close(b.survival_days(0.0), 104.16);
        close(b.survival_days(100.0), 96.15);
    }

    #[test]
    fn survival_falls_as_events_rise() {
        let b = PowerBudget::PLACEHOLDER;
        let mut previous = f32::INFINITY;

        for rate in REPORTED_EVENT_RATES {
            let days = b.survival_days(rate);
            assert!(
                days <= previous,
                "survival rose from {previous} to {days} when the rate went up to {rate}"
            );
            previous = days;
        }
    }

    /// The central claim: at plausible rates the events are noise and the leak
    /// is everything.
    ///
    /// If this ever fails, the per-attestation cost has grown enough to matter
    /// and the framing in the module docs needs revisiting — which is a finding,
    /// not a broken test.
    #[test]
    fn events_are_negligible_against_standby() {
        let b = PowerBudget::PLACEHOLDER;

        let idle = b.survival_days(0.0);
        let busy = b.survival_days(100.0);
        let lost_fraction = (idle - busy) / idle;

        assert!(
            lost_fraction < 0.10,
            "100 attestations a day cost {:.1}% of battery life; \
             the events are no longer negligible and the module's framing is stale",
            lost_fraction * 100.0
        );
    }

    /// The number to take to the bench.
    #[test]
    fn the_permissible_standby_current_is_about_a_milliamp() {
        let b = PowerBudget::PLACEHOLDER;

        // 500_000 uAh over 21 days x 24 h, with nothing spent on events.
        close(b.permissible_standby_ua(TARGET_SURVIVAL_DAYS, 0.0), 992.06);

        // Even a heavy rate barely moves it, which is the point.
        let heavy = b.permissible_standby_ua(TARGET_SURVIVAL_DAYS, 100.0);
        assert!(
            heavy > 950.0,
            "100 events a day dropped the permissible standby to {heavy} uA; \
             the events were supposed to be negligible"
        );
    }

    #[test]
    fn shortfall_is_signed_so_a_near_miss_is_visible() {
        let leaky = PowerBudget {
            standby_ua: 2000.0,
            ..PowerBudget::PLACEHOLDER
        };

        assert!(!leaky.meets_target(TARGET_SURVIVAL_DAYS, 1.0));
        let short = leaky.shortfall_days(TARGET_SURVIVAL_DAYS, 1.0);
        assert!(
            short > 0.0,
            "a budget that misses the target reported no shortfall"
        );

        // ...and a comfortable budget reports a negative shortfall rather than
        // clamping, so "how much headroom" is answerable from the same call.
        assert!(PowerBudget::PLACEHOLDER.shortfall_days(TARGET_SURVIVAL_DAYS, 1.0) < 0.0);
    }

    #[test]
    fn a_budget_that_consumes_nothing_survives_forever() {
        let perfect = PowerBudget {
            standby_ua: 0.0,
            per_attestation_uah: 0.0,
            ..PowerBudget::PLACEHOLDER
        };
        assert_eq!(perfect.survival_days(0.0), f32::INFINITY);
    }

    /// **This test is a tripwire, and failing it is the intended outcome.**
    ///
    /// The shipped budget is a placeholder. When someone replaces the standby
    /// figure with a bench reading and marks it measured, this fails — which
    /// forces them to look at the threshold and update the module docs rather
    /// than letting a real measurement slide in silently behind an unchanged
    /// projection.
    #[test]
    fn the_shipped_budget_is_still_a_projection() {
        assert!(
            !PowerBudget::PLACEHOLDER.is_fully_measured(),
            "a measurement has landed -- update the module docs with the real \
             threshold verdict, then change this test to assert the opposite"
        );
    }

    /// A fully measured budget reports itself as one.
    #[test]
    fn a_measured_budget_is_recognised() {
        let measured = PowerBudget {
            standby_provenance: Provenance::MeasuredOnHardware,
            per_attestation_provenance: Provenance::MeasuredOnHardware,
            ..PowerBudget::PLACEHOLDER
        };
        assert!(measured.is_fully_measured());
    }
}
