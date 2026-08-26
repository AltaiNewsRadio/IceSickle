//! Debounced button state machine.
//!
//! No GPIO here. This takes a raw level and a clock reading and reports edges;
//! the pin, its polarity and its pull are the firmware's problem. That split is
//! what makes the debounce logic testable on a host, which the esp-idf
//! prototype's version was not — it owned a `PinDriver` and called
//! `esp_timer_get_time()` directly, so nothing about it could be exercised
//! without an ESP32.
//!
//! # Debounce strategy
//!
//! Lockout, not integration: an accepted change starts a window during which
//! further changes are ignored. Contact bounce lasting less than
//! `debounce_ms` is therefore absorbed, and the reported edge is the *first*
//! transition of a bounce train rather than the last. That makes the press
//! land as early as the hardware allows, which is the right trade for a device
//! whose entire job is to timestamp a physical act.

/// Default debounce window. Matches the esp-idf prototype.
pub const DEFAULT_DEBOUNCE_MS: u32 = 50;

/// A debounced transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// The button became pressed.
    Pressed,
    /// The button became released.
    Released,
}

/// Debounced button.
///
/// Poll it with [`Button::update`] as often as you like; it reports each
/// accepted transition exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Button {
    debounce_ms: u32,
    pressed: bool,
    last_change_ms: u64,
}

impl Button {
    /// Seed the state machine from the pin's current level.
    ///
    /// `initial_pressed` is read from the actual pin, not assumed. This is a
    /// deliberate change from the prototype, which always started in the
    /// released state: a device booted with the button already held would see
    /// a level change it had never observed a press for, and emit an
    /// attestation nobody made. Seeding from the pin means a press must be an
    /// actual release-then-press transition.
    ///
    /// That matters on the reference hardware, where the trigger is the BOOT
    /// button — held at power-on to enter download mode.
    pub const fn new(initial_pressed: bool, now_ms: u64, debounce_ms: u32) -> Self {
        Self {
            debounce_ms,
            pressed: initial_pressed,
            last_change_ms: now_ms,
        }
    }

    /// Feed one sample. Returns an edge only when a change is accepted.
    ///
    /// `raw_pressed` is the debounced-input level already normalised to
    /// "pressed", so an active-low button is inverted by the caller.
    pub fn update(&mut self, raw_pressed: bool, now_ms: u64) -> Option<Edge> {
        if raw_pressed == self.pressed {
            return None;
        }

        // saturating_sub, so a clock that reads backwards yields zero elapsed
        // and the change is ignored rather than accepted early. Fail-closed is
        // right here: the cost is one missed press, and the state machine
        // recovers on the next sample once the clock passes the stored value.
        if now_ms.saturating_sub(self.last_change_ms) < self.debounce_ms as u64 {
            return None;
        }

        self.pressed = raw_pressed;
        self.last_change_ms = now_ms;

        Some(if raw_pressed {
            Edge::Pressed
        } else {
            Edge::Released
        })
    }

    /// The debounced level, which is not necessarily the pin's raw level.
    pub const fn is_pressed(&self) -> bool {
        self.pressed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn button() -> Button {
        Button::new(false, 0, DEFAULT_DEBOUNCE_MS)
    }

    #[test]
    fn a_clean_press_and_release_reports_both_edges() {
        let mut b = button();
        assert_eq!(b.update(true, 100), Some(Edge::Pressed));
        assert!(b.is_pressed());
        assert_eq!(b.update(false, 200), Some(Edge::Released));
        assert!(!b.is_pressed());
    }

    #[test]
    fn holding_the_button_reports_one_edge_not_many() {
        let mut b = button();
        assert_eq!(b.update(true, 100), Some(Edge::Pressed));
        for t in 101..500 {
            assert_eq!(b.update(true, t), None, "re-fired while held at {t}");
        }
    }

    /// The property the debounce exists for: a bounce train inside the window
    /// yields exactly one press.
    #[test]
    fn bounce_within_the_window_is_absorbed() {
        let mut b = button();
        assert_eq!(b.update(true, 100), Some(Edge::Pressed));

        // Contacts chatter for 40ms, inside the 50ms window.
        let mut edges = 0;
        for (t, level) in [(105, false), (110, true), (118, false), (130, true)] {
            if b.update(level, t).is_some() {
                edges += 1;
            }
        }
        assert_eq!(edges, 0, "bounce leaked through the debounce window");
        assert!(b.is_pressed(), "settled state should still be pressed");
    }

    #[test]
    fn a_release_after_the_window_is_accepted() {
        let mut b = button();
        b.update(true, 100);
        assert_eq!(
            b.update(false, 100 + DEFAULT_DEBOUNCE_MS as u64),
            Some(Edge::Released)
        );
    }

    #[test]
    fn a_release_one_millisecond_early_is_rejected() {
        let mut b = button();
        b.update(true, 100);
        assert_eq!(b.update(false, 100 + DEFAULT_DEBOUNCE_MS as u64 - 1), None);
    }

    /// Boot with the button already held: no press is invented.
    ///
    /// The prototype would have reported one, because it assumed a released
    /// initial state and then observed a level it had no press for.
    #[test]
    fn a_button_held_at_boot_does_not_synthesise_a_press() {
        let mut b = Button::new(true, 0, DEFAULT_DEBOUNCE_MS);
        assert!(b.is_pressed());
        for t in 0..1000 {
            assert_eq!(b.update(true, t), None, "invented a press at {t}");
        }
        // It takes a real release, then a real press.
        assert_eq!(b.update(false, 1000), Some(Edge::Released));
        assert_eq!(b.update(true, 1100), Some(Edge::Pressed));
    }

    #[test]
    fn a_backwards_clock_ignores_the_change_rather_than_accepting_it() {
        let mut b = button();
        b.update(true, 10_000);
        assert_eq!(
            b.update(false, 5_000),
            None,
            "accepted an edge on a backwards clock"
        );
        // Recovers once the clock passes the stored value again.
        assert_eq!(b.update(false, 10_100), Some(Edge::Released));
    }

    #[test]
    fn a_zero_debounce_accepts_every_change() {
        let mut b = Button::new(false, 0, 0);
        assert_eq!(b.update(true, 0), Some(Edge::Pressed));
        assert_eq!(b.update(false, 0), Some(Edge::Released));
        assert_eq!(b.update(true, 0), Some(Edge::Pressed));
    }
}
