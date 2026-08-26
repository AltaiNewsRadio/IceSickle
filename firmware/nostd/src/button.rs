//! GPIO binding for the attestation trigger.
//!
//! Everything decision-making lives in [`icesickle_core::button`]; this holds
//! the pin and the one fact that is genuinely about this hardware — the button
//! is **active low**, so a pressed button reads as a low level.
//!
//! Polling, not interrupts. The esp-idf prototype made the same call for
//! simplicity and determinism, and it still holds: an interrupt-driven trigger
//! would want light sleep to be worth having, and sleep interacts with the
//! entropy source (`docs/NOSTD_ENTROPY_SPIKE.md`) in ways nothing has measured
//! on silicon yet.

use esp_hal::gpio::{Input, InputConfig, InputPin, Pull};

use icesickle_core::button::{Button as Debounce, DEFAULT_DEBOUNCE_MS, Edge};

/// A debounced, active-low button on a GPIO pin.
pub struct Button<'d> {
    pin: Input<'d>,
    debounce: Debounce,
}

impl<'d> Button<'d> {
    /// Configure `pin` as a pulled-up input and seed the debouncer from its
    /// current level.
    ///
    /// The pull-up is internal, so the button only has to short the pin to
    /// ground. Seeding from the live level rather than assuming "released" is
    /// what stops a device booted with the button held from emitting an
    /// attestation nobody made; the reference trigger is the BOOT button,
    /// which is held at power-on to enter download mode, so this is not a
    /// hypothetical.
    pub fn new(pin: impl InputPin + 'd, now_ms: u64) -> Self {
        let pin = Input::new(pin, InputConfig::default().with_pull(Pull::Up));
        let debounce = Debounce::new(pin.is_low(), now_ms, DEFAULT_DEBOUNCE_MS);

        Self { pin, debounce }
    }

    /// Sample the pin once. Returns an edge only when the debouncer accepts it.
    pub fn poll(&mut self, now_ms: u64) -> Option<Edge> {
        // is_low, not is_high: active low. This inversion is the only place
        // the polarity is encoded, which is why icesickle-core speaks in
        // "pressed" rather than in levels.
        self.debounce.update(self.pin.is_low(), now_ms)
    }

    /// The debounced level, which is not necessarily the pin's raw level.
    pub fn is_pressed(&self) -> bool {
        self.debounce.is_pressed()
    }
}
