//! Button input handling with hardware debouncing
//!
//! Provides a simple interface for detecting button presses on GPIO pins.
//! The ESP32-S3 devkit typically has a BOOT button on GPIO0 (active low).
//!
//! This implementation uses polling rather than interrupts for simplicity
//! and determinism. In a power-constrained design, you'd want to use
//! GPIO interrupts with light sleep.

use esp_idf_hal::gpio::{Input, InputPin, PinDriver, Pull};

/// Debounce time in milliseconds
const DEBOUNCE_MS: u32 = 50;

/// Button state machine
///
/// `PinDriver` is type-erased as of esp-idf-hal 0.46, so the concrete pin type
/// is absorbed at construction rather than carried as a parameter.
pub struct Button<'d> {
    pin: PinDriver<'d, Input>,
    last_state: bool,
    last_change_ms: u32,
}

impl<'d> Button<'d> {
    /// Create a new button on the given pin
    ///
    /// Configures the pin with internal pull-up (assuming active-low button).
    /// `set_pull` is private as of esp-idf-hal 0.46; the pull is chosen when the
    /// driver is created, so the driver is constructed here rather than passed in.
    pub fn new<T: InputPin + 'd>(pin: T) -> anyhow::Result<Self> {
        Ok(Self {
            pin: PinDriver::input(pin, Pull::Up)?,
            last_state: false,
            last_change_ms: 0,
        })
    }

    /// Poll for a button press (returns true once per press, after debounce)
    pub fn poll_pressed(&mut self) -> anyhow::Result<bool> {
        let now = millis();
        let current_raw = self.pin.is_low(); // Active low

        // Debounce: only register state change after stable period
        if current_raw != self.last_state && now.wrapping_sub(self.last_change_ms) >= DEBOUNCE_MS {
            self.last_state = current_raw;
            self.last_change_ms = now;

            // Return true only on press (transition to pressed state)
            if current_raw {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Block until the button is released (with debounce)
    pub fn wait_release(&mut self) -> anyhow::Result<()> {
        // Wait for raw release
        while self.pin.is_low() {
            esp_idf_hal::delay::FreeRtos::delay_ms(10);
        }

        // Debounce delay
        esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE_MS);

        // Update state
        self.last_state = false;
        self.last_change_ms = millis();

        Ok(())
    }

    /// Check if button is currently pressed (raw, no debounce)
    #[allow(dead_code)]
    pub fn is_pressed(&self) -> bool {
        self.pin.is_low()
    }
}

/// Get current time in milliseconds (wraps at u32::MAX)
fn millis() -> u32 {
    (unsafe { esp_idf_sys::esp_timer_get_time() } / 1000) as u32
}
