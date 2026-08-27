//! Deep-sleep scaffolding for the standby-current bench measurement.
//!
//! Not the firmware. This exists so a multimeter inline with the battery rail
//! reads *true standby* rather than whatever the application happens to be doing
//! — which is why it is a separate binary rather than a flag on the real one.
//!
//! Flash it, put the meter in series with the battery, and read the number. The
//! device wakes on a press of GPIO0 and goes straight back to sleep, so the
//! meter should show one brief spike per press and a flat line otherwise.
//!
//! # Why it must not touch the entropy source
//!
//! `icesickle_nostd::entropy::EntropySource` brings up the SAR ADC and holds it
//! on. `docs/NOSTD_ENTROPY_SPIKE.md` lists the power and timing cost of that as
//! specifically unmeasured, and it would land squarely in the middle of this
//! measurement. This binary never constructs one.
//!
//! That is not a distortion of the real figure: deep sleep resets the chip, so
//! nothing survives it and the entropy source is rebuilt on every wake anyway.
//! What the meter reads here is what the sleeping device actually draws.
//!
//! # What deep sleep costs the application, and why that is not settled here
//!
//! **Deep sleep is a reset.** On wake, execution restarts from the reset vector
//! with RAM gone. For the real firmware that means:
//!
//! - the monotonic counter restarts at zero, which the payload already
//!   documents as resetting on a power cycle, and
//! - **the cooldown is erased**, which it does not. `icesickle_core::cooldown`
//!   holds its state in an owned value, so a device woken repeatedly would
//!   attest every time with no rate limit at all.
//!
//! The second is a real interaction between low power and rate limiting, and it
//! is out of scope for a measurement scaffold. **Tracked in `docs/ROADMAP.md`,
//! "Cooldown must survive deep sleep"**, which also records the trap: persisting
//! the stored timestamp is not enough on its own, because `Instant::now()`
//! restarts at zero after deep sleep. The time base has to move to something
//! that survives the reset — `Rtc::time_since_power_up()` — or the fix compares
//! a saved value against a counter that just reset and changes nothing.

#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]

use esp_backtrace as _;

use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::gpio::{Input, InputConfig, Pull};
use esp_hal::main;
use esp_hal::rtc_cntl::Rtc;
use esp_hal::rtc_cntl::sleep::{Ext0WakeupSource, WakeupLevel};
use esp_println::println;

esp_bootloader_esp_idf::esp_app_desc!();

/// The trigger, and the wake source. Active low, as on the reference hardware.
const BUTTON_PIN: u8 = 0;

/// Long enough for a meter to settle on the awake figure before the device
/// disappears again, short enough that it contributes nothing to an average
/// taken over minutes.
const SETTLE_MS: u32 = 250;

#[main]
fn main() -> ! {
    println!("IceSickle sleep bench");
    println!("wake source: GPIO{BUTTON_PIN}, active low");

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    // `mut` because the held-trigger check below reborrows GPIO0 rather than
    // consuming it -- the pin has to survive to become the wake source.
    let mut peripherals = esp_hal::init(config);

    // Read the pin once, before it is consumed as a wake source. A device whose
    // button is held at boot would otherwise wake immediately and forever, and
    // the meter would show a duty cycle rather than a standby figure -- with
    // nothing on the console to explain why.
    {
        let held = Input::new(
            peripherals.GPIO0.reborrow(),
            InputConfig::default().with_pull(Pull::Up),
        )
        .is_low();

        if held {
            println!("WARNING: trigger is held; release it or the device will wake on entry");
        }
    }

    // No EntropySource here. See the module docs -- holding the SAR ADC on is an
    // unmeasured cost and would be measured as if it were standby.
    println!("entropy source deliberately not started");

    Delay::new().delay_millis(SETTLE_MS);

    let mut rtc = Rtc::new(peripherals.LPWR);
    let wake = Ext0WakeupSource::new(peripherals.GPIO0, WakeupLevel::Low);

    println!("sleeping now -- read the meter; press GPIO{BUTTON_PIN} to wake");

    // Returns `!`. Waking restarts the chip from the reset vector, so the next
    // thing on the console is this program's banner again -- which is also how
    // you confirm the wake source works.
    rtc.sleep_deep(&[&wake]);
}
