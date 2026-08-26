//! IceSickle no_std firmware.
//!
//! Boot sequence, in order:
//!
//! 1. Demonstrate that `Trng` is unavailable before an entropy source exists
//!    (the gate).
//! 2. Bring up the SAR-ADC entropy source explicitly.
//! 3. Enter the event loop: a debounced button press, gated by the cooldown,
//!    produces one attestation whose key was derived from that source.
//!
//! Step 3 replaces the spike's unconditional sign-at-boot. A device that
//! attests without a physical event is attesting to nothing, and the whole
//! claim of the payload is that a person did something. The entropy prints in
//! steps 1 and 2 stay: they are the only evidence the gate held, and the only
//! thing the emulator can observe.

#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use core::sync::atomic::{AtomicU32, Ordering};

use esp_backtrace as _;

use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::main;
use esp_hal::time::Instant;
use esp_println::println;

use icesickle_core::button::Edge;
use icesickle_core::cooldown::{Cooldown, DEFAULT_COOLDOWN_MS};
use icesickle_core::{Attestation, AttestationEvent};
use icesickle_nostd::button::Button;
use icesickle_nostd::entropy::{EntropySource, trng_available};

// This creates a default app-descriptor required by the esp-idf bootloader.
esp_bootloader_esp_idf::esp_app_desc!();

/// GPIO the trigger is wired to, and the number the payload records.
///
/// GPIO0 is the BOOT button on most ESP32-S3 devkits. Unlike the esp-idf
/// prototype, this constant is not a second source of truth: the pin is taken
/// from `Peripherals` below and this only labels it, but the two still have to
/// agree, because esp-hal pins are distinct types and the number cannot be
/// recovered from one.
const BUTTON_PIN: u8 = 0;

/// How often the button is sampled. Well inside the 50 ms debounce window, so
/// no press can be slept through.
const POLL_INTERVAL_MS: u32 = 10;

/// Monotonic counter. Resets on power cycle, like the cooldown.
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Milliseconds since boot.
fn now_ms() -> u64 {
    Instant::now().duration_since_epoch().as_millis()
}

#[allow(
    clippy::large_stack_frames,
    reason = "the signing path keeps a seed, an expanded key, a signature and fixed hex buffers on the stack; with no allocator that is the point, not an oversight"
)]
#[main]
fn main() -> ! {
    // Output goes through `println!` rather than the `log` facade on purpose:
    // an attestation is the device's product, not a diagnostic, and it should
    // not disappear because a logger was misconfigured or filtered out.
    //
    // Printed before esp_hal::init so that a hang or fault inside init is
    // distinguishable from a console that is not wired up at all.
    println!("IceSickle no_std firmware");

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    println!("esp_hal::init done");

    // 1. The gate. Before any TrngSource exists, esp-hal refuses to hand out a
    //    Trng at all. This is the property the migration is buying, and the
    //    esp-idf prototype had no equivalent -- esp_fill_random() would have
    //    happily returned pseudo-random bytes here with no indication.
    if trng_available() {
        println!("UNEXPECTED: true entropy reported available before TrngSource exists");
    } else {
        println!("gate holds: no true entropy available before TrngSource exists");
    }

    // 2. Enable the SAR-ADC entropy source. Consumes RNG and ADC1 for good.
    //    The RF subsystem stays off: this device is radio-silent by identity,
    //    which is exactly why the ADC path has to carry the entropy claim.
    let entropy_source = EntropySource::new(peripherals.RNG, peripherals.ADC1);
    println!("TrngSource live: SAR-ADC entropy enabled, radio off");

    if trng_available() {
        println!("gate open: true entropy available");
    } else {
        println!("UNEXPECTED: TrngSource is live but true entropy is unavailable");
    }

    // 3. The event loop.
    let delay = Delay::new();
    let mut button = Button::new(peripherals.GPIO0, now_ms());
    let mut cooldown = Cooldown::new(DEFAULT_COOLDOWN_MS);

    if button.is_pressed() {
        println!("note: trigger held at boot; a press requires releasing it first");
    }
    println!("ready: press GPIO{BUTTON_PIN} to attest");

    loop {
        let now = now_ms();

        if button.poll(now) == Some(Edge::Pressed) {
            // The cooldown is checked *before* signing, not after, so a
            // rejected press costs no entropy and no key material.
            match cooldown.gate(now) {
                Ok(()) => attest(&entropy_source, now),
                Err(remaining_ms) => println!("cooldown: {remaining_ms} ms remaining"),
            }
        }

        delay.delay_millis(POLL_INTERVAL_MS);
    }
}

/// Draw a key from the live entropy source, sign, and print.
///
/// Takes `&EntropySource` rather than a `Trng`: the reference is itself the
/// proof the source is live, and the handle it yields cannot outlive it. There
/// is no way to reach `Attestation::create` without one.
#[allow(
    clippy::large_stack_frames,
    reason = "same as main: the signing path is deliberately stack-only"
)]
fn attest(entropy_source: &EntropySource, timestamp_ms: u64) {
    let entropy = entropy_source.entropy();
    let event = AttestationEvent::ButtonPress { gpio: BUTTON_PIN };

    // The two hardware inputs, made explicit. Everything downstream of them is
    // deterministic, which is what lets icesickle-core be tested on a host.
    // `create` zeroizes `seed` before returning.
    let mut seed = [0u8; 32];
    entropy.read(&mut seed);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    match Attestation::create(&mut seed, event, timestamp_ms, counter) {
        Ok(attestation) => {
            println!("=== ATTESTATION ===");
            println!("event:     {:?}", attestation.event());
            println!("timestamp: {} ms since boot", attestation.timestamp_ms());
            println!("payload:   {}", attestation.signed_payload_hex());
            println!("pubkey:    {}", attestation.public_key_hex());
            println!("signature: {}", attestation.signature_hex());
        }
        Err(e) => println!("attestation failed: {e:?}"),
    }
}
