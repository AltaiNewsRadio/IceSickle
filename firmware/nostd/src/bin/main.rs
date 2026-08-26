//! IceSickle no_std entropy spike.
//!
//! Demonstrates, in order:
//!
//! 1. That `Trng` is unavailable before an entropy source exists (the gate).
//! 2. Bringing up the SAR-ADC entropy source explicitly.
//! 3. Producing one attestation whose key was derived from that source.
//!
//! There is no button here. The trigger is not part of the signing path, and
//! leaving it out keeps the diff focused on what the spike is meant to answer.

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
use esp_hal::main;
use esp_hal::time::Instant;
use esp_println::println;

use icesickle_core::{Attestation, AttestationEvent};
use icesickle_nostd::entropy::{EntropySource, trng_available};

// This creates a default app-descriptor required by the esp-idf bootloader.
esp_bootloader_esp_idf::esp_app_desc!();

/// GPIO the attestation payload claims as its trigger.
///
/// Recorded, not read: this spike has no button wired up.
const BUTTON_PIN: u8 = 0;

/// Monotonic counter. Resets on power cycle, like the cooldown it will pair with.
static COUNTER: AtomicU32 = AtomicU32::new(0);

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
    println!("IceSickle no_std entropy spike");

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

    // 3. Sign. `entropy()` is infallible because `&entropy_source` is itself
    //    the proof the source is live, and the returned handle cannot outlive
    //    it. There is no way to reach Attestation::create without one.
    let entropy = entropy_source.entropy();
    let event = AttestationEvent::ButtonPress { gpio: BUTTON_PIN };

    // The two hardware inputs, made explicit. Everything downstream of them is
    // deterministic, which is what lets icesickle-core be tested on a host.
    // `create` zeroizes `seed` before returning.
    let mut seed = [0u8; 32];
    entropy.read(&mut seed);
    let timestamp_ms = Instant::now().duration_since_epoch().as_millis();
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
        Err(e) => println!("attestation failed: {:?}", e),
    }

    loop {
        core::hint::spin_loop();
    }
}
