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

use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::main;
use log::info;

use icesickle_nostd::attestation::{Attestation, AttestationEvent};
use icesickle_nostd::entropy::{EntropySource, trng_available};

// This creates a default app-descriptor required by the esp-idf bootloader.
esp_bootloader_esp_idf::esp_app_desc!();

/// GPIO the attestation payload claims as its trigger.
///
/// Recorded, not read: this spike has no button wired up.
const BUTTON_PIN: u8 = 0;

#[allow(
    clippy::large_stack_frames,
    reason = "the signing path keeps a seed, an expanded key, a signature and fixed hex buffers on the stack; with no allocator that is the point, not an oversight"
)]
#[main]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    info!("IceSickle no_std entropy spike");

    // 1. The gate. Before any TrngSource exists, esp-hal refuses to hand out a
    //    Trng at all. This is the property the migration is buying, and the
    //    esp-idf prototype had no equivalent -- esp_fill_random() would have
    //    happily returned pseudo-random bytes here with no indication.
    if trng_available() {
        info!("UNEXPECTED: true entropy reported available before TrngSource exists");
    } else {
        info!("gate holds: no true entropy available before TrngSource exists");
    }

    // 2. Enable the SAR-ADC entropy source. Consumes RNG and ADC1 for good.
    //    The RF subsystem stays off: this device is radio-silent by identity,
    //    which is exactly why the ADC path has to carry the entropy claim.
    let entropy_source = EntropySource::new(peripherals.RNG, peripherals.ADC1);
    info!("TrngSource live: SAR-ADC entropy enabled, radio off");

    if trng_available() {
        info!("gate open: true entropy available");
    } else {
        info!("UNEXPECTED: TrngSource is live but true entropy is unavailable");
    }

    // 3. Sign. `entropy()` is infallible because `&entropy_source` is itself
    //    the proof the source is live, and the returned handle cannot outlive
    //    it. There is no way to reach Attestation::create without one.
    let entropy = entropy_source.entropy();
    let event = AttestationEvent::ButtonPress { gpio: BUTTON_PIN };

    match Attestation::create(&entropy, event) {
        Ok(attestation) => {
            info!("=== ATTESTATION ===");
            info!("event:     {:?}", attestation.event());
            info!("timestamp: {} ms since boot", attestation.timestamp_ms());
            info!("payload:   {}", attestation.signed_payload_hex());
            info!("pubkey:    {}", attestation.public_key_hex());
            info!("signature: {}", attestation.signature_hex());
        }
        Err(e) => info!("attestation failed: {:?}", e),
    }

    loop {
        core::hint::spin_loop();
    }
}
