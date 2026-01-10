//! IceSickle - Hardware-assisted ephemeral attestation device
//!
//! When a physical event occurs (button press), the device:
//! 1. Generates a fresh Ed25519 keypair from hardware RNG
//! 2. Signs an attestation payload containing the event + timestamp
//! 3. Outputs the signature + public key
//! 4. Zeroizes the private key (never persisted, never reused)

mod attestation;
mod auth;
mod button;
mod cooldown;
mod entropy;

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_svc::log::EspLogger;
use log::{info, warn};

use crate::attestation::{Attestation, AttestationEvent};
use crate::button::Button;
use crate::entropy::HardwareRng;

/// GPIO pin for the attestation trigger button
/// Default: GPIO0 (BOOT button on most ESP32-S3 devkits)
const BUTTON_PIN: i32 = 0;

fn main() -> anyhow::Result<()> {
    // Initialize ESP-IDF
    esp_idf_sys::link_patches();
    EspLogger::initialize_default();

    info!("IceSickle v{} starting", env!("CARGO_PKG_VERSION"));

    let peripherals = Peripherals::take()?;

    // Initialize hardware RNG
    let rng = HardwareRng::new()?;
    info!("Hardware RNG initialized");

    // Initialize button on GPIO0
    let button_pin = unsafe { esp_idf_hal::gpio::Gpio0::new() };
    let mut button = Button::new(PinDriver::input(button_pin)?)?;
    info!("Button initialized on GPIO{}", BUTTON_PIN);

    // Main event loop
    info!("Entering event loop - press button to generate attestation");

    loop {
        if button.poll_pressed()? {
            // Check cooldown before generating attestation
            match cooldown::gate() {
                Ok(()) => {
                    info!("Button press detected - generating attestation");

                    match generate_attestation(&rng) {
                        Ok(attestation) => {
                            output_attestation(&attestation);
                        }
                        Err(e) => {
                            warn!("Attestation failed: {}", e);
                        }
                    }
                }
                Err(remaining_ms) => {
                    info!("Cooldown active - wait {}ms", remaining_ms);
                }
            }

            // Debounce
            button.wait_release()?;
        }

        // Small delay to prevent busy-spinning
        esp_idf_hal::delay::FreeRtos::delay_ms(10);
    }
}

/// Generate a fresh attestation for a button press event
fn generate_attestation(rng: &HardwareRng) -> anyhow::Result<Attestation> {
    let event = AttestationEvent::ButtonPress {
        gpio: BUTTON_PIN as u8,
    };

    Attestation::create(rng, event)
}

/// Output the attestation (currently via serial/log, extensible to USB HID, BLE, etc.)
fn output_attestation(attestation: &Attestation) {
    info!("=== ATTESTATION ===");
    info!("Event: {:?}", attestation.event());
    info!("Timestamp: {}", attestation.timestamp_ms());
    info!("Public Key: {}", attestation.public_key_hex());
    info!("Signature: {}", attestation.signature_hex());

    // Machine-readable output (JSON-ish for easy parsing)
    println!(
        "{{\"event\":\"{:?}\",\"ts\":{},\"pk\":\"{}\",\"sig\":\"{}\"}}",
        attestation.event(),
        attestation.timestamp_ms(),
        attestation.public_key_hex(),
        attestation.signature_hex()
    );
}
