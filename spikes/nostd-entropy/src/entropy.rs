//! True-RNG bring-up, with the entropy precondition made structural.
//!
//! # Why this module exists
//!
//! The ESP32-S3 hardware RNG only produces true random numbers under one of two
//! conditions. Quoting `esp-hal` 1.1.2 (`src/rng/mod.rs`):
//!
//! > The hardware RNG produces true random numbers under any of the following
//! > conditions:
//! > - RF subsystem is enabled (i.e. Wi-Fi or Bluetooth are enabled).
//! > - An ADC is used to generate entropy.
//! >
//! > [...] If none of the above conditions are true, the output of the RNG
//! > should be considered pseudo-random only.
//!
//! IceSickle is radio-silent by identity, so the RF path is permanently
//! unavailable to us. The SAR-ADC path is therefore the *only* way this device
//! can hold a true-entropy claim, and it must be proven live at the moment a
//! signing key is derived.
//!
//! The esp-idf prototype could not express this. It called `esp_fill_random()`,
//! which returns bytes unconditionally and gives the caller no signal about
//! which regime produced them. A device whose entire value rests on key
//! unpredictability was reading entropy of unverifiable quality.
//!
//! # What esp-hal actually enforces, and what this module adds
//!
//! Being precise here, because the difference matters:
//!
//! - **Compile-time (esp-hal):** `TrngSource::new` consumes the `RNG` and
//!   `ADC1` peripheral singletons. While the source is alive the ADC cannot be
//!   used for anything else, and that is enforced by ownership.
//! - **Runtime (esp-hal):** `Trng::try_new()` is a free function that checks a
//!   global counter and returns `Err(TrngError::TrngSourceNotEnabled)` when no
//!   source is live. It is fail-closed, but it is a runtime check, not a proof.
//!   Anyone can call it from anywhere.
//! - **Compile-time (this module):** [`Entropy`] borrows from [`EntropySource`],
//!   so a handle capable of producing key material cannot outlive the entropy
//!   source that justifies it. Obtaining one is infallible *because* holding an
//!   `&EntropySource` is itself the proof.
//!
//! So "entropy enforced by the type system" is accurate for the path this crate
//! uses, but it is a property we construct on top of esp-hal's runtime gate --
//! esp-hal alone does not provide it. `Trng::try_new()` remains public and
//! callable directly; this module does not and cannot prevent that.
//!
//! # Cost
//!
//! `TrngSource` occupies ADC1 for as long as it lives. IceSickle has no other
//! use for the ADC, so we take it once at boot and never give it back.

use core::marker::PhantomData;

use esp_hal::peripherals::{ADC1, RNG};
use esp_hal::rng::{Trng, TrngSource};

/// A live SAR-ADC entropy source.
///
/// Constructing this enables the entropy path (`ensure_randomness()` on S3:
/// RNG clock, 8 MHz clock source, and the SAR ADC sampling a disconnected
/// input). Dropping it reverts that and releases ADC1.
pub struct EntropySource<'d> {
    inner: TrngSource<'d>,
}

impl<'d> EntropySource<'d> {
    /// Enable the true-entropy path.
    ///
    /// Takes both peripherals by value: ADC1 is unavailable to the rest of the
    /// program until this is dropped, which is exactly the trade we want.
    pub fn new(rng: RNG<'d>, adc1: ADC1<'d>) -> Self {
        Self {
            inner: TrngSource::new(rng, adc1),
        }
    }

    /// Obtain a handle that can produce true random bytes.
    ///
    /// Infallible by construction: `&self` proves the entropy source is live,
    /// which is the precondition `Trng::try_new()` checks at runtime. The
    /// returned handle borrows `self`, so it cannot outlive that proof.
    pub fn entropy(&self) -> Entropy<'_> {
        // Cannot fail: `self` is a live TrngSource, so the global entropy
        // counter is non-zero. This is the one place the runtime gate is
        // collapsed into a compile-time guarantee, and it is sound only
        // because `EntropySource` owns the source it is asserting about.
        let trng =
            Trng::try_new().expect("EntropySource is alive, so the TRNG entropy source is enabled");

        Entropy {
            trng,
            _source: PhantomData,
        }
    }
}

/// A borrowed true-entropy handle.
///
/// The lifetime ties this to the [`EntropySource`] that justifies it, so key
/// material can never be derived from an RNG whose entropy source has been
/// torn down.
pub struct Entropy<'s> {
    trng: Trng,
    _source: PhantomData<&'s ()>,
}

impl Entropy<'_> {
    /// Fill `buffer` with true random bytes.
    pub fn read(&self, buffer: &mut [u8]) {
        self.trng.read(buffer);
    }
}

/// Whether a true-entropy source is currently live.
///
/// Only for demonstrating the gate at startup -- the signing path proves this
/// structurally via [`EntropySource::entropy`] rather than asking.
pub fn trng_available() -> bool {
    Trng::try_new().is_ok()
}
