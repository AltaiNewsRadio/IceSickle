#![no_std]

pub mod entropy;

// Attestation logic lives in `icesickle-core`, which is platform-independent and
// host-testable. This crate supplies only what is genuinely hardware: entropy
// from the SAR-ADC-backed TRNG, and the clock.
pub use icesickle_core as attestation;
