//! Emission discipline, as executable assertions.
//!
//! The architecture claims three LPI/LPD properties: transmit rarely, transmit
//! without a fingerprint, and stay dark when told. Those are stated as prose in
//! `THREAT_MODEL.md` and `docs/ARCHITECTURE.md`, which means a stranger has to
//! take them on trust. This module restates them as a pure function plus tests
//! over it, so they can be *checked* instead.
//!
//! That checkability is the deliverable. The function is a model of the
//! transport layer, which does not exist yet — when a real `Transport` lands,
//! the invariants below should move onto it rather than being re-derived.
//!
//! # Pure by construction
//!
//! [`emit`] takes an attestation and a policy and returns bytes. No clock, no
//! entropy, no peripheral. Same inputs, same output, so the whole thing runs on
//! a host with no radio attached — which is the only reason these properties are
//! testable at all.
//!
//! # What this cannot tell you
//!
//! Nothing about *when* or *how often* a device actually transmits, which is the
//! part of LPI/LPD that matters most to someone whose exposure is physical.
//! `docs/EMISSION_TESTING.md` is explicit that no test in this repo can speak to
//! that: it is spent by transmitting, not by what is transmitted, and measuring
//! it needs a radio and an SDR. What is here covers the second budget — the
//! shape of the bytes, given that a transmission happens.

use crate::{Attestation, ATTESTATION_PAYLOAD_LEN};

/// Bytes on the wire for one emission. Every frame is exactly this long.
///
/// `public_key` (32) + `signature` (64) + signed payload
/// ([`ATTESTATION_PAYLOAD_LEN`]). Fixed-width throughout, so there is nothing to
/// length-prefix and nothing whose size depends on content.
pub const FRAME_LEN: usize = 32 + 64 + ATTESTATION_PAYLOAD_LEN;

/// D5's padding tier: the ceiling a frame may not cross.
///
/// v2 lands exactly here (`docs/TOKEN_PROTOCOL.md` §5). v1 sits below it, which
/// is fine — the property that matters is that every frame in a deployment is
/// the *same* length, not that it is any particular length.
pub const PADDING_TIER: usize = 224;

/// Single-packet ceiling of the narrowest transport (RFM95W), per D5.
///
/// A frame plus the LoRa header and CRC must stay under this, or the narrowest
/// transport splits it into two packets — which is both a bigger emission
/// footprint and a distinguisher.
pub const SINGLE_PACKET_CEILING: usize = 255;

/// LoRa explicit-header preamble plus CRC, the overhead D5 reserved room for.
pub const LORA_HEADER_AND_CRC: usize = 21;

// Invariant 1, the half of it that is a relationship between constants rather
// than a property of any particular report. These are `const` assertions on
// purpose: a frame that outgrew the tier should fail the *build*, not a test
// someone might not run. The per-report half stays in the test module, because
// it depends on what a report contains.
const _: () = assert!(FRAME_LEN <= PADDING_TIER, "frame exceeds D5's padding tier");
const _: () = assert!(
    PADDING_TIER + LORA_HEADER_AND_CRC <= SINGLE_PACKET_CEILING,
    "D5's tier plus LoRa overhead exceeds the single-packet ceiling; \
     the narrowest transport would split every frame"
);

/// Whether the radio may be used at all.
///
/// There is no `Default` derive on purpose. `Policy::SILENT` has to be named,
/// and so does its opposite: radio silence is the device's identity rather than
/// a setting that happens to be off, and a policy that could be constructed
/// implicitly would be one someone could forget to think about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    radio: Radio,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Radio {
    Silent,
    Permitted,
}

impl Policy {
    /// Dark. [`emit`] produces nothing.
    pub const SILENT: Self = Self {
        radio: Radio::Silent,
    };

    /// Transmission allowed. Must be constructed deliberately.
    pub const fn permitting_radio() -> Self {
        Self {
            radio: Radio::Permitted,
        }
    }

    pub const fn is_silent(&self) -> bool {
        matches!(self.radio, Radio::Silent)
    }
}

/// Serialise one attestation for transmission, or refuse.
///
/// Returns `None` when the policy is silent. That is the whole of invariant 3:
/// emission is possible only where a policy explicitly permits it, and the type
/// system makes the silent case impossible to skip, because the caller has to
/// handle an `Option` before it has any bytes to send.
///
/// The layout carries no length prefixes and no framing, because every field is
/// fixed-width. It also carries no device identifier — see
/// `crates/icesickle-core/src/auth.rs` for why that is a rule rather than an
/// omission, and the tests below for the assertion that keeps it true.
pub fn emit(attestation: &Attestation, policy: &Policy) -> Option<[u8; FRAME_LEN]> {
    if policy.is_silent() {
        return None;
    }

    let mut frame = [0u8; FRAME_LEN];
    frame[..32].copy_from_slice(attestation.public_key_bytes());
    frame[32..96].copy_from_slice(attestation.signature_bytes());
    frame[96..].copy_from_slice(attestation.signed_payload_bytes());

    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttestationEvent;

    fn attest(seed: u8, event: AttestationEvent, ts: u64, counter: u32) -> Attestation {
        let mut bytes = [seed; 32];
        Attestation::create(&mut bytes, event, ts, counter).expect("payload must fit")
    }

    /// Every combination worth covering: both event variants, a `gpio` range,
    /// and magnitudes that move postcard's varint widths.
    fn matrix() -> impl Iterator<Item = (AttestationEvent, u64, u32)> {
        let events = [
            AttestationEvent::ButtonPress { gpio: 0 },
            AttestationEvent::ButtonPress { gpio: 127 },
            AttestationEvent::ButtonPress { gpio: 255 },
            AttestationEvent::Unknown,
        ];
        let magnitudes = [
            (0u64, 0u32),
            (1, 1),
            (12_345, 7),
            (u64::MAX, u32::MAX),
            (u64::from(u32::MAX), u32::MAX / 2),
        ];

        events
            .into_iter()
            .flat_map(move |e| magnitudes.into_iter().map(move |(t, c)| (e, t, c)))
    }

    // -----------------------------------------------------------------------
    // Invariant 1 — frame bound
    // -----------------------------------------------------------------------

    /// No report, whatever it contains, tips onto a second packet.
    ///
    /// The constant-to-constant half of this invariant — frame fits tier, tier
    /// plus LoRa overhead fits the ceiling — is asserted at compile time above,
    /// so it cannot be skipped by not running tests. What remains here is the
    /// part that depends on a report's contents.
    #[test]
    fn a_frame_always_fits_one_packet() {
        for (event, ts, counter) in matrix() {
            let frame = emit(&attest(7, event, ts, counter), &Policy::permitting_radio())
                .expect("policy permits");
            assert_eq!(
                frame.len(),
                FRAME_LEN,
                "{event:?} ts={ts} counter={counter} changed the emitted length"
            );
        }
    }

    /// Length is uniform across content, which is the property that stops an
    /// observer reading the event type off the packet size.
    #[test]
    fn emitted_length_does_not_depend_on_content() {
        let mut lengths = heapless::Vec::<usize, 32>::new();

        for (event, ts, counter) in matrix() {
            let frame = emit(&attest(7, event, ts, counter), &Policy::permitting_radio()).unwrap();
            let _ = lengths.push(frame.len());
        }

        assert!(
            lengths.iter().all(|l| *l == FRAME_LEN),
            "emitted length varied with content: {lengths:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Invariant 2 — no linkable identifier
    // -----------------------------------------------------------------------

    const DEVICE_A: u8 = 0x11;
    const DEVICE_B: u8 = 0xEE;

    /// One attestation from `device`, with a **fresh key**, as the design
    /// requires: `Attestation::create` is handed new entropy every time and the
    /// key is destroyed immediately after signing.
    ///
    /// Modelling this correctly is load-bearing. An earlier version of these
    /// tests gave each device one fixed seed for its whole life, which made the
    /// public key constant per device — and the scan below dutifully reported it
    /// as a device identifier. It was right to: a device that reuses a key *has*
    /// one. The bug was in the harness, and the fix is to model fresh entropy
    /// rather than to loosen the check.
    fn attest_fresh(
        device: u8,
        index: usize,
        event: AttestationEvent,
        ts: u64,
        counter: u32,
    ) -> Attestation {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            // Stands in for a TRNG draw: varies with the device, with the
            // attestation, and along the seed. Deterministic so the test is.
            *b = device
                .wrapping_mul(31)
                .wrapping_add((index as u8).wrapping_mul(17))
                .wrapping_add((i as u8).wrapping_mul(7));
        }
        Attestation::create(&mut seed, event, ts, counter).expect("payload must fit")
    }

    /// Scan for a *device-distinguishing invariant*: a byte position whose value
    /// is constant across everything device A emits, constant across everything
    /// device B emits, and different between the two.
    ///
    /// That is precisely the shape a serial number, a persistent keypair, or a
    /// MAC-derived field would take — and precisely what `auth.rs` forbids.
    ///
    /// A position constant across *both* devices is not a hit: that is a
    /// structural constant such as the version tag, which carries no identity. A
    /// cruder "nothing may be constant" check would fire on the version byte and
    /// teach nobody anything.
    ///
    /// `key_reuse` selects the failure mode: when true, each device signs
    /// everything with one key, which is what the check exists to catch.
    fn device_distinguishing_byte(key_reuse: bool) -> Option<usize> {
        /// Every frame one device emits across the matrix. Signing is the
        /// expensive part, so this happens once per device rather than once per
        /// byte position — the naive nesting costs 128x more Ed25519 operations
        /// and turns a fast test into a ninety-second one.
        fn frames(device: u8, key_reuse: bool) -> heapless::Vec<[u8; FRAME_LEN], 32> {
            let mut out = heapless::Vec::new();
            for (index, (event, ts, counter)) in matrix().enumerate() {
                let a = if key_reuse {
                    attest(device, event, ts, counter)
                } else {
                    attest_fresh(device, index, event, ts, counter)
                };
                let _ = out.push(emit(&a, &Policy::permitting_radio()).unwrap());
            }
            out
        }

        let a = frames(DEVICE_A, key_reuse);
        let b = frames(DEVICE_B, key_reuse);

        /// Is this position the same value in every frame? If so, which.
        fn fixed_value(frames: &[[u8; FRAME_LEN]], position: usize) -> Option<u8> {
            let first = frames.first()?[position];
            frames.iter().all(|f| f[position] == first).then_some(first)
        }

        (0..FRAME_LEN).find(|&position| {
            match (fixed_value(&a, position), fixed_value(&b, position)) {
                (Some(x), Some(y)) => x != y,
                _ => false,
            }
        })
    }

    /// No byte position identifies the device that produced the frame.
    #[test]
    fn no_byte_position_identifies_the_device() {
        assert_eq!(
            device_distinguishing_byte(false),
            None,
            "a byte position is constant per device and differs between devices \
             -- that is a device identifier"
        );
    }

    /// The scan above is not vacuous: reuse one key per device and it fires.
    ///
    /// Without this, `no_byte_position_identifies_the_device` would pass just as
    /// happily against a scan that could never find anything, and the invariant
    /// would be decoration. This is also a real regression test — key reuse is
    /// the most plausible way the property gets broken, since it takes only
    /// caching a `SigningKey` that was meant to be ephemeral.
    #[test]
    fn the_identifier_scan_catches_key_reuse() {
        let hit = device_distinguishing_byte(true)
            .expect("key reuse must be detected, or the scan proves nothing");

        assert!(
            hit < 32,
            "expected the reused public key (bytes 0..32) to be the giveaway, found byte {hit}"
        );
    }

    /// Two devices reporting the identical event still emit different bytes.
    ///
    /// The converse of the test above: not merely "no stable identifier", but
    /// that the frames are not equal either. Equal frames would make devices
    /// interchangeable rather than anonymous, and a Sink deduplicating on frame
    /// bytes would silently drop one of two genuine reports.
    #[test]
    fn identical_events_from_different_devices_differ() {
        let event = AttestationEvent::ButtonPress { gpio: 0 };
        let a = emit(&attest(0x11, event, 12_345, 7), &Policy::permitting_radio()).unwrap();
        let b = emit(&attest(0xEE, event, 12_345, 7), &Policy::permitting_radio()).unwrap();

        assert_ne!(a, b, "two devices produced byte-identical frames");

        // ...and the difference is in the key and signature, not the content.
        assert_eq!(
            a[96..],
            b[96..],
            "the signed payloads should match; only the key and signature differ"
        );
    }

    // -----------------------------------------------------------------------
    // Invariant 3 — silence when forbidden
    // -----------------------------------------------------------------------

    /// A silent policy yields no frame, for any input.
    #[test]
    fn a_silent_policy_emits_nothing() {
        for (event, ts, counter) in matrix() {
            assert!(
                emit(&attest(7, event, ts, counter), &Policy::SILENT).is_none(),
                "{event:?} ts={ts} counter={counter} emitted under a silent policy"
            );
        }
    }

    /// Emission requires an explicitly permissive policy, and `SILENT` is the
    /// one you get without saying anything.
    #[test]
    fn permission_must_be_explicit() {
        assert!(Policy::SILENT.is_silent());
        assert!(!Policy::permitting_radio().is_silent());

        let a = attest(7, AttestationEvent::ButtonPress { gpio: 0 }, 1, 1);
        assert!(emit(&a, &Policy::SILENT).is_none());
        assert!(emit(&a, &Policy::permitting_radio()).is_some());
    }

    // -----------------------------------------------------------------------
    // Purity
    // -----------------------------------------------------------------------

    /// Same inputs, same bytes. Without this the invariants above would only
    /// hold for the run that observed them.
    #[test]
    fn emission_is_pure() {
        for (event, ts, counter) in matrix() {
            let first = emit(&attest(7, event, ts, counter), &Policy::permitting_radio());
            let second = emit(&attest(7, event, ts, counter), &Policy::permitting_radio());
            assert_eq!(
                first, second,
                "{event:?} ts={ts} counter={counter} emitted different bytes on a second run"
            );
        }
    }

    /// The frame is exactly its three parts, in order, with nothing added.
    #[test]
    fn the_frame_is_key_signature_payload_and_nothing_else() {
        let a = attest(7, AttestationEvent::ButtonPress { gpio: 3 }, 999, 2);
        let frame = emit(&a, &Policy::permitting_radio()).unwrap();

        assert_eq!(&frame[..32], a.public_key_bytes());
        assert_eq!(&frame[32..96], a.signature_bytes());
        assert_eq!(&frame[96..], a.signed_payload_bytes());
    }
}
