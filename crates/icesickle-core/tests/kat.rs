//! Known-answer tests for the attestation crypto mechanics.
//!
//! **Scope is mechanical correctness only.** Nothing here validates the security
//! of the token scheme — that is under human review (see the security gate
//! issue), and no test suite can substitute for it. The job of this file is to
//! catch implementation bugs and pin behaviour, so that a reviewer reading
//! `docs/TOKEN_PROTOCOL.md` §7 can assume the mechanics underneath work and
//! spend their attention on the argument.
//!
//! Boneh–Shoup put the limit plainly: no amount of unit testing finds a
//! cryptographic vulnerability. These tests are the floor, not the ceiling.
//!
//! # What is here, and what is deliberately absent
//!
//! The brief this file implements asked for four groups. Two are written; two
//! cannot be, and saying so is more useful than approximating them:
//!
//! | Group | Status |
//! |---|---|
//! | Primitive vectors — Ed25519 (RFC 8032) | **written** |
//! | Primitive vectors — X25519 (RFC 7748) | **absent**, see below |
//! | Binding vectors, positive and negative | **partly**, see below |
//! | Round-trip and determinism | **written** |
//!
//! **X25519 is absent because there is no X25519 in this crate yet, and adding
//! one now would prejudge an open decision.** D12's sealed content layer does
//! not fit the 224-byte frame; the only route that fits derives the sealed box's
//! ephemeral key from `T` rather than carrying its own, which changes what
//! X25519 API is even needed. Pulling a dependency in ahead of that ruling would
//! be a guess dressed as a test.
//!
//! **Binding vectors over the sealed layer cannot be written for the same
//! reason** — there is no sealed layer to bind to. What *can* be written is the
//! half of the binding property that already exists: `sig_P` covers the whole
//! fixed-width payload region, so a payload swap or a single flipped bit
//! anywhere in it — padding included — invalidates the signature. Those are
//! below, and they are the mechanism D12 relies on rather than a stand-in for
//! it.
//!
//! The two missing groups unblock together, the moment D12's wire encoding is
//! settled.
//!
//! # On the vectors themselves
//!
//! The RFC 8032 vectors are transcribed constants. If one ever fails, **the
//! expected value is not the thing to change** — a transcription error and a
//! genuine regression look identical from here, and only one of them is fixed by
//! editing the test. Check the RFC.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use icesickle_core::{
    Attestation, AttestationEvent, AttestationPayload, ATTESTATION_PAYLOAD_LEN, PAYLOAD_VERSION,
};

/// Decode a compile-time hex literal. Panics on malformed input, which in a
/// test file is the correct response to a typo.
fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex literal has an odd length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("non-hex digit in literal"))
        .collect()
}

fn array32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("expected 32 bytes")
}

fn array64(s: &str) -> [u8; 64] {
    unhex(s).try_into().expect("expected 64 bytes")
}

// ---------------------------------------------------------------------------
// 1. Primitive vectors — Ed25519, RFC 8032 §7.1
// ---------------------------------------------------------------------------

/// One RFC 8032 test case.
struct Rfc8032Vector {
    name: &'static str,
    secret: &'static str,
    public: &'static str,
    message: &'static str,
    signature: &'static str,
}

const RFC_8032_VECTORS: &[Rfc8032Vector] = &[
    Rfc8032Vector {
        name: "TEST 1 (empty message)",
        secret: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        message: "",
        signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    Rfc8032Vector {
        name: "TEST 2 (one byte)",
        secret: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        message: "72",
        signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    Rfc8032Vector {
        name: "TEST 3 (two bytes)",
        secret: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        message: "af82",
        signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
];

/// Our Ed25519 reproduces RFC 8032 exactly, in both directions.
///
/// This pins the dependency, not our code. It is here because every other
/// guarantee in the system is downstream of Ed25519 behaving as specified, and a
/// silent change under a version bump would invalidate every attestation already
/// produced in the field.
#[test]
fn ed25519_matches_rfc_8032() {
    for v in RFC_8032_VECTORS {
        let sk = SigningKey::from_bytes(&array32(v.secret));
        let message = unhex(v.message);

        assert_eq!(
            sk.verifying_key().to_bytes(),
            array32(v.public),
            "{}: public key derivation diverged from RFC 8032",
            v.name
        );

        assert_eq!(
            sk.sign(&message).to_bytes(),
            array64(v.signature),
            "{}: signature diverged from RFC 8032",
            v.name
        );

        let vk = VerifyingKey::from_bytes(&array32(v.public)).expect("RFC public key must decode");
        vk.verify(&message, &Signature::from_bytes(&array64(v.signature)))
            .unwrap_or_else(|e| panic!("{}: RFC signature failed to verify: {e}", v.name));
    }
}

/// A one-bit change to an RFC signature must be rejected.
///
/// Trivial, and worth having: it proves the positive vectors above are testing
/// verification rather than a function that returns `Ok` unconditionally.
#[test]
fn ed25519_rejects_a_mutated_rfc_signature() {
    for v in RFC_8032_VECTORS {
        let vk = VerifyingKey::from_bytes(&array32(v.public)).unwrap();
        let message = unhex(v.message);

        let mut sig = array64(v.signature);
        sig[0] ^= 1;

        assert!(
            vk.verify(&message, &Signature::from_bytes(&sig)).is_err(),
            "{}: a mutated signature verified",
            v.name
        );
    }
}

/// Small-order public keys must not verify anything under strict verification.
///
/// `docs/TOKEN_PROTOCOL.md` §6 step 3 requires the verifier to reject a token
/// `T` that is non-canonical, the identity, or of small order, and says the
/// check is called out separately because §7's argument depends on it. This
/// pins the behaviour that requirement is leaning on.
///
/// Each candidate may be rejected at either stage — decoding or verification —
/// and both count. What must not happen is a signature verifying under one.
#[test]
fn small_order_public_keys_never_verify() {
    // The canonical Ed25519 points of order dividing 8.
    const SMALL_ORDER: &[&str] = &[
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    let message = b"attestation payload stand-in";

    for hex in SMALL_ORDER {
        let Ok(vk) = VerifyingKey::from_bytes(&array32(hex)) else {
            continue; // Rejected at decode. Also a pass.
        };

        // Try every signature we can cheaply manufacture. None may verify.
        for sig_bytes in [[0u8; 64], [1u8; 64], [0xffu8; 64]] {
            let sig = Signature::from_bytes(&sig_bytes);
            assert!(
                vk.verify_strict(message, &sig).is_err(),
                "small-order key {hex} verified a signature under verify_strict"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Binding — the half that exists today
// ---------------------------------------------------------------------------
//
// D12's content layer is not built (see the module docs), so there is no sealed
// ciphertext to swap. What is testable is the property D12 relies on: `sig_P`
// covers the entire fixed-width payload region, so nothing inside it can be
// altered or substituted without invalidating the signature. When the sealed box
// lands inside that region, these tests already cover it.

fn attest(event: AttestationEvent, ts: u64, counter: u32) -> Attestation {
    let mut seed = [7u8; 32];
    Attestation::create(&mut seed, event, ts, counter).expect("payload must fit")
}

fn verifying_key(a: &Attestation) -> VerifyingKey {
    VerifyingKey::from_bytes(a.public_key_bytes()).expect("attestation key must decode")
}

/// Positive: a well-formed attestation verifies over its own signed region.
#[test]
fn a_genuine_attestation_verifies() {
    let a = attest(AttestationEvent::ButtonPress { gpio: 0 }, 12_345, 7);
    verifying_key(&a)
        .verify_strict(
            a.signed_payload_bytes(),
            &Signature::from_bytes(a.signature_bytes()),
        )
        .expect("a genuine attestation must verify");
}

/// Negative: swapping the whole signed region for another valid one is rejected.
///
/// This is the payload-transplant case D12 names — a valid signature carried
/// onto content it never covered. Here the "swap" is another genuine payload,
/// which is the strongest form: the substitute is not malformed, merely
/// different.
#[test]
fn a_transplanted_signature_is_rejected() {
    let a = attest(AttestationEvent::ButtonPress { gpio: 0 }, 12_345, 7);
    let b = attest(AttestationEvent::ButtonPress { gpio: 1 }, 99_999, 8);

    assert_ne!(
        a.signed_payload_bytes(),
        b.signed_payload_bytes(),
        "the two payloads must differ for this test to mean anything"
    );

    assert!(
        verifying_key(&a)
            .verify_strict(
                b.signed_payload_bytes(),
                &Signature::from_bytes(a.signature_bytes()),
            )
            .is_err(),
        "a signature verified over a payload it never covered"
    );
}

/// Negative: every single bit of the signed region is covered, padding included.
///
/// Exhaustive over bit positions rather than sampling. The padding bytes are the
/// ones worth this effort — a verifier that decoded the struct and ignored the
/// remainder would pass a spot check and still leave room to smuggle bytes.
#[test]
fn every_bit_of_the_signed_region_is_covered() {
    let a = attest(AttestationEvent::ButtonPress { gpio: 0 }, 12_345, 7);
    let vk = verifying_key(&a);
    let sig = Signature::from_bytes(a.signature_bytes());

    for byte in 0..ATTESTATION_PAYLOAD_LEN {
        for bit in 0..8 {
            let mut tampered = *a.signed_payload_bytes();
            tampered[byte] ^= 1 << bit;

            assert!(
                vk.verify_strict(&tampered, &sig).is_err(),
                "flipping bit {bit} of byte {byte} left the signature valid"
            );
        }
    }
}

/// Negative: the right payload under the wrong key is rejected.
///
/// The token analogue of "presented a credential from the wrong epoch". It
/// cannot be written against `key_id` yet, because v2's epoch selection does not
/// exist — but the underlying property, that a signature is only meaningful
/// under the key that made it, is the same one §6 step 4 will rest on.
#[test]
fn a_payload_under_the_wrong_key_is_rejected() {
    let a = attest(AttestationEvent::ButtonPress { gpio: 0 }, 12_345, 7);

    let mut other_seed = [9u8; 32];
    let other = SigningKey::from_bytes(&other_seed);
    other_seed.fill(0);

    assert!(
        other
            .verifying_key()
            .verify_strict(
                a.signed_payload_bytes(),
                &Signature::from_bytes(a.signature_bytes()),
            )
            .is_err(),
        "an attestation verified under a key that did not sign it"
    );
}

// ---------------------------------------------------------------------------
// 3. Round-trip and determinism
// ---------------------------------------------------------------------------

/// Encode then decode returns the identical structure, and the remainder is
/// padding rather than smuggled content.
#[test]
fn payload_round_trips_exactly() {
    let event = AttestationEvent::ButtonPress { gpio: 42 };
    let a = attest(event, 12_345, 7);

    let (decoded, rest): (AttestationPayload, &[u8]) =
        postcard::take_from_bytes(a.signed_payload_bytes()).expect("payload must decode");

    assert_eq!(decoded.version, PAYLOAD_VERSION);
    assert_eq!(decoded.event, event);
    assert_eq!(decoded.timestamp_ms, 12_345);
    assert_eq!(decoded.counter, 7);
    assert!(
        rest.iter().all(|b| *b == 0),
        "the region after the struct must be zero padding"
    );
}

/// Encoding is deterministic: identical inputs give byte-identical output.
///
/// Required by `docs/TOKEN_PROTOCOL.md`'s premise that the only non-deterministic
/// inputs are the seed and the clock. If this ever fails, a verifier cannot
/// reproduce what a device signed.
#[test]
fn encoding_is_deterministic_across_the_input_range() {
    let events = [
        AttestationEvent::ButtonPress { gpio: 0 },
        AttestationEvent::ButtonPress { gpio: 255 },
        AttestationEvent::Unknown,
    ];

    for event in events {
        for (ts, counter) in [(0u64, 0u32), (u64::MAX, u32::MAX), (12_345, 7)] {
            let first = attest(event, ts, counter);
            let second = attest(event, ts, counter);

            assert_eq!(
                first.signed_payload_bytes(),
                second.signed_payload_bytes(),
                "{event:?} ts={ts} counter={counter} encoded differently on a second run"
            );
            assert_eq!(
                first.signature_bytes(),
                second.signature_bytes(),
                "{event:?} ts={ts} counter={counter} signed differently on a second run"
            );
        }
    }
}

/// The emitted length never varies. Traffic analysis depends on it, and so does
/// D5's frame arithmetic.
#[test]
fn the_signed_region_is_always_the_same_length() {
    let events = [
        AttestationEvent::ButtonPress { gpio: 0 },
        AttestationEvent::ButtonPress { gpio: 255 },
        AttestationEvent::Unknown,
    ];

    for event in events {
        for (ts, counter) in [(0u64, 0u32), (u64::MAX, u32::MAX), (1, 1)] {
            assert_eq!(
                attest(event, ts, counter).signed_payload_bytes().len(),
                ATTESTATION_PAYLOAD_LEN,
                "{event:?} ts={ts} counter={counter} changed the signed length"
            );
        }
    }
}
