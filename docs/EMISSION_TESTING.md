# Emission testing

*What we can assert about the artifact IceSickle produces, what we cannot, and why most
of this is already done.*

This note exists because a sibling project — [dpi-bench], an offline test harness for the
anti-DPI tool [zapret2] — needed the same underlying tool: **capture the real emitted
artifact, then run property assertions on it.** The question was whether that pattern
transfers here. It does, but far more narrowly than it first appeared, and the parts that
transfer are largely already implemented.

Recording the scoping so it does not get re-derived, and so the two wrong framings below
do not come back.

[dpi-bench]: https://github.com/Mezo-oz/DPI-Tester
[zapret2]: https://github.com/bol-van/zapret2

## Two framings to discard

**"Assert on emitted radio frames."** There are none, and that is deliberate. Radio
silence is the device's identity, not a configuration ([NOSTD_ENTROPY_SPIKE.md](NOSTD_ENTROPY_SPIKE.md)
§2), enforced by the `no-network-guard` CI job, which fails if a radio crate appears at all
— including transitively — and scans every manifest and lockfile. Attestations are
**create-now / transmit-later**. A transport lands later behind a `Transport` trait as an
explicit, reporter-initiated tier; no BLE, LoRa, cellular or satellite exists today.

So properties phrased over "frames per policy state", "MAC-linkable identifiers in a
frame", or "SBD payload entropy" describe a tier that does not exist and is deliberately
excluded. They are not deferred work. They are a category error until a `Transport` tier
is real, and the governing constraint stays: **no radio may ever become a precondition for
producing an attestation.**

**"Extract framing into a pure function so it can be host-tested."** Already done.
`crates/icesickle-core` is `no_std` with no allocator and no hardware; entropy and the
clock are parameters supplied by the caller. That is precisely the move, and it landed in
the core-crate refactor.

## What the artifact actually is

The emitted artifact today is the signed attestation:

```
{ public_key: [u8; 32], signature: [u8; 64], signed_payload: [u8; ATTESTATION_PAYLOAD_LEN] }
```

with `ATTESTATION_PAYLOAD_LEN = 32` (`crates/icesickle-core/src/lib.rs:47`). It leaves the
device by whatever out-of-band means the reporter chooses. Assertions belong on those
bytes.

## What is already asserted

`crates/icesickle-core` carries ten host tests. Mapped onto the property vocabulary this
note was meant to introduce, they already cover most of it:

| Property | Test |
|---|---|
| Constant emitted length regardless of event variant or magnitude | `payload_length_is_fixed_across_events_and_magnitudes` |
| Padding sits inside the signed region and cannot be stripped | `tampering_with_padding_invalidates_the_signature` |
| Encoding is deterministic and pinned | `signing_is_deterministic_and_pinned`, `identical_inputs_give_identical_output` |
| Distinct inputs do not collide | `differing_inputs_give_differing_signatures` |
| Key material does not survive the operation | `seed_is_zeroized_even_on_success` |
| Artifact verifies standalone | `signature_verifies_against_its_own_public_key` |
| No trailing garbage in the padded region | `payload_round_trips_and_the_remainder_is_zero` |
| Worst-case payload fits | `worst_case_payload_still_fits_with_room_to_spare` |

The fixed-length property is the important one for signature minimisation: every
attestation signs exactly `ATTESTATION_PAYLOAD_LEN` bytes regardless of event type, so a
future transport emits a constant-size frame and the event variant cannot be inferred from
length.

Note the limit already recorded in the spike: fixed length fixes the *emitted* length. If a
transport ever carries the payload in cleartext, the trailing zero run still reveals the
true encoded length. That is the transport's problem, and an argument for an encrypted or
constant-weight encoding at that layer rather than more machinery here.

## What is genuinely still open

One property in this family has no test: **cross-attestation unlinkability.**

Ephemeral keys mean no persistent identity, and each attestation carries a fresh public
key. But the payload also carries a local counter and a coarse timestamp. Nothing currently
asserts that two attestations produced by the same device in the same power cycle share no
field an observer could use to correlate them. The counter in particular is monotonic
within a power cycle by design — which is what makes ordering work, and is exactly the kind
of field that links two artifacts to one source.

That tension is worth stating rather than testing away: ordering and unlinkability pull in
opposite directions here, and which one wins is a decision for
[VERIFIER_MODEL.md](VERIFIER_MODEL.md), not something a test should silently settle. The
test to write once that decision lands asserts whatever the answer turns out to be —
"correlatable only within a power cycle, never across" being the likely shape.

## The distinction worth keeping

[NOSTD_ENTROPY_SPIKE.md](NOSTD_ENTROPY_SPIKE.md) §3 states it more sharply than the sibling
project did, and it is the reason the two projects share less than they seemed to:

- **Obfuscation** protects *content and linkability* — what the message says, and whether
  two messages came from the same source.
- **Emission discipline** protects *the fact that something transmitted at all* — and
  nothing at the payload layer touches it.

dpi-bench lives entirely in the first category. A DPI classifier reads content; it does not
direction-find you. Every property in that harness is a content property, which is why its
assertion vocabulary maps onto the padding and determinism tests here and stops dead at
anything about *when* or *whether* a device emits.

For a reporter whose exposure is physical, the second budget is the one that matters, and
it is spent by transmitting — not by what is transmitted. No test in this repo can speak to
it. Hardware-in-the-loop measurement (real device, SDR or logic analyser) would be a
different activity entirely, outside `cargo test`, and only meaningful once there is a
transport to measure.

## Running the core tests

From the repo root:

```sh
cargo test -p icesickle-core
```

Alone, not `--workspace`: cargo's v2 resolver unifies features across the packages
one invocation selects, and `verify-attestation` pulls `ed25519-dalek` with `std`.
Testing them together builds `icesickle-core` against a std-enabled graph, which
would mask exactly the regression the `no_std` build in CI is there to catch.
