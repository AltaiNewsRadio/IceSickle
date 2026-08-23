# no_std entropy spike

Spike, not a migration. Lives in `spikes/nostd-entropy/`, builds independently of
the esp-idf crate at the repo root, and changes nothing about it.

The question it answers: **what does the signing path look like when the entropy
precondition is structural rather than assumed?**

## 1. Why no_std, and why `Trng` specifically

IceSickle's entire value rests on one property — the ephemeral signing key is
unpredictable. Everything else (zeroization, unlinkability, ephemerality) is
downstream of that. If the key is guessable, none of it matters.

The ESP32-S3 hardware RNG only produces true random numbers under one of two
conditions. From `esp-hal` 1.1.2, `src/rng/mod.rs`:

> The hardware RNG produces true random numbers under any of the following
> conditions:
> - RF subsystem is enabled (i.e. Wi-Fi or Bluetooth are enabled).
> - An ADC is used to generate entropy.
>
> [...] If none of the above conditions are true, the output of the RNG should be
> considered pseudo-random only.

IceSickle is radio-silent, so the RF path is permanently unavailable. **The
SAR-ADC path is the only way this device can hold a true-entropy claim at all.**

The esp-idf prototype could not express that. It called `esp_fill_random()`,
which returns bytes unconditionally and tells the caller nothing about which
regime produced them. `entropy.rs` asserted in a comment that entropy came from
thermal noise and was "still considered cryptographically secure"; nothing in the
code established it, and the only runtime check — rejecting four all-zero bytes —
detects a dead peripheral, not a weak one. The device was reading entropy of
unverifiable quality for the one operation where quality is the whole point.

### What is actually enforced, and by what

Worth being precise, because the shorthand "entropy enforced by the type system"
is true of the finished path but not of any single piece of it:

| Mechanism | Enforced by | Provided by |
|---|---|---|
| ADC1 cannot be used elsewhere while entropy is live | compile time (ownership) | esp-hal: `TrngSource::new` consumes `RNG` + `ADC1` |
| No `Trng` without a live source | **runtime**, fail-closed | esp-hal: `Trng::try_new() -> Result<_, TrngSourceNotEnabled>` |
| Entropy handle cannot outlive its source | compile time (lifetimes) | this spike: `Entropy<'s>` borrows `EntropySource` |
| Signing cannot be reached without an entropy handle | compile time (signature) | this spike: `Attestation::create(&Entropy<'_>, ..)` |

esp-hal's own gate is a runtime check against a global counter, not a proof —
and `Trng::try_new()` stays public and callable from anywhere. The spike layers
the compile-time part on top: `EntropySource::entropy()` is infallible *because*
holding `&EntropySource` is itself the proof the source is live, and the handle
it returns is lifetime-bound to that proof. `main.rs` demonstrates the runtime
gate holding before the source exists, then opening after.

### What no_std buys alongside this

- **No allocator.** `postcard` is built without its `alloc` feature, so
  `to_allocvec` is not reachable; payloads encode with `to_slice` into a stack
  buffer and hex renders into `heapless::String`. A heap-allocated copy of a
  signed payload cannot appear, because there is no heap.
- **A provably network-free binary.** esp-idf links FreeRTOS, lwIP and mbedTLS
  whether or not you call them. Bare metal links what you use. The CI guard can
  eventually check ELF symbols rather than grepping comments.
- **Auditability.** 161 crates in the spike's lockfile, no radio crate among
  them, and CI now fails if one appears — including transitively.

## 2. Radio-silent by default; radios are opt-in tiers

Radio silence is the device's identity, not a configuration. It is why
`THREAT_MODEL.md`, the `no-network-guard` CI job, and `src/auth/mod.rs` exist,
and this spike keeps all three as law. The guard now covers `spikes/` as well as
`src/`, and additionally scans every manifest and lockfile for radio crates.

Attestations are **create-now / transmit-later**. Signing happens offline, with
the RF subsystem off — which is exactly what makes the ADC entropy path
load-bearing rather than optional. A future transport lands behind a `Transport`
trait as an explicit, reporter-initiated tier. Not in this spike; no BLE, LoRa,
cellular or satellite here.

The design consequence to keep hold of: **no radio may ever become a precondition
for producing an attestation.** The moment signing depends on a transport being
up, the device stops being usable in the situation it was built for.

## 3. Obfuscation is a transport concern, and it does not hide emission

Two different protections, routinely conflated:

**Obfuscation** protects *content and linkability* — what the message says, and
whether two messages came from the same source. It belongs at the transport layer
or off-device, at the point where bytes leave. Padding to a fixed length is the
one piece of it this spike does on-device: every attestation signs exactly
`ATTESTATION_PAYLOAD_LEN` bytes regardless of event type, so a future transport
emits a constant-size frame and the event variant cannot be inferred from length.
The padding sits inside the signed region, so it cannot be stripped without
invalidating the signature.

Note the limit even there. Fixed length fixes the *emitted* length. If a transport
ever carries the payload in cleartext, the trailing zero run still reveals the
true encoded length to anyone reading the bytes. That is the transport's problem
to solve, and it is a reason to prefer an encrypted or constant-weight encoding
at that layer rather than to add more machinery here.

**Emission discipline** protects *the fact that something transmitted at all* —
and nothing at the payload layer touches it. No amount of encryption, padding or
identifier rotation conceals that RF energy left a device at a given time from a
given place. Direction-finding does not read your payload. For a reporter whose
exposure is physical, the transmission event is the disclosure, and the only
controls over it are when, how often, how long, and from where you emit — or
not emitting, and moving the attestation off the device by other means.

Hence: obfuscation reduces what an intercept yields. It does not reduce the
probability of being located. Those budgets are separate, and the second one is
spent by transmitting, not by what you transmit.

## Status

Compile-verified only. No ESP32-S3 was available; nothing here has run on
silicon. Specifically unverified:

- that `ensure_randomness()` genuinely raises entropy quality on real hardware —
  the spike proves the source is *enabled*, not that its output is good. Statistical
  validation of TRNG output is separate work and should not be skipped.
- power and timing cost of holding the SAR ADC on continuously.
- whether `esp-bootloader-esp-idf`'s app descriptor path boots as expected.

No button: the trigger is not part of the signing path, and leaving it out keeps
the spike's diff readable.
