# Roadmap

Open work, and where the detail for each item already lives. This file is an
index plus the items that had nowhere else to go; it does not restate the
reasoning in the documents it points at.

Nothing here is scheduled. Order within a section is rough priority, not a plan.

---

## Hardening regressions from the retired prototype

Retiring the esp-idf crate dropped two `sdkconfig` settings that had no
bare-metal equivalent. `docs/ARCHITECTURE.md` records where the settings table
used to be; this is the tracking entry.

### Memory protection (was `CONFIG_ESP_SYSTEM_MEMPROT_FEATURE`)

**Status: absent, no upstream support.**

On the ESP32-S3 this is the PMS block, reached through the `SENSITIVE`
peripheral. That peripheral exists as a singleton in `esp-metadata-generated`,
so the registers are addressable — but **esp-hal 1.1.2 ships no memprot or PMS
driver**, and nothing in `esp-hal/src` references it.

Two routes, neither cheap:

- Drive the `SENSITIVE` registers directly from the firmware. Fastest to a
  working result, and it means owning a chunk of undocumented-in-Rust register
  programming that upstream will eventually duplicate.
- Contribute a driver to esp-hal. Slower, but this is exactly the kind of gap
  the migration to esp-hal was supposed to close rather than route around.

Worth sizing before choosing. The security value is real but bounded: it makes
regions non-writable or non-executable, which mitigates code injection on a
device whose threat model already concedes physical access and reflashing
(`THREAT_MODEL.md`).

### Stack canaries (was `CONFIG_COMPILER_STACK_CHECK_MODE_STRONG`)

**Status: partly covered already, by an esp-hal default nobody chose.**

esp-hal places a sentinel 60 bytes from the stack's end and watches it with a
data watchpoint. `ESP_HAL_CONFIG_STACK_GUARD_MONITORING` defaults to `true` and
the firmware does not override it, so this is live today — a write past the
guard panics with "Detected a write to the stack guard value".

That is **stack-overflow detection, not what the ESP-IDF setting did.**
`CONFIG_COMPILER_STACK_CHECK_MODE_STRONG` is GCC's `-fstack-protector-strong`:
a canary per function frame, catching a smash *within* the stack rather than a
run off the end of it.

So the remaining gap is per-frame canaries, and the honest question is whether
they are worth it here:

- Rust's equivalent is `-Z stack-protector`, which is nightly-only. The `esp`
  toolchain is a nightly fork and the crate already sets `[unstable] build-std`,
  so it is plausibly reachable — **untested**, and worth ten minutes to find out
  before any of this is argued further.
- The attack `-fstack-protector-strong` defends against is a buffer overflow in
  C. This firmware has no `unsafe` outside the entropy driver and no parsing of
  attacker-supplied input at all — the device only ever signs data it
  constructed itself. The value here is lower than the prototype's config
  implied.

Two things to do before deciding: confirm `-Z stack-protector` builds under the
`esp` toolchain, and record the code-size cost. If it is free, take it; if it
is not, this is arguably a setting the prototype carried without needing it.

---

## Already documented elsewhere

Pointers, not summaries. Each of these is developed where it is linked.

**v2 token protocol** — `docs/TOKEN_PROTOCOL.md` §11 is the live list:

- ~~Issuer key distribution.~~ **Settled** as D10: verifiers pin a long-lived
  operator root key and accept epoch keys by certificate, rather than pinning
  the epoch keys themselves. `TOKEN_PROTOCOL.md` §10 has the format and the
  check.
- **Epoch length — now the most blocking item here.** It sets the
  freshness/anonymity knob, the revocation granularity (D6), and, since D10, the
  damage window of a leaked epoch key: an offline verifier may never receive a
  revocation, so expiry is the only bound that reaches it.
- Beacon source — external (drand) versus verifier-signed.
- Entropy re-scoping — v2 moves key generation from press time to provisioning
  time, so `docs/NOSTD_ENTROPY_SPIKE.md` guards the right secret at the wrong
  moment.
- Cryptographic review. §7 is a sketch by a non-specialist and says so.
  **Implementing the protocol before this happens means building on unreviewed
  crypto.**

**Hardware validation** — `docs/NOSTD_ENTROPY_SPIKE.md`, Status. Every item
needs silicon; no emulator can substitute, because QEMU's RNG returns host
randomness regardless of whether the SAR-ADC path is live.

- Statistical validation of TRNG output. The spike proves the source is
  *enabled*, never that it is good.
- Power and timing cost of holding the SAR ADC on continuously.

**Feature ideas** — `docs/ARCHITECTURE.md`, Future Extensions:
challenge-response, a persistent counter, more event types, batch signing. These
are sketches, not commitments, and some conflict with the v2 payload budget.
