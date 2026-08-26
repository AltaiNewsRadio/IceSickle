# Resolved architecture decisions (v2.1)

Deltas over the v2.0 security and transport architecture notes. Where this
conflicts with v2.0, this wins. The two narrative documents
(`icesickle_security_architecture.docx`, `icesickle_transport_architecture.docx`)
still need rewording to match; the decisions are recorded here so they do not
depend on that rewrite happening.

The through-line of v2.1: **decouple the system from a single hardcoded
operator** (formerly ALTAI), and **settle how an attestation proves it came from
a genuine device**.

`docs/TOKEN_PROTOCOL.md` develops D4 into a protocol. `docs/VERIFIER_MODEL.md`
is the prior design note these decisions answer.

---

## D1 — Operator decoupling

"Operator" is a role any deploying organisation fills: a newsroom, an NGO, a
research group, a lone journalist. ALTAI is demoted from a hardwired dependency
to *the reference deployment*.

Everything the device previously pointed at ALTAI — the backend public key it
seals payloads to, the delivery address — becomes **provisioning-time
configuration**, not baked-in identity. Structurally the firmware does not
change; it never knew "ALTAI" except as a configured key plus an address. The
work is server-side and in the provisioning tooling.

## D2 — Split the "Intelligence Engine" into Verifier and Sink

v2.0 fused verification, storage, and publication into one component. Split it
into two roles behind interfaces, mirroring the `Transport` trait:

- **Verifier** — checks a received attestation's token signature. Holds only the
  issuer's **public** key. Carries no identity state.
- **Sink** — where a verified attestation lands: a database, a local file, a live
  map, a transparency log, or nothing. Fully pluggable, operator's choice.

The device seals to the operator's backend key and ships bytes. It is oblivious
to which Verifier or Sink sits downstream.

```rust
trait Verifier { fn verify(&self, att: &Attestation) -> Result<VerifiedAttestation, VerifyError>; }
trait Sink     { fn commit(&mut self, att: &VerifiedAttestation) -> Result<(), SinkError>; }
```

## D3 — Distributed, offline verification

Verifier nodes verify locally using only the public key, with no callback to a
central issuer. This is what makes "bring your own local database that verifies
in the field" viable.

## D4 — Token scheme: blind Schnorr on ed25519 (publicly verifiable)

The secret **issue** key stays central at provisioning. The public **verify** key
is distributed to every Verifier — the "specimen card" model.

**Why not VOPRF.** A VOPRF's verify key *is* its issue key, so distributing the
checker would distribute forgery power: a seized field verifier could mint
attestations. Publicly verifiable signatures keep the issuing secret central
while letting verification scatter safely. D3 therefore forces a publicly
verifiable scheme, and that is the decisive argument — not signature size.

**Why blind Schnorr specifically.** It is the smallest publicly verifiable option
that fits a single LoRa frame. Blind RSA-2048 does not: its signature alone is
256 bytes, which pushes the frame past the RFM95W's single-packet ceiling. The
standard ROS objection to blind Schnorr requires many *concurrent* open signing
sessions; issuance here is a sequential offline batch ceremony, which removes the
precondition. See `docs/TOKEN_PROTOCOL.md` §7 for the quantified version.

**Relationship to the old ephemeral key.** In v2.0 each attestation was signed by
an ephemeral Ed25519 key that was zeroized immediately. That gives integrity but
**not genuineness**: anyone can mint a throwaway key and sign anything, so the
v2.0 claim that a signature proves "a genuine IceSickle device" was not backed.
The blind token supplies the missing binding — it proves the attestation came
from a genuinely provisioned device without revealing which one.

## D5 — Padding tier is 224 bytes

Length-uniform padding hides event type by packet size. A 256-byte tier collides
with the roughly 255-byte single-packet ceiling of the RFM95W, tipping onto two
packets on the narrowest transport. 224 bytes stays uniform and stays inside one
frame with room for the LoRa header and CRC.

## D6 — Revocation is epoch rotation

Anonymity means the issuer cannot link a token to a device, so there is **no
per-device revocation**, by design. The lever is the epoch key: rotate it to
invalidate a whole batch. The payload carries an epoch and a key id.

## D7 — Replay and double-report are a per-Sink concern

Offline verifiers cannot share a global spent-token set, so a token can be
re-accepted by a different node. Each Sink dedupes within its own view;
cross-operator dedup is impossible and is **accepted as a known limitation**. For
attestation this is low-harm: a replay merely re-reports an event that did
happen.

## D8 — The map is an optional Sink; location stays coarse by default

Operators may plot attestations; the default is no map. The only thing a map
forces back onto the device is **location granularity**. The device emits a
coarse **region** code from the codebook by default. Precise or GPS location is
an explicit per-deployment opt-in, with the *reporter* choosing granularity at
attestation time — never the backend silently pulling finer location. This
protects reporters under the seizure threat model: a seized device must not carry
a rooftop.

## D9 — No blockchain for verification

Verification is a local signature check. Consensus solves a
mutually-distrusting-parties problem the single-operator model does not have. A
public ledger's permanence and metadata leakage fight the secure-delete and
no-persistent-record design, and the device cannot hold a wallet key — that is a
persistent identity, forbidden by `src/auth/mod.rs`.

**Narrow optional exception, Sink-side only.** Timestamp transparency via
periodic **Merkle-root anchoring** (for example OpenTimestamps). Publishes one
root hash per epoch, never attestation content or location, giving
anti-backdating and censorship resistance to operators who want public
accountability. Off by default.

---

## Still open

D4 fixes the scheme, not the protocol. `docs/TOKEN_PROTOCOL.md` takes up the
protocol: what the issuer blind-signs, how a token binds to a specific
attestation, one-time versus reusable tokens, the provisioning ceremony and
device-side blinding, the verifier's exact offline check, public-key
distribution authenticity, and the unforgeability, unlinkability, and replay
arguments.
