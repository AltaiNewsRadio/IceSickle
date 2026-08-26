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
persistent identity, forbidden by `crates/icesickle-core/src/auth.rs`.

**Narrow optional exception, Sink-side only.** Timestamp transparency via
periodic **Merkle-root anchoring** (for example OpenTimestamps). Publishes one
root hash per epoch, never attestation content or location, giving
anti-backdating and censorship resistance to operators who want public
accountability. Off by default.

## D10 — Issuer key distribution: pin a root, not a map

A Verifier holds `key_id -> X` and checks `sigma` under it (`TOKEN_PROTOCOL.md`
§6 step 4). Substitute `X` and forgery is trivial, so `X` has to arrive
authentically at a node that is **offline by design** (D3).

The earlier sketch was to *pin the map* at verifier provisioning. **That works
exactly once.** D6 makes revocation *be* epoch rotation, so `X` changes on a
schedule — and a pinned map means physically revisiting every verifier at every
rotation. The sketch and D6 were in direct tension; it was one line long, which
is why nobody saw it.

**Decision: pin one long-lived operator root key `K_op` at verifier
provisioning.** Each epoch key then ships as a short certificate signed by it:

```
cert = (key_id, X, valid_from, valid_until)  ||  Sign_{K_op}(cert)
```

A verifier accepts a new epoch key **iff** the certificate verifies under its
pinned root. Certificates are self-authenticating, so they travel over any
untrusted channel — sneakernet, a radio burst, an email attachment, a QR code
photographed off a screen — and rotation stops requiring physical access to
every node.

### Why this is not the device identity `auth.rs` forbids

It looks like exactly that, and the distinction is the whole point of the rule:
**the prohibition is on *device* identity.** The operator is a named party by
construction — D1 defines "operator" as a role a newsroom or an NGO fills, and
every attestation is already sealed to that operator's backend key. `K_op` says
who issued a batch of tokens. It says nothing about which device spent one, and
the blind signature (D4) is what guarantees the issuer itself cannot tell.

### What it costs, named

- **`K_op` is a single point of compromise.** Whoever holds it can mint epoch
  keys every verifier will accept. The mitigation is operational rather than
  cryptographic: it signs a handful of certificates a year, so it can stay
  offline — on paper, on an air-gapped machine, in an HSM for operators who have
  one. It is a smaller and more manageable secret than the issue key `x`, which
  has to be live during a provisioning ceremony.
- **Root rotation still needs physical access.** If `K_op` is compromised or
  retired, every verifier must be re-provisioned. Accepted: it should be rare,
  and every pinned-root scheme bottoms out somewhere.
- **Early revocation of an epoch key is not solved.** If `X` leaks before
  `valid_until`, a signed revocation has to reach verifiers that are offline by
  design and may never receive it. **Expiry is therefore the real bound**, which
  makes epoch length load-bearing for a *third* reason: it already sets the
  freshness/anonymity knob and the revocation granularity, and it now caps the
  damage window of a leaked epoch key. Decide it with this in view.
- **Verifiers need a clock.** `valid_from`/`valid_until` presume one. That is
  fine — a verifier is a laptop or a server, and the *device's* clocklessness is
  precisely why §6 uses a beacon instead. But an offline verifier's clock is
  attacker-influenceable: roll it back and an expired epoch key becomes
  acceptable again. The beacon values a verifier already holds give a weak
  monotonic floor, since it cannot have received round `N`'s value before round
  `N` was published. That is a partial mitigation, not a fix. Stated rather than
  solved.

### The small-deployment mode, deliberately kept

An operator running three verifiers who would rather not hold a long-lived
signing key at all **may pin the map directly and re-provision on rotation**.
That is the superseded sketch, retained as an explicit mode rather than a
default: it removes the single point of compromise entirely, and pays for it by
making every rotation a physical operation.

Verifier implementations should support both, because the check is the same
either way. The only difference is whether the pinned object is a root or a leaf.

### Where D9's anchoring fits

Merkle anchoring stays what D9 made it: an optional audit trail. Publishing each
epoch's `X` lets a substitution be **detected after the fact**, which is worth
having. It cannot be the mechanism, because checking it needs network access at
verification time and D3 denies the verifier exactly that.

### What it does not cost

Nothing on the wire, and nothing in the firmware. The frame stays 224 bytes, the
payload already carries `key_id` (§5), and certificates are held by verifiers out
of band. The device never learns `K_op` exists.

---

## Still open

D4 fixes the scheme, not the protocol. `docs/TOKEN_PROTOCOL.md` takes up the
protocol: what the issuer blind-signs, how a token binds to a specific
attestation, one-time versus reusable tokens, the provisioning ceremony and
device-side blinding, the verifier's exact offline check, and the
unforgeability, unlinkability, and replay arguments. Public-key distribution
authenticity was on that list and is now D10; §10 of that document carries the
certificate format and the verifier's added check.

What remains open is tracked in `docs/ROADMAP.md`. **Epoch length is now the
next thing to decide** — D10 made it load-bearing for a third reason.
