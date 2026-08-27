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
every attestation is already destined for that operator's backend (whether it is
*sealed* to it is the open question D11 surfaced). `K_op` says
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

## D11 — Epoch length: two periods, and the anonymity floor under both

"Epoch length" was being tracked as one knob. **The wire format already has
two.** `TOKEN_PROTOCOL.md` §5 carries `key_id` and `beacon_round` as separate
payload fields, and they answer different questions:

| Period | Field | Governs |
|---|---|---|
| **Beacon round** | `beacon_round` | how tight the freshness lower bound is |
| **Key epoch** | `key_id` | revocation granularity (D6), leaked-key damage window (D10) |

Treating them as one number forced a trade that does not actually exist. They are
hereby separate, with the rule that **the key epoch is an integer multiple of the
beacon round** — so a key rotation lands on a round boundary and the coarser
field never subdivides the finer one.

### The constraint that binds them

The anonymity set is not "one epoch's batch", as §7 currently says. It is the
**intersection of every payload field an observer can read** — `key_id`,
`beacon_round`, `region` (D8), `event` — so it is bounded by whichever of them is
finest-grained.

Two consequences fall straight out:

- **Splitting the periods buys cheaper revocation for free.** With the key epoch
  coarser than the beacon round, the beacon is already the binding constraint, so
  shortening the key epoch costs no anonymity at all until it reaches the beacon
  round. That is why the rule above is `>=` and not `==`.
- **It does not buy anonymity.** No arrangement of these two numbers widens the
  crowd beyond what the finest field allows. `region` is in that intersection
  too: a fine-grained region code shrinks the crowd exactly as a short beacon
  round does, which ties D8 to this decision more tightly than either document
  previously admitted.

### Decision: 7-day beacon round, 28-day key epoch

**Beacon round: 7 days.** The reasoning is that the *upper* bound is already
loose. §3.3 of `VERIFIER_MODEL.md` gets the upper bound from a co-signature at
ingest — but this device is create-now / transmit-later by design, and an
artifact may sit for days before it reaches anything that can co-sign it. The
interval `[t, T]` is therefore wide because of `T`, and paying anonymity to
tighten `t` buys very little. Anonymity is scarce here; lower-bound precision is
not the scarce thing.

**Key epoch: 28 days.** Four beacon rounds exactly. D10 made rotation cheap — a
114-byte certificate over any untrusted channel, no physical access — which
removes the reason long key epochs used to be attractive. 28 days caps the D10
damage window at a month and is a plausible cadence for handing out fresh token
batches anyway.

### The floor, stated because the numbers cannot fix it

Crowd size for one beacon round is roughly

```
fleet size  ×  attestations per device per round
```

A 50-device deployment where each device attests about once a week gives a crowd
of ~50 per 7-day round. The same fleet on an hourly round gives a crowd of
**well under one** — the attestation is effectively signed "by whoever was
active that hour", and no choice of number repairs it.

So: **below roughly a few dozen active devices per round, the beacon round
provides no anonymity and this decision cannot supply any.** An operator in that
position should treat the beacon as a pure freshness anchor, take unlinkability
from relay mixing instead (the batch/delay/reorder model in `README.md`), and
understand that attestations are linkable to a small group. That is a real limit
of the design, not a tuning failure.

### When to override

Shorten the beacon round when the upper bound is tight — a deployment relaying
promptly over a wired gateway in the same building, where `T` lands within
minutes. There the lower bound *is* the limiting factor and the trade reverses.
That is the deliberate setting `VERIFIER_MODEL.md` §3.2 asks for; 7 days is the
default for a deployment that has not made that determination.

### Interaction with the beacon source

Still open, and this constrains it rather than settling it. Both remaining
candidates work at a 7-day sampling period: drand publishes far faster than that
and the device simply samples one round per period, and an operator-signed epoch
token is issued on whatever period the operator picks. Sampling period and beacon
native period are not the same thing.

## D12 — Verifier reads the outer layer; Sink opens the seal

**Provisional. Pending specialist review —
[issue #16](https://github.com/Mezo-oz/IceSickle/issues/16).** Recorded so it
stops blocking, not because it is confirmed. No security-relevant decision after
this one may be built on it until that gate closes.

Resolves the D1/D2 ↔ `TOKEN_PROTOCOL.md` ↔ D3 contradiction D11 surfaced. The
attestation is two layers:

- **Genuineness layer, cleartext.** Blind token and payload signature. Publicly
  verifiable with the issuer's public verify key. A Verifier checks this offline
  in the field and decrypts nothing.
- **Content layer, sealed.** Event, region, precision, timestamp, in a sealed box
  to the operator's backend key. Only the **Sink** holds that private key.

**Verifier and Sink become distinct roles**, which is the substance of this
decision. A field node is a Verifier: it holds public material and unopenable
blobs. That preserves D3 (offline public-key verification), keeps D1/D2's sealing
claim true, and means a seized field node decrypts nothing.

### The binding requirement is already met

The concern is real: a valid token and signature must not be transplantable onto
a swapped payload. The proposed remedy was to have the signature commit to a hash
of the sealed box.

**That is already what happens.** §5 makes `sig_P` an Ed25519 signature over all
64 bytes of the padded payload region, and §6 step 5 verifies it over all 64. A
sealed box placed inside `P` is covered byte-for-byte, so the commitment exists
without adding a mechanism. The Verifier checks it without opening the seal,
exactly as required.

No new construction is needed here, and adding a redundant hash-commitment layer
would be one more thing for a reviewer to check for no gain.

### It does not fit the frame

This is the blocking problem, and it is arithmetic rather than judgement.

| | bytes |
|---|---|
| Frame (D5) | 224 |
| `T` (32) + `sig_P` (64) + `sigma` (64) | −160 |
| **available for `P`** | **64** |
| cleartext the Verifier must read: `version` 1, `key_id` 2 (§6 step 2), `beacon` 16, `beacon_round` 5 (step 6) | −24 |
| **left for the sealed box** | **40** |
| X25519 sealed box overhead: ephemeral public key 32 + Poly1305 MAC 16 | **48** |

**Short by 8 bytes carrying no plaintext at all.** The four fields above cannot
be sealed — §6 needs them to select the epoch key and check freshness — so this
is not recoverable by moving content around.

Four routes, none of them free, none decided here:

- **Truncate the beacon to 8 bytes.** Frees exactly 8, which reaches 48 available
  against 48 of overhead — still nothing left for content. Insufficient alone.
- **Derive the sealed box's ephemeral X25519 key from `T`.** `T` is already in the
  frame, and Ed25519 keys map to X25519 birationally, so the 32-byte ephemeral
  public key stops needing its own space: overhead falls to the 16-byte MAC and
  the payload lands at 24 + 16 + 21 = 61 of 64. **This is the only route that
  fits comfortably**, and it is a signing-key-reuse-for-key-agreement composition
  with known sharp edges. It is a question for the gate, not a choice to make
  here.
- **Raise the padding tier.** D5 picked 224 precisely because 256 collides with
  the RFM95W single-packet ceiling. This means two packets on the narrowest
  transport.
- **Seal only where there is room.** Tier-dependent behaviour, and it reintroduces
  a length distinguisher of exactly the kind D5 and §8 work to remove.

Until one is chosen, **D12's role split stands and its wire encoding does not
exist.** Anything implementing the content layer is blocked; anything
implementing the genuineness layer is not.

---

## Still open

D4 fixes the scheme, not the protocol. `docs/TOKEN_PROTOCOL.md` takes up the
protocol: what the issuer blind-signs, how a token binds to a specific
attestation, one-time versus reusable tokens, the provisioning ceremony and
device-side blinding, the verifier's exact offline check, and the
unforgeability, unlinkability, and replay arguments. Public-key distribution
authenticity was on that list and is now D10; §10 of that document carries the
certificate format and the verifier's added check.

What remains open is tracked in `docs/ROADMAP.md`. **The next thing to decide is
whether the payload is sealed or in the clear** — D1 and D2 say the device seals
to the operator's backend key, `TOKEN_PROTOCOL.md` §5 and §6 read it in the
clear, and D3 is why those cannot both stand. It surfaced while working out
D11's anonymity set, which it also changes.
