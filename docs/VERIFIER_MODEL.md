# Verifier model

Design note, not an implementation. It states what an IceSickle attestation
proves today (very little), why the fix named in `ARCHITECTURE.md` is unavailable
to us, and what is left once the locked constraints are applied.

Decisions that need a human are collected in [Open decisions](#open-decisions).

## 1. What an attestation proves today

An attestation is `(public_key, signature, payload)` where the key was generated
moments before signing and discarded immediately after.

It proves exactly one thing: **the payload has not been altered since it was
signed.** That is a real property and worth keeping. It is also nearly the
weakest useful property in the catalogue, because the verifier has no reason to
care about a key it has never seen before and will never see again.

Concretely, anyone can produce an attestation that passes every check a verifier
can currently perform:

```rust
// No device involved. No physical event. Verifies perfectly.
let sk = SigningKey::generate(&mut OsRng);
let payload = AttestationPayload { version: 1, event, timestamp_ms: 4_2000, counter: 7 };
let mut buf = [0u8; ATTESTATION_PAYLOAD_LEN];
postcard::to_slice(&payload, &mut buf).unwrap();
let attestation = (sk.verifying_key().to_bytes(), sk.sign(&buf).to_bytes(), buf);
```

Nothing distinguishes that from a genuine one. The ephemeral-key design is
what makes this so: by removing device identity we removed the only thing that
made a signature attributable, and we did not put anything in its place.

`ARCHITECTURE.md` is honest that a verifier needs "other means to establish
device provenance". `README.md` is not: **dead man's switch** and **audit trail
anchoring** both presuppose that an attestation is evidence of something, and
today it is not. Those claims should be softened or removed regardless of which
design below we adopt.

Also worth naming: `timestamp_ms` is milliseconds since boot. Across a power
cycle it is meaningless, and to a third party it is meaningless from the start,
because there is no anchor for what "boot" was.

## 2. Why challenge-response is unavailable

The textbook fix is a verifier-supplied nonce: the verifier sends an
unpredictable challenge, the device signs it, and the signature proves the
attestation was created after the challenge was issued and specifically for that
verifier.

**This is foreclosed by a locked decision.** Attestations are create-now /
transmit-later: signing happens offline, with the RF subsystem off, possibly long
before any verifier is reachable. There is no interaction at signing time, so
there is no channel for a challenge to arrive on.

This is a genuine cost of the operating model, not an oversight, and it means the
solution has to supply the same properties *non-interactively*.

## 3. Decomposing what a verifier actually wants

"Prove the event happened" is not one property. It is several, and they have
very different prices under our constraints:

| # | Property | Available? | Mechanism |
|---|---|---|---|
| 1 | **Integrity** — payload unaltered since signing | yes, today | ephemeral-key signature |
| 2 | **Authorization** — signer held a scarce credential | yes | blind-signed one-time tokens |
| 3 | **Freshness lower bound** — created no earlier than `t` | yes | preloaded public randomness beacon |
| 4 | **Freshness upper bound** — existed no later than `T` | yes | co-signature at ingest |
| — | **Physical causation** — a human actually pressed the button | **no** | requires device integrity, which requires device identity |

Properties 2–4 are all obtainable without a radio at signing time. The last row
is not obtainable at all, at any price, and §6 deals with why.

### 3.1 Authorization: blind-signed one-time tokens

`crates/icesickle-core/src/auth.rs` already names this as the V1.1+ plan, so this
is developing an
existing decision rather than proposing a new one:

> **Unlinkable one-time tokens**: Verifier issues blinded tokens; device signs
> with token to prove authorization without revealing identity

The verifier blind-signs a batch of tokens during provisioning. The device spends
one per attestation and includes the unblinded token plus the verifier's
signature over it. The verifier can confirm it issued that token without learning
which device received it, and a double-spend is detectable because tokens are
one-time.

This is what converts a self-signed blob into evidence: **a forger without a
token cannot produce an accepted attestation.** Scarcity is the whole mechanism.

Costs, stated plainly:

- Requires a provisioning ceremony before deployment.
- The token supply is finite. Running out means no more attestations.
- **A seized device gives up its unspent tokens**, and the adversary can then
  forge attestations that verify. This is the sharpest weakness of the scheme and
  it is a HUMINT-relevant one. Partial mitigations: small batches, epoch-scoped
  tokens that expire (see below), and whatever the disguise/duress design ends up
  providing. None of them eliminate it.

### 3.2 Freshness lower bound: a preloaded beacon

Include in the signed payload a recent value from a public randomness beacon —
drand, the NIST beacon, or a verifier-signed epoch token.

Because the beacon value was unpredictable before it was published at time `t`,
an attestation containing it **cannot have been created before `t`**. That is a
verifiable lower bound on age, obtained with no network at signing time: the
device ingests the beacon while it still has a channel, then goes dark.

The privacy consequence needs to be stated honestly. Every attestation carrying
beacon value `B` is linkable to that epoch, and to every other attestation
carrying `B`. But **`B` is shared by every device in the epoch**, so this is an
anonymity set, not a device identifier — it does not violate `auth/mod.rs`. The
tradeoff is direct and tunable:

- **Shorter epochs** → tighter time bound, smaller anonymity set.
- **Longer epochs** → looser bound, larger crowd to hide in.

That knob should be set deliberately, by someone who knows the operational
picture, not defaulted.

### 3.3 Freshness upper bound: co-signature at ingest

Whoever first receives the attestation — relay, courier laptop, verifier —
counter-signs it with their own timestamp `T`. That proves the artifact existed
by `T`. It says nothing about the device and requires nothing from it.

Combined with the beacon, a verifier gets a real interval: **this attestation was
created between `t` and `T`.** For a create-now/transmit-later device with no
clock, that is about as good as time provenance gets.

## 4. Recommended shape

Layer 1 (have) + 2 + 3 + 4, yielding the claim:

> An entity holding a verifier-issued one-time token created this attestation
> between `t` and `T`, and the payload is unaltered.

That is a defensible evidentiary statement, it is the strongest one reachable
under the locked constraints, and every layer is non-interactive at signing time.

Each layer also degrades independently, which is worth having: an attestation
with no token is still integrity-checked and still time-bounded; it just carries
no authorization weight.

## 5. Impact on the payload format

Not free, and it collides with the spike's fixed-length padding.

`ATTESTATION_PAYLOAD_LEN` is currently **32 bytes**, against a worst case of 18.
A v2 payload adds roughly:

| Field | Size |
|---|---|
| beacon value or `H(beacon)` | 32 bytes |
| epoch / round identifier | ~8 bytes |
| token + issuer signature | 48–96 bytes, scheme-dependent |

That is 88–136 bytes on top of 18, so the fixed length would need to grow to
**128 or 256**. Since every attestation is padded to that length regardless of
content, this is a flat cost on every transmission — which matters a great deal
for a constrained opt-in transport tier and should be sized against whatever the
narrowest planned tier can carry, not against convenience.

> **Superseded.** Both numbers above are wrong, in opposite directions. The
> "48–96 bytes, scheme-dependent" row undercounts blind RSA badly — at RSA-2048
> the issuer signature alone is 256 bytes. And the whole estimate assumed the
> token is a field *added* to the payload. It is not: under
> `docs/TOKEN_PROTOCOL.md` the token *is* the attestation's public key, which the
> wire format already carried, so the only new field is the issuer's 64-byte
> signature and it sits outside the padded payload. The settled numbers are
> `ATTESTATION_PAYLOAD_LEN = 64` and a 224-byte frame — 224 rather than 256
> because a 256-byte tier does not fit one RFM95W packet (D5).

The v1 → v2 bump is what the `version` field exists for; v1 attestations remain
verifiable as integrity-only.

## 6. What stays unprovable, permanently

**No offline device can prove a human physically pressed a button.** It can prove
its firmware signed a claim that one was. Distinguishing those requires proving
the firmware was unmodified, which requires a device identity key and a remote
attestation protocol — explicitly forbidden by `crates/icesickle-core/src/auth.rs`,
and rightly so,
because that key is exactly the linkable identifier the whole design exists to
avoid.

So the honest ceiling is:

> **An authorized holder asserted that an event occurred, within a known time
> window, and the assertion is unaltered.**

Not "the event occurred". Every downstream claim in the README should be measured
against that sentence. This is not a gap to be closed later; it is the shape of
what an identity-less offline attestation device can be, and the design is
better for saying so out loud.

## Open decisions

Need a human, in rough dependency order:

1. ~~**Token scheme.**~~ **Settled** as blind Schnorr on ed25519 — see D4 in
   `docs/DECISIONS_V2_1.md`, developed into a protocol in
   `docs/TOKEN_PROTOCOL.md`. The deciding argument was not signature size but
   public verifiability: verification is distributed to offline field nodes, and
   a VOPRF's verify key is its issue key, so distributing the checker would
   distribute forgery power.
2. ~~**Epoch length.**~~ **Settled** as D11, which splits it into two periods
   the wire format already had: a 7-day **beacon round** and a 28-day **key
   epoch**. §3.2's framing below is superseded on one point — the anonymity set
   is the intersection of every readable payload field, not one epoch's batch,
   so `region` (D8) constrains it too. D11 also names the floor: below roughly a
   few dozen devices attesting per round there is no crowd, and no period
   repairs it.
3. **Beacon source.** An external public beacon (drand) is independently
   verifiable by anyone but needs the verifier to trust that beacon; a
   verifier-signed epoch token keeps it in-house but makes the verifier the
   single source of truth about time.
4. **Seizure model.** How many unspent tokens is an acceptable loss if a device
   is taken? This sets batch size, and it is an operational judgement, not a
   technical one.
5. **README claims.** Whether to soften "dead man's switch" and "audit trail
   anchoring" now, or after v2 lands. They over-claim under either design.

## Status

No code. Nothing here is implemented and nothing in `firmware/nostd/` depends
on it. The payload is still v1 and still proves only integrity.
