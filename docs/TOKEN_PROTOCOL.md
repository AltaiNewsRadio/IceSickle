# Token protocol

Design note, not an implementation. It takes D4 in `docs/DECISIONS_V2_1.md` —
blind Schnorr on ed25519, publicly verifiable — and develops it into a protocol:
what the issuer signs, how a token binds to one attestation, what the ceremony
looks like, what the verifier checks, how it comes to trust the key it checks
against, and what the security argument rests on.

Nothing here is built. `crates/icesickle-core` is still v1 and still proves only
integrity.

Read `docs/VERIFIER_MODEL.md` first for why a token is needed at all.

---

## 1. The one idea

**The token is the attestation key.**

An `Attestation` already carries a 32-byte `public_key` — the ephemeral key that
signed the payload, discarded immediately after. v2 keeps that field and changes
where the key comes from: instead of being drawn from the TRNG at press time, it
is drawn at *provisioning* time and its public half is blind-signed by the
issuer.

So the token is not a separate credential travelling alongside the signature. The
token *is* the public key, and the issuer's blind signature over it is the only
new field on the wire.

That collapses the two things a verifier needs into one object:

| Question | Answered by |
|---|---|
| Was this key issued by the operator? | issuer's blind signature over `T` |
| Does the sender actually hold that key? | the payload signature under `T` |

The second question is what stops a bearer-token replay. An eavesdropper who
copies a whole attestation off the wire learns `T` and the issuer's signature
over it, but cannot produce a *different* payload under `T`, because the scalar
behind `T` never leaves the device.

## 2. Notation

- `B` — ed25519 basepoint, `L` — group order.
- Issuer keypair: secret scalar `x`, public `X = x*B`. One pair per epoch (D6).
- `k` — a token's secret scalar. `T = k*B` — the token, and the attestation's
  public key.
- `H` — SHA-512 reduced mod `L`, as in Ed25519's challenge.
- `DOM` — the domain separator `"IceSickle/token/v2"`.

`k` is not stored as a raw scalar. It is a 32-byte seed handed to
`ed25519_dalek::SigningKey::from_bytes`, exactly as `Attestation::create` does
today, so `T` is that key's `VerifyingKey` and the payload signature is an
ordinary Ed25519 signature. This matters: it means the verifier's second check is
stock Ed25519 verification with no custom code, and the device's signing path is
unchanged.

## 3. Issuance (blind Schnorr, one token)

Runs over USB or UART during provisioning, device attached, no radio.

| # | Party | Step |
|---|---|---|
| 1 | Device | Draw seed from the TRNG, derive `k`, compute `T = k*B`. Draw blinding scalars `a, b`. |
| 2 | Issuer | Draw session nonce `r`, send `R = r*B`. |
| 3 | Device | `R' = R + a*B + b*X`; `c' = H(DOM, R', X, T)`; `c = c' + b mod L`. Send `c`. |
| 4 | Issuer | `s = r + c*x mod L`. Send `s`. Close the session. |
| 5 | Device | `s' = s + a mod L`. Store `(seed, R', s')`. Erase `a, b, c`. |

The token is `sigma = (R', s')`, 64 bytes, and it verifies as a plain Schnorr
signature on message `T` under `X`:

```
s'*B == R' + c'*X        where c' = H(DOM, R', X, T)
```

Correctness:

```
s'*B      = (s + a)*B = (r + c*x + a)*B = R + a*B + c*X
R' + c'*X = R + a*B + b*X + c'*X        = R + a*B + (c' + b)*X = R + a*B + c*X
```

### What the issuer learns

`R`, `c`, `s`. That is all. **The issuer never sees `T`.** It signs a scalar
challenge, not a message, so it cannot record which token it issued to which
device — which is the whole point, and it is why unlinkability holds against the
issuer itself and not merely against a passive observer.

A consequence worth stating because it reads as a bug: the issuer cannot check
that it is signing a well-formed `T` at all. It might be signing garbage. That
costs the issuer nothing — a token whose `T` is not a real point, or whose scalar
the device does not know, is simply unusable. There is no need for a proof of
well-formedness, and adding one would break blindness.

### Blinding happens on the device

`a`, `b`, and the seed are generated on the ESP32-S3, not on the provisioning
host. The alternative — a laptop that blinds and flashes finished
`(seed, token)` blobs — is simpler and wrong: that host would know every `k` it
ever provisioned, and could forge attestations for every device it touched. A
compromised provisioning laptop should not be a universal forgery oracle.

This also keeps the entropy work load-bearing. `docs/NOSTD_ENTROPY_SPIKE.md`
enforces TRNG quality at the moment a key is drawn; under v2 that moment moves
from press time to provisioning time, but it is the same enforcement guarding the
same secret. **Press-time entropy no longer protects the attestation key** — this
is a real re-scoping of the spike, and §11 lists it as a follow-up.

Device-side blinding costs two scalar multiplications and two scalar additions
per token, using `curve25519-dalek`, already a transitive dependency of
`ed25519-dalek`. For a batch of 50 that is negligible; the round trips dominate.

## 4. Attestation (spending a token)

On a button press the device takes the next unspent `(seed, sigma)` from flash
and otherwise follows the existing path:

1. Build the v2 payload `P` (§5), zero-pad to 64 bytes.
2. `SigningKey::from_bytes(seed)`; `T = verifying_key()`; `sig_P = sign(P)`.
3. Zeroize the seed, mark the slot spent, erase it from flash.
4. Emit `T || sig_P || sigma || P`.

Step 3 must complete before the frame is handed to a transport. A token whose
seed survives its own use is a token that can be spent twice, and §8 explains why
that is worse than it sounds.

## 5. Wire format — exactly 224 bytes

D5 fixes the on-air frame at 224 bytes. Everything is fixed-width, so there are
no length prefixes and no framing overhead:

| Field | Bytes | Notes |
|---|---|---|
| `T` | 32 | token, and the attestation's Ed25519 public key |
| `sig_P` | 64 | Ed25519 signature over the padded payload, under `T` |
| `sigma = (R', s')` | 64 | issuer's blind Schnorr signature over `T` |
| `P` | 64 | payload, zero-padded (`ATTESTATION_PAYLOAD_LEN`) |
| **total** | **224** | |

`ATTESTATION_PAYLOAD_LEN` therefore goes **32 to 64**, not the 128 or 256 that
`VERIFIER_MODEL.md` §5 projected. That projection assumed the token was a field
*added* to the payload; making the token double as the public key removes 32
bytes, and the issuer signature moves outside `P`.

Payload contents, at postcard's varint worst case:

| Field | Worst case | Notes |
|---|---|---|
| `version` | 1 | `2` |
| `key_id` | 2 | selects the epoch issuer key `X` (D6) |
| `event` | 2 | tag + `gpio` |
| `timestamp_ms` | 10 | u64 varint; still milliseconds since boot |
| `counter` | 5 | u32 varint |
| `beacon` | 16 | truncated `H(beacon)`, freshness lower bound |
| `beacon_round` | 5 | u32 varint |
| `region` | 3 | coarse codebook code (D8) |
| `loc_precision` | 1 | reporter's granularity choice (D8) |
| **sum** | **45** | 19 bytes of slack in 64 |

The beacon is truncated to 16 bytes deliberately. 128 bits of preimage resistance
is ample for a freshness anchor, and the 19 bytes it buys are the difference
between a comfortable payload and one that fails closed the first time a field is
added. A full 32-byte beacon still fits, with 3 bytes of slack; that is not
enough room to be worth having.

The padding stays *inside* the signed region, as it is today, so it cannot be
stripped or rewritten without invalidating `sig_P`.

## 6. Verification — the exact offline check

A Verifier holds the pinned operator root `K_op`, the map `key_id -> X` it has
authenticated against that root (§10), and the epoch's beacon values. No network,
no issuer callback (D3).

1. **Parse.** Split the 224-byte frame into `T || sig_P || sigma || P`. Wrong
   length, reject.
2. **Select the key.** Decode `P` far enough to read `version` and `key_id`.
   Unknown `key_id`, or an epoch the operator has retired, reject.
3. **Validate `T`.** Canonical 32-byte encoding, on the curve, not the identity,
   not of small order. `ed25519-dalek`'s strict verification covers the cases
   that matter here; the check is called out separately because §7's argument
   depends on it.
4. **Token genuine.** `c' = H(DOM, R', X, T)`; accept iff `s'*B == R' + c'*X`.
   Failure means the key was not issued by this operator.
5. **Holder present.** Verify `sig_P` over all 64 bytes of `P` under `T`, strict
   Ed25519. Failure means whoever assembled this frame does not hold the token.
6. **Freshness lower bound.** Look up `beacon_round`, hash the known beacon
   value, compare against `P.beacon`. A match means the attestation was created
   no earlier than that round's publication time `t_lo`.
7. **Dedup.** Hand `T` to the Sink as the spend identifier (§8).
8. **Freshness upper bound.** The Sink counter-signs with its ingest time `t_hi`.

Steps 4 and 5 are the pair. Either alone proves nothing useful: step 4 without
step 5 accepts anyone who copied a token off the wire; step 5 without step 4 is
v1, which accepts anyone at all.

What a passing frame licenses, and no more:

> A holder of an operator-issued one-time token asserted this event between
> `t_lo` and `t_hi`, and the payload is unaltered.

`VERIFIER_MODEL.md` §6 still applies unchanged: this does not prove a human
pressed a button, and no offline identity-less device can.

## 7. Security argument

Sketches with named assumptions, not proofs. They should be reviewed by someone
who does this for a living before any of it is built.

### Unforgeability

Rests on **one-more-discrete-log** for Schnorr blind signatures in the random
oracle model. An adversary who completes `n` issuance sessions cannot produce
`n+1` valid `(T, sigma)` pairs.

The ROS attack (Benhamouda, Lepoint, Loss, Orru, Raykova, EUROCRYPT 2021) is the
live objection. It breaks blind Schnorr in polynomial time, but it needs on the
order of `log2(L)`, about 253, **concurrently open** signing sessions to do it.
§3 step 4 closes each session before the next opens, so the issuer has exactly
one open session at all times, and the attack has no purchase.

That property must be enforced by the issuer, not assumed of it: the issuer holds
at most one `(r, R)` at a time and refuses a new `R` request until the
outstanding `c` arrives or the session is abandoned. This is a small state
machine and it is the single most security-critical part of the ceremony.

**If sequential issuance ever becomes impossible — a parallel provisioning rig,
say — the fallback is clause blind Schnorr (Fuchsbauer, Plouviez, Seurin, 2020),
which is ROS-resistant at roughly twice the issuance cost and the same 64-byte
signature.** Reaching for it later is a protocol change, not a parameter change,
so the choice is worth making deliberately now rather than discovering it under
schedule pressure.

### Unlinkability

`a` and `b` are uniform and independent, so `(R', s')` is uniformly distributed
over all valid signatures on `T` regardless of the session transcript
`(R, c, s)`. This is the standard perfect-blindness argument for Schnorr blind
signatures, and it holds against the issuer, who is the strongest relevant
adversary here.

Combined with the issuer never seeing `T` (§3), an operator holding every
issuance transcript still cannot say which device produced a given attestation.
That is what keeps the scheme inside `crates/icesickle-core/src/auth.rs`: a token
is a capability,
used once and destroyed, not an identifier.

The anonymity set is one epoch's batch. Small batches (§9) sharpen the seizure
picture and blunt this; the two pull in opposite directions and the balance is an
operator's call, not a default.

### Replay

Within one Sink, `T` is the exact spend identifier: it is unique per token and
appears verbatim in every frame that spends it. This is a better dedup key than
the `nonce + epoch + timestamp` tuple D7 assumed, because it cannot collide and
cannot be forged into a fresh-looking value.

Across Sinks, D7 stands: offline verifiers share no state, so the same frame can
be accepted by two nodes. Accepted, and low-harm — a replay re-reports an event
that did happen.

The consequence that is *not* low-harm: two attestations spending the same `T`
are **linkable to each other**, because they carry the same 32 bytes. That is the
real reason tokens must be strictly one-time, and it is a stronger reason than
double-spend accounting. A device that reuses a token has not just spent twice,
it has told an observer that two events came from one device.

## 8. One-time only, and what that costs

Tokens are one-time. §7 gives the reason: reuse is a linkability leak, not merely
an accounting problem.

**Spend must be atomic against power loss.** The window between signing and
erasing the seed is the whole vulnerability. The flash slot should be marked
spent *before* the frame reaches a transport, and a slot found in an ambiguous
state on boot must be treated as spent and erased, never retried. Losing an
attestation to a badly timed power cut is the correct trade against emitting a
duplicate `T`.

**Exhaustion.** `VERIFIER_MODEL.md` §4 says the layers degrade independently, so
running out of tokens should fail *open* to an untokened attestation that still
carries integrity and time bounds, rather than refusing to attest.

That creates a distinguisher to handle: an untokened frame must still be 224
bytes, or the transport leaks "this device is out of tokens" by length alone.
Fill the `sigma` slot with **random bytes**, not zeros. To a passive observer
without `X`, random bytes are indistinguishable from a real blind signature; a
verifier learns the attestation is untokened only by failing step 4. Zeros would
announce it to anyone watching.

Whether fail-open is right at all is an operator decision, and a deployment where
an untokened attestation is worse than none should be able to configure
fail-closed.

## 9. Seizure

A device holds `n` unspent `(seed, sigma)` pairs. Seizing it yields `n` forgeable
attestations that verify perfectly. `VERIFIER_MODEL.md` §3.1 already names this
as the scheme's sharpest weakness; the protocol does not fix it, and nothing at
this layer can.

What is available:

- **Small batches.** Directly caps the loss. Costs re-provisioning frequency, and
  shrinks the anonymity set (§7).
- **Epoch rotation** (D6). Rotating `X` invalidates every unspent token from that
  epoch at once. This is the only revocation that exists, and it is
  batch-granular by design.
- **Passphrase-wrapped token storage.** Seeds stored encrypted under a key
  derived from a reporter-supplied secret, so a seized device without coercion
  yields nothing. This buys the most and costs a UX the design has not yet
  decided it wants — named here as an option, not assumed.

Batch size is an operational judgement. It should be set against a specific
threat picture, not defaulted.

## 10. Issuer key distribution

Settled as D10. The rationale, the costs and the small-deployment alternative are
there; this is the format and the check.

A verifier is provisioned once with a long-lived **operator root** public key
`K_op`, pinned. Epoch keys then arrive as certificates it can authenticate for
itself:

| Field | Bytes | Notes |
|---|---|---|
| `key_id` | 2 | matches the payload field (§5) |
| `X` | 32 | the epoch's issuer public key |
| `valid_from` | 8 | unix seconds |
| `valid_until` | 8 | unix seconds; see D10 on why expiry is load-bearing |
| `sig` | 64 | Ed25519 under `K_op` over `DOM_CERT \|\| the 50 bytes above` |
| **total** | **114** | |

`DOM_CERT` is the domain separator `"IceSickle/epoch-cert/v2"`. It is prefixed to
the signed input but is **not** transmitted — both sides know it — so a
certificate is 114 bytes on the wire while the signature covers 50 bytes of
fields plus the separator. Without it, an epoch certificate could in principle be
reinterpreted as some other signature this protocol produces.

Certificates never appear on the wire. The frame stays 224 bytes; they reach
verifiers out of band, over any channel, because they carry their own proof.

### The added check

§6 step 2 selects the key. It gains a precondition:

> **2. Select the key.** Decode `P` far enough to read `version` and `key_id`.
> Look up `key_id` in the verifier's key map. A `key_id` with no entry, or an
> epoch the operator has retired, rejects.
>
> An entry may only enter that map by one of two routes: pinned directly at
> verifier provisioning, or installed from a certificate whose `sig` verifies
> under the pinned `K_op` **and** whose `[valid_from, valid_until]` contains the
> verifier's current time. Nothing else may write to it. A certificate that
> fails either test is discarded, not cached for retry.

Everything downstream is unchanged: step 4 still checks `s'*B == R' + c'*X`, and
it now does so against an `X` the verifier can trace to something it was handed
in person.

### What this does not establish

The certificate proves the operator issued that epoch key. It says nothing about
*when the attestation was made* — that is still steps 6 and 8, the beacon and the
Sink's ingest time. A valid certificate on a genuine token does not make the
timestamp trustworthy, and the two are easy to conflate when reading step 2 as a
"validity" check.

## 11. Open items

- **Epoch length.** Still open from `VERIFIER_MODEL.md`, and now load-bearing
  three times over: it sets the freshness/anonymity knob, the revocation
  granularity (D6), and — since D10 — the damage window of a leaked epoch key,
  because an offline verifier may never receive a revocation and expiry is the
  only bound that reaches it. **This is the next decision.**
- **Beacon source.** Still open. An external beacon (drand) is independently
  verifiable but imports a trust assumption; a verifier-signed epoch token keeps
  it in-house and makes the operator the sole authority on time.
- **Entropy re-scoping.** `docs/NOSTD_ENTROPY_SPIKE.md` guards press-time key
  generation. Under §3 the guarded moment moves to provisioning. The enforcement
  is still needed and still guards the same secret, but the doc and the spike
  both describe the wrong moment and should be updated.
- **Cryptographic review.** §7 is a sketch by a non-specialist. The ROS bound,
  the blindness argument, and the decision to reuse an Ed25519 verifying key as a
  blind-signed message all want an expert eye before implementation.
