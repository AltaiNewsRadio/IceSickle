
# IceSickle 🧊

**Hardware-assisted, ephemeral-key attestation device**

IceSickle is a minimal embedded attestation primitive: when a physical event occurs (e.g., a button press), it produces a cryptographically signed attestation using an ephemeral key that is *never reused or persisted*.

## What IceSickle Is (and Is Not)

IceSickle is **not** a TPM, secure enclave, or remote attestation system in the traditional sense. It does not attempt to prove device identity, firmware integrity to a remote verifier, or continuous trust over time.

Instead, IceSickle provides a **hardware-assisted, event-driven signing primitive**:

| Traditional Attestation | IceSickle |
|------------------------|-----------|
| Persistent device identity | No identity persistence |
| Proves firmware integrity | Proves a payload was signed and is unaltered |
| Long-lived keys in secure storage | Ephemeral keys, zeroized after use |
| Remote verifier protocol | Simple signed payload output |

## How It Works

```
┌──────────────────────────────────────────────────────────────┐
│  Physical Event (button press)                               │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  1. Generate ephemeral Ed25519 keypair from hardware RNG     │
│  2. Construct payload: { event, coarse_time, local_counter } │
│  3. Sign payload with ephemeral private key                  │
│  4. Output: { public_key, signature, payload }               │
│  5. Zeroize private key (immediately after signing)          │
└──────────────────────────────────────────────────────────────┘
```

The private key exists only for the duration of the signing operation. It is never written to flash or transmitted, and is zeroized immediately after use.

## Use Cases

> **These describe the intended design, not what the current firmware
> delivers.** Today an attestation proves only that its payload is unaltered
> since signing: a fresh key signing a self-authored payload is reproducible by
> anyone, with no device and no event. The authorization and time-bounding these
> use cases rest on are specified in
> [docs/VERIFIER_MODEL.md](docs/VERIFIER_MODEL.md) and are not built yet.

- **Air-gapped signing**: produce one-time signatures with no network exposure.
  Works today.
- **Physical presence claim**: assert a button was pressed. Note *claim* — the
  device can show its firmware signed the assertion, not that a human caused it.
  No offline device can prove the latter.
- **Audit trail anchoring**: signed records ordered within a single power cycle.
  Ordering does not survive a reboot, and nothing anchors it to wall-clock time
  until the verifier model lands.
- **Dead man's switch**: proof of continued physical interaction. Depends
  entirely on the freshness bounds in the verifier model — without them there is
  no verifiable notion of "recently", which is the whole mechanism.

## Hardware

**Reference platform:** ESP32-S3 (16MB Flash / 8MB PSRAM)

Chosen for:
- Hardware RNG. True randomness is *conditional*: the ESP32-S3 RNG requires
  either the RF subsystem or an ADC entropy source to be live. IceSickle keeps
  radios off by design, so the SAR-ADC path has to be enabled explicitly — see
  [docs/NOSTD_ENTROPY_SPIKE.md](docs/NOSTD_ENTROPY_SPIKE.md)
- Availability and low cost
- Mature Rust toolchain (`esp-rs`)
- No network connectivity required (WiFi/BT disabled by default)

The design is intentionally portable; only `entropy.rs` and `button.rs` have platform-specific code.

## Relay & Transport Model

IceSickle is intentionally **offline-first and transport-agnostic**.

The device itself does not maintain network connectivity and does not implement
IP, satellite, cellular, or radio protocols. Instead, it produces signed
attestation artifacts that can be relayed later using external systems.

Planned and supported relay mechanisms include:

- One-way satellite uplink (short-burst transmission)
- Hybrid gateways that batch, delay, mix, and forward attestations
- Physical transfer (USB, SD card, air-gapped workflows)

This separation ensures that evidence production remains decoupled from
transport, identity, and network policy.

### Hybrid Relay Model (Conceptual Comparison to Tor)

IceSickle’s hybrid relay system is conceptually similar to Tor, but operates at a
different layer and solves a different problem.

Tor is designed to protect **network anonymity** during live communication by
obscuring routing paths, IP addresses, and timing correlations.

IceSickle’s hybrid relays protect **epistemic anonymity** by obscuring the link
between an attestation and the device that produced it. Relays batch, delay,
reorder, and forward already-signed attestations without preserving origin
metadata.

Unlike Tor, IceSickle does not perform onion routing or interactive traffic
relay. The goal is not anonymous communication, but **unlinkable evidence
production** under adversarial observation.

## Building

### Prerequisites

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install ESP32 Rust toolchain
cargo install espup
espup install

# Install flash tool
cargo install espflash
```

### Build and Flash

```bash
# Build
cargo build --release

# Flash and monitor (connect ESP32-S3 via USB)
cargo run --release
```

### Output

Press the BOOT button (GPIO0) to generate an attestation:

```json
{"event":"ButtonPress { gpio: 0 }","ts":12345,"pk":"a1b2c3...","sig":"d4e5f6..."}
```

## Project Structure

```
icesickle/
├── src/
│   ├── main.rs          # Entry point, event loop
│   ├── attestation.rs   # Core signing logic, ephemeral keys
│   ├── auth/            # Authorization primitives (V1.1+)
│   │   └── mod.rs       # Capability-based, not identity-based
│   ├── button.rs        # GPIO event detection
│   ├── cooldown.rs      # Physical rate limiting
│   └── entropy.rs       # Hardware RNG wrapper
├── spikes/
│   └── nostd-entropy/   # no_std esp-hal spike: entropy-enforced signing
├── docs/
│   ├── ARCHITECTURE.md  # Architecture rationale
│   ├── VERIFIER_MODEL.md      # What an attestation does and does not prove
│   └── NOSTD_ENTROPY_SPIKE.md # Why no_std, radio silence, emission discipline
├── THREAT_MODEL.md      # Explicit threat assumptions
├── SECURITY.md          # Vulnerability reporting
├── LICENSE              # Apache-2.0
└── README.md
```

## Security Properties

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed analysis.

**Guarantees:**
- Private keys never persist (zeroized immediately after signing)
- Each attestation uses a fresh keypair (no key reuse)
- Payload includes a monotonic counter for replay detection within a single power cycle

**Conditional, not yet guaranteed:**
- *True hardware entropy.* The RNG is only a true RNG while the RF subsystem or
  an ADC entropy source is live. With radios off, that means the SAR-ADC path,
  which is brought up explicitly in `spikes/nostd-entropy/` but **not** in the
  esp-idf crate at the repo root. Unvalidated on hardware either way.

**Non-goals:**
- Device identity or authentication
- Firmware integrity verification
- Protection against physical attacks on the device itself
- Secure boot chain verification
- Proof to a third party that a physical event actually occurred — see
  [docs/VERIFIER_MODEL.md](docs/VERIFIER_MODEL.md) for why this is out of reach
  for an identity-less offline device, and what replaces it

## Verifying Attestations

```rust
use ed25519_dalek::{Signature, VerifyingKey, Verifier};

let public_key = VerifyingKey::from_bytes(&pk_bytes)?;
let signature = Signature::from_bytes(&sig_bytes);
let payload = /* reconstruct payload */;

public_key.verify(&payload, &signature)?;
```

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contributing

Contributions welcome. Please read [THREAT_MODEL.md](THREAT_MODEL.md) first to understand the security boundaries.