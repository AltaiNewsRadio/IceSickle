# IceSickle Design Document

## Overview

IceSickle implements a single primitive: **ephemeral-key event attestation**.

When a physical event occurs, the device:
1. Samples hardware entropy
2. Derives a fresh Ed25519 keypair
3. Signs a structured payload
4. Outputs the public key + signature
5. Zeroizes the private key

The key insight is that we can prove "an event occurred" without proving "which device saw it" — by making the key itself ephemeral and tied to the event.

## Why Ephemeral Keys?

Traditional attestation systems use persistent keys:
- Device has a long-lived identity key
- Key is stored in secure element / TPM / flash
- All attestations are linkable to the device

This creates a tradeoff:
- **Pro:** Verifier knows which device signed
- **Con:** Key extraction = permanent compromise
- **Con:** All past attestations become suspect if key leaks

IceSickle inverts this:
- **Pro:** Key extraction is impossible (key doesn't exist after signing)
- **Pro:** Compromise of one attestation doesn't affect others
- **Con:** No device identity (attestations are unlinkable)

This tradeoff is appropriate when:
- Physical presence matters more than device identity
- Verifier has other means to establish device provenance
- Key management complexity is unacceptable

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          main.rs                                  │
│  - Initializes peripherals                                       │
│  - Event loop: poll button → generate attestation → output       │
└──────────────────────────────────────────────────────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  button.rs   │     │ attestation  │     │  entropy.rs  │
│              │     │     .rs      │     │              │
│ GPIO input   │     │ Ephemeral    │     │ Hardware RNG │
│ Debouncing   │     │ key gen      │     │ esp_fill_    │
│              │     │ Signing      │     │ random()     │
│              │     │ Zeroization  │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
```

### Module Responsibilities

**`main.rs`**
- Peripheral initialization
- Event loop orchestration
- Output formatting

**`attestation.rs`**
- Payload structure definition
- Ephemeral key lifecycle (generate → sign → zeroize)
- Serialization (postcard)

**`entropy.rs`**
- Hardware RNG abstraction
- Implements `rand_core` traits for ed25519-dalek compatibility

**`button.rs`**
- GPIO input handling
- Software debouncing
- Press detection state machine

## Key Lifecycle

```
Time ──────────────────────────────────────────────────────────────►

     ┌─────────┐
     │ Button  │
     │ pressed │
     └────┬────┘
          │
          ▼
     ┌─────────────────────────────────────────────────────────┐
     │  EphemeralSigningKey::new()                             │
     │    - Read 32 bytes from HRNG                            │
     │    - Derive Ed25519 keypair                             │
     │    - Zeroize seed buffer                                │
     └─────────────────────────────────────────────────────────┘
          │
          │  Key exists ONLY in this scope
          ▼
     ┌─────────────────────────────────────────────────────────┐
     │  signing_key.sign(&payload)                             │
     └─────────────────────────────────────────────────────────┘
          │
          ▼
     ┌─────────────────────────────────────────────────────────┐
     │  Drop → ZeroizeOnDrop                                   │
     │    - Private key memory overwritten with zeros          │
     │    - Compiler cannot optimize away (zeroize crate)      │
     └─────────────────────────────────────────────────────────┘
          │
          │  Key no longer exists
          ▼
     ┌─────────────────────────────────────────────────────────┐
     │  Output: { public_key, signature }                      │
     └─────────────────────────────────────────────────────────┘
```

The private key exists for approximately:
- 32 bytes HRNG read: ~32 μs
- Ed25519 key derivation: ~50 μs
- Payload serialization: ~10 μs
- Ed25519 signing: ~100 μs
- Zeroization: ~1 μs

**Total: < 200 μs**

## Payload Format

```rust
struct AttestationPayload {
    version: u8,           // Protocol version
    event: AttestationEvent,
    timestamp_ms: u64,     // Milliseconds since boot
    counter: u32,          // Monotonic, resets on power cycle
}
```

Serialized with `postcard` (COBS + varint encoding):
- Deterministic (same input → same bytes)
- Compact (typically < 20 bytes)
- No allocation required

## Why Ed25519?

| Property | Benefit |
|----------|---------|
| **Deterministic signing** | Same message + key → same signature (no per-signature randomness needed) |
| **Fast signing** | ~100 μs on ESP32 |
| **Small signatures** | 64 bytes |
| **No side-channel on signing** | Signing uses only public operations after key derivation |
| **Widely implemented** | Easy to verify on any platform |

Alternatives considered:
- **ECDSA-P256**: Requires per-signature randomness (dangerous with weak RNG)
- **RSA**: Signatures too large (256+ bytes), slower signing
- **Ed448**: Overkill for this use case, less tooling support

## Why postcard?

| Property | Benefit |
|----------|---------|
| **no_std compatible** | Works on embedded |
| **Deterministic** | Required for signing |
| **Compact** | Smaller than JSON, protobuf |
| **Simple** | No schema files, just `#[derive(Serialize)]` |

The serialization format is:
- COBS framing (unambiguous message boundaries)
- Varint encoding for integers (compact)

## GPIO Handling

The button module uses polling rather than interrupts:

**Pros of polling:**
- Simpler code
- Deterministic timing
- No ISR context concerns

**Cons of polling:**
- Higher power consumption
- 10ms polling interval = potential 10ms latency

For a device that's always powered and latency isn't critical, polling is the right tradeoff. A battery-powered version would use GPIO wake from light sleep.

## Output Format

Currently: JSON-ish string over serial:
```json
{"event":"ButtonPress { gpio: 0 }","ts":12345,"pk":"...","sig":"..."}
```

Future options:
- USB HID (appear as keyboard, type attestation)
- BLE (broadcast attestation)
- QR code (display on attached screen)

The output module is intentionally minimal and easily replaceable.

## Configuration

ESP-IDF sdkconfig settings:

| Setting | Value | Rationale |
|---------|-------|-----------|
| `CONFIG_BT_ENABLED` | n | Reduce attack surface |
| `CONFIG_ESP_WIFI_ENABLED` | n | Reduce attack surface |
| `CONFIG_ESP_SYSTEM_MEMPROT_FEATURE` | y | Memory protection |
| `CONFIG_COMPILER_STACK_CHECK_MODE_STRONG` | y | Stack canaries |

## Future Extensions

### Challenge-Response
```rust
struct AttestationPayload {
    // ... existing fields ...
    challenge: Option<[u8; 32]>,  // Verifier-provided nonce
}
```

### Persistent Counter
```rust
// In NVS (flash)
fn increment_persistent_counter() -> u64 {
    let mut nvs = EspNvs::new(...)?;
    let count = nvs.get_u64("counter")?.unwrap_or(0) + 1;
    nvs.set_u64("counter", count)?;
    count
}
```

### Multiple Event Types
```rust
enum AttestationEvent {
    ButtonPress { gpio: u8 },
    SwitchToggle { gpio: u8, state: bool },
    TemperatureThreshold { celsius: i8 },
    AccelerometerShock { g_force: u8 },
}
```

### Batch Signing
```rust
struct BatchAttestation {
    events: Vec<AttestationEvent>,  // Multiple events
    signature: [u8; 64],            // Single signature over all
}
```
