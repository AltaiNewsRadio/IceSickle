# IceSickle Threat Model

This document explicitly states the security assumptions, threat boundaries, and non-goals of IceSickle.

## Security Goal

**Primary claim:** A valid IceSickle attestation proves that a physical event (button press) occurred at the reported time on *some* device running IceSickle firmware.

**What this does NOT prove:**
- Which specific device produced the attestation
- That the device has not been tampered with
- That the device firmware is unmodified
- That the timestamp corresponds to wall-clock time

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TRUSTED                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Hardware RNG (ESP32-S3 thermal noise)                      │    │
│  │  Ed25519 signing operation                                   │    │
│  │  Zeroization of private key material                        │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                       UNTRUSTED                                      │
│  - Physical access to device                                         │
│  - Network (disabled, but if enabled)                               │
│  - USB interface (for output)                                        │
│  - Wall-clock time synchronization                                   │
│  - Device identity / provenance                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Threat Analysis

### Threats MITIGATED

| Threat | Mitigation |
|--------|------------|
| **Key extraction via firmware dump** | Private keys are ephemeral, never written to flash |
| **Key extraction via RAM dump** | Private keys are zeroized immediately after signing |
| **Key reuse across attestations** | Fresh keypair generated per attestation |
| **PRNG weakness** | Hardware true RNG (thermal noise), not software PRNG |
| **Signature forgery** | Ed25519 with 128-bit security level |
| **Replay within power cycle** | Monotonic counter in payload |
| **Type confusion** | Rust's type system prevents mixing key types |
| **Use-after-zeroize** | `ZeroizeOnDrop` enforced at compile time |

### Threats NOT MITIGATED

| Threat | Why | Consequence |
|--------|-----|-------------|
| **Device cloning** | No unique device identity | Attacker can build identical device |
| **Firmware replacement** | No secure boot | Attacker can flash malicious firmware |
| **Physical button simulation** | Button is just a GPIO | Attacker with physical access can trigger |
| **Timing attacks on signing** | Not hardened | Theoretical side-channel (requires physical proximity) |
| **Glitching / fault injection** | No countermeasures | Physical attack can corrupt execution |
| **Power analysis** | Not hardened | Physical attack can leak key bits |
| **Replay across power cycles** | Counter resets | Same counter values can recur |
| **Clock manipulation** | No secure time source | Timestamp can be arbitrary |

### Explicit Non-Goals

1. **Device authentication**: IceSickle does not prove *which* device signed. Any device running the firmware can produce valid attestations.

2. **Tamper resistance**: Physical attacks are out of scope. An attacker with physical access can clone, modify, or simulate the device.

3. **Firmware integrity**: There is no secure boot chain. The firmware can be replaced.

4. **Time accuracy**: The timestamp is milliseconds since boot, not wall-clock time. It can be manipulated by resetting the device.

5. **Revocation**: There is no way to revoke an attestation. Once signed, it's valid forever.

## Hardware RNG Considerations

The ESP32-S3 hardware RNG sources entropy from:
- **RF subsystem noise** (when WiFi/BT enabled)
- **Thermal noise** (always available)

Since we disable WiFi/BT, entropy comes solely from thermal noise. Per Espressif documentation, this is still cryptographically secure, but:
- Entropy accumulation is slower (~1 byte/μs vs ~10 bytes/μs with RF)
- In extremely cold environments, thermal noise may be reduced

**Mitigation:** We generate only 32 bytes per attestation (Ed25519 seed), well within safe limits even at reduced entropy rates.

## Attack Scenarios

### Scenario 1: Remote Attacker (No Physical Access)

**Attacker goal:** Forge an attestation without pressing the button.

**Result:** Not possible. Attacker cannot:
- Extract private keys (ephemeral, zeroized)
- Predict future keys (hardware RNG)
- Replay old attestations with fresh timestamps (would need new signature)

### Scenario 2: Attacker with Physical Access

**Attacker goal:** Produce attestations without legitimate button presses.

**Result:** Trivially possible. Attacker can:
- Wire GPIO0 to arbitrary trigger
- Clone the entire device
- Replace firmware with always-signing version

**Conclusion:** IceSickle is NOT tamper-resistant. Physical access = full compromise.

### Scenario 3: Attacker with Network Access (if enabled)

**Attacker goal:** Exfiltrate keys or inject commands.

**Result:** Keys cannot be exfiltrated (zeroized before any network activity could occur). However, a network-enabled version would need careful analysis of:
- Timing of network vs. signing operations
- Potential for remote code execution

**Mitigation:** WiFi/BT disabled by default. Network support is out of scope for v1.

### Scenario 4: Compromised Verifier

**Attacker goal:** Extract private keys by manipulating verification process.

**Result:** Not possible. Verifier only receives public key and signature. Private key is zeroized before output occurs.

## Cryptographic Choices

| Choice | Rationale |
|--------|-----------|
| **Ed25519** | Fast, small signatures (64 bytes), no side-channel on signing, widely audited |
| **postcard serialization** | Deterministic, compact, no-std compatible |
| **32-byte seed** | Full entropy for Ed25519 key derivation |
| **Monotonic counter** | Prevents replay within power cycle without requiring RTC |

## Recommendations for Deployers

1. **Physical security**: IceSickle is only as trustworthy as its physical environment. Seal devices, use tamper-evident enclosures.

2. **Multiple attestations**: For high-security applications, require attestations from multiple independent devices.

3. **Time binding**: If wall-clock time matters, have the verifier provide a challenge/nonce to include in the payload.

4. **Firmware verification**: Consider enabling ESP32 secure boot and flash encryption for production deployments.

## Future Considerations

- **Secure boot integration**: Verify firmware before execution
- **Monotonic counter in flash**: Persist counter across power cycles
- **Challenge-response**: Allow verifier to provide nonce
- **Multi-event batching**: Sign multiple events atomically
