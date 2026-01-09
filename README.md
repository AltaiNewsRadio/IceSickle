# IceSickle
Cryptographically verifiable and identity-less HUMINT attestation device without network connectivity built on ESP32-S3 hardware

## Relay & Transport Model

IceSickle is intentionally **transport-agnostic**.

The device itself does not maintain network connectivity and does not embed
satellite, cellular, or IP networking stacks. Instead, it produces signed
attestation artifacts that can be relayed later using a variety of mechanisms.

Supported and planned relay models include:

- **Direct satellite uplink** (one-way, short-burst transmission)
- **Hybrid gateways** that batch, delay, mix, and forward attestations
- **Physical transfer** (USB, SD card, or other air-gapped methods)

This separation allows IceSickle to remain offline-first while supporting
global, censorship-resistant relay paths when required.

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
