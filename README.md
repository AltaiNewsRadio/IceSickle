# IceSickle
HUMINT cryptographically verifiable and identity-less attestation device without network connectivity built on ESP32-S3 hardware

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
