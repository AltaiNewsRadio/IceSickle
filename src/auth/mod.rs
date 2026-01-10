//! Authorization primitives (V1.1+)
//!
//! # Philosophy
//!
//! Authorization in IceSickle is **capability-based**, not **identity-based**.
//!
//! This means:
//! - No persistent device IDs
//! - No linkable credentials across attestations
//! - No "who are you?" — only "what can you do?"
//!
//! # Planned for V1.1+
//!
//! - **Unlinkable one-time tokens**: Verifier issues blinded tokens; device
//!   signs with token to prove authorization without revealing identity
//! - **Capability delegation**: Token holder can derive sub-tokens with
//!   restricted scope (e.g., "valid only for next 10 attestations")
//!
//! # Anti-patterns (DO NOT IMPLEMENT)
//!
//! The following are explicitly out of scope and should not be added:
//!
//! - Device serial numbers or unique identifiers
//! - Persistent keypairs for device authentication
//! - Certificates or PKI chains that link attestations
//! - Any mechanism that allows correlating attestations to a single device
//!
//! If you need device identity, IceSickle is the wrong tool. Consider a
//! traditional TPM or secure enclave solution instead.

// No implementation in V1 — this module exists to document intent
// and prevent well-meaning contributors from adding identity primitives.
