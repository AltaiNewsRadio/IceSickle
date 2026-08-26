//! Authorization primitives.
//!
//! There is no code here, and that is the point. This module exists to record
//! a constraint and to sit where someone adding the wrong thing would have to
//! read it first.
//!
//! It used to live in the esp-idf prototype. When that crate was retired the
//! policy moved here rather than into `docs/`, because it binds every firmware
//! that links this crate, and a rule in the source tree is harder to walk past
//! than one in a document.
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
//!
//! # What this permits, and what v2 does with it
//!
//! The original note listed "unlinkable one-time tokens" as a V1.1+ plan. That
//! plan now has a protocol: `docs/TOKEN_PROTOCOL.md` blind-signs an
//! attestation's own public key, so a verifier learns the key was issued by the
//! operator without the issuer ever seeing it.
//!
//! It is worth being precise about why that does not violate the rule above. A
//! token is spent once and destroyed, and the issuer holds no transcript that
//! links it to a device — so it answers "what can you do?" and nothing else.
//! The moment a token were reused, two attestations would carry the same 32
//! bytes and become linkable to each other, which is why the protocol makes
//! one-time use a hard requirement rather than an accounting convenience.
//!
//! Capability delegation — deriving sub-tokens with restricted scope, such as
//! "valid for the next 10 attestations" — remains unbuilt and unspecified.
