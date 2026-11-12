// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit ISO/IEC 18013-5:2021 COSE signature verification.
//!
//! Legacy wire registrations are resolved together with named key curves.
//! Applications authorize exact pairs, supply a trusted verifier, and retain
//! responsibility for ISO format preflight, certificate trust, and transcripts.
//! This profile does not broaden the modern Sign1 or COSE_Key defaults.
//!
//! ```
//! use reallyme_cose::iso18013::{
//!     cose_verify_iso18013_sign1, Iso18013CryptoVerifier, Iso18013Sign1Content,
//!     Iso18013Sign1Limits, Iso18013Sign1Request, Iso18013SignatureAlgorithm,
//!     Iso18013SignatureCurve, Iso18013SignatureSuite, VerifiedIso18013Sign1,
//! };
//! use reallyme_cose::CoseError;
//! use zeroize::Zeroizing;
//!
//! fn verify_device(
//!     encoded: &[u8],
//!     exact_device_authentication_bytes: &[u8],
//!     trusted_public_key: Zeroizing<Vec<u8>>,
//! ) -> Result<VerifiedIso18013Sign1, CoseError> {
//!     let suite = Iso18013SignatureSuite::new(
//!         Iso18013SignatureAlgorithm::Es384, Iso18013SignatureCurve::P384,
//!     )?;
//!     let verifier = Iso18013CryptoVerifier::new(suite, trusted_public_key)?;
//!     cose_verify_iso18013_sign1(Iso18013Sign1Request {
//!         encoded,
//!         content: Iso18013Sign1Content::DeviceDetached(exact_device_authentication_bytes),
//!         allowed_suites: &[suite],
//!         limits: Iso18013Sign1Limits::default(),
//!     }, &verifier)
//! }
//! ```

mod algorithm;
mod curve;
mod decode;
mod import_key;
mod provider;
mod suite;
mod types;
mod validate_headers;
mod verify;

pub use algorithm::{Iso18013EcdsaHash, Iso18013SignatureAlgorithm};
pub use curve::Iso18013SignatureCurve;
pub use provider::{Iso18013CryptoVerifier, Iso18013Verifier};
pub use suite::Iso18013SignatureSuite;
pub use types::{
    Iso18013Sign1Content, Iso18013Sign1Limits, Iso18013Sign1Request, VerifiedIso18013Sign1,
};
pub use verify::cose_verify_iso18013_sign1;

#[cfg(test)]
mod tests;
