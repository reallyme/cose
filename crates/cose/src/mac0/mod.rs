// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Detached COSE_Mac0 verification (RFC 9052 §§6.2–6.3).
//!
//! This profile requires a protected integer algorithm, an explicit allowlist,
//! and a key bound to that exact registration. Only HMAC registrations 4–7 are
//! supported. The payload slot must be null; external AAD is always explicit.

mod algorithm;
mod decode;
mod error;
mod key;
mod types;
mod validate_headers;
mod verify;

pub use algorithm::CoseMacAlgorithm;
pub use error::{CoseMac0Error, CoseMac0ErrorReason};
pub use key::CoseMacKey;
pub use types::{CoseMac0Limits, CoseMac0VerifyRequest, VerifiedDetachedCoseMac0};
pub use verify::cose_verify_mac0_detached;

#[cfg(test)]
mod tests;
