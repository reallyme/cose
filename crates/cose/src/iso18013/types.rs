// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::limits::{MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES};

use super::Iso18013SignatureSuite;

/// Role-specific ISO authentication content; external AAD is always empty.
pub enum Iso18013Sign1Content<'a> {
    /// Issuer authentication requires an attached payload.
    IssuerAttached,
    /// Device authentication requires a null payload slot and these exact bytes.
    DeviceDetached(&'a [u8]),
    /// Reader authentication requires a null payload slot and these exact bytes.
    ReaderDetached(&'a [u8]),
}

/// Application byte limits capped by the crate's hard Sign1 and payload maxima.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Iso18013Sign1Limits {
    /// Maximum encoded COSE_Sign1 bytes, capped at 65,536.
    pub max_encoded_bytes: usize,
    /// Maximum attached or detached payload bytes, capped at 1,048,576.
    pub max_payload_bytes: usize,
}

impl Default for Iso18013Sign1Limits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: MAX_COSE_SIGN1_BYTES,
            max_payload_bytes: MAX_DETACHED_PAYLOAD_BYTES,
        }
    }
}

/// Inputs for explicitly authorized ISO/IEC 18013-5:2021 Sign1 verification.
///
/// Original input owners remain responsible for clearing sensitive data. The
/// verifier wipes all owned decoding and authentication-structure copies.
pub struct Iso18013Sign1Request<'a> {
    /// Bounded, untagged COSE_Sign1 bytes with the received protected byte string.
    pub encoded: &'a [u8],
    /// Issuer, device, or reader content convention.
    pub content: Iso18013Sign1Content<'a>,
    /// Exact authorized registration/curve pairs. Empty always rejects.
    pub allowed_suites: &'a [Iso18013SignatureSuite],
    /// Application limits; larger values cannot raise the hard maxima.
    pub limits: Iso18013Sign1Limits,
}

/// Authenticated ISO Sign1 metadata and optional attached issuer payload.
///
/// Contains no unprotected header hints or certificate-trust assertions. All
/// owned identifier, header, and payload bytes wipe on drop. No formatting,
/// cloning, or serialization implementations expose identifying content.
pub struct VerifiedIso18013Sign1 {
    pub(super) suite: Iso18013SignatureSuite,
    pub(super) protected: Zeroizing<Vec<u8>>,
    pub(super) protected_kid: Option<Zeroizing<Vec<u8>>>,
    pub(super) payload: Option<Zeroizing<Vec<u8>>>,
}

impl VerifiedIso18013Sign1 {
    /// Return the exact authenticated registration and validated key curve.
    #[must_use]
    pub const fn suite(&self) -> Iso18013SignatureSuite {
        self.suite
    }

    /// Return the protected header bytes exactly as authenticated.
    #[must_use]
    pub fn protected_header_bytes(&self) -> &[u8] {
        &self.protected
    }

    /// Return only an authenticated protected key identifier, if present.
    #[must_use]
    pub fn protected_key_id(&self) -> Option<&[u8]> {
        self.protected_kid.as_ref().map(|kid| kid.as_slice())
    }

    /// Return the authenticated attached issuer payload; detached roles return none.
    #[must_use]
    pub fn attached_payload(&self) -> Option<&[u8]> {
        self.payload.as_ref().map(|payload| payload.as_slice())
    }
}

impl ZeroizeOnDrop for VerifiedIso18013Sign1 {}
