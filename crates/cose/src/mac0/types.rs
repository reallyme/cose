// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::limits::{MAX_COSE_MAC0_BYTES, MAX_DETACHED_PAYLOAD_BYTES, MAX_MAC0_EXTERNAL_AAD_BYTES};

use super::CoseMacAlgorithm;

/// Caller byte limits, each capped by the crate's corresponding hard maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoseMac0Limits {
    /// Maximum encoded Mac0 length (hard maximum 65,536 bytes).
    pub max_encoded_bytes: usize,
    /// Maximum detached payload length (hard maximum 1,048,576 bytes).
    pub max_payload_bytes: usize,
    /// Maximum external AAD length (hard maximum 65,536 bytes).
    pub max_external_aad_bytes: usize,
}

impl Default for CoseMac0Limits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: MAX_COSE_MAC0_BYTES,
            max_payload_bytes: MAX_DETACHED_PAYLOAD_BYTES,
            max_external_aad_bytes: MAX_MAC0_EXTERNAL_AAD_BYTES,
        }
    }
}

/// Explicit inputs to detached MAC verification; an empty allowlist rejects all.
///
/// Borrowed input owners remain responsible for wiping PII. The verifier wipes
/// its decoded copies and MAC_structure, including on authentication failure.
pub struct CoseMac0VerifyRequest<'a> {
    /// Definite-length, preferred-width CBOR, optionally carrying outer tag 17.
    pub encoded: &'a [u8],
    /// Expected detached payload; the encoded payload slot must be null.
    pub detached_payload: &'a [u8],
    /// Application-supplied external AAD, including an explicit empty slice.
    pub external_aad: &'a [u8],
    /// Exact COSE registrations accepted by the application.
    pub allowed_algorithms: &'a [CoseMacAlgorithm],
    /// Application byte limits; values above hard maxima do not raise them.
    pub limits: CoseMac0Limits,
}

/// Authenticated Mac0 metadata, released only after successful verification.
///
/// Contains neither payload nor key material, and never exposes unprotected
/// headers. Metadata can contain identifiers, so it is wiped on drop and has
/// no formatting, cloning, or serialization implementations.
pub struct VerifiedDetachedCoseMac0 {
    pub(super) algorithm: CoseMacAlgorithm,
    pub(super) protected_bytes: Zeroizing<Vec<u8>>,
    pub(super) protected_kid: Option<Zeroizing<Vec<u8>>>,
}

impl VerifiedDetachedCoseMac0 {
    /// Return the authenticated, exact COSE registration.
    #[must_use]
    pub const fn algorithm(&self) -> CoseMacAlgorithm {
        self.algorithm
    }

    /// Return the authenticated protected header byte string without re-encoding.
    #[must_use]
    pub fn protected_header_bytes(&self) -> &[u8] {
        &self.protected_bytes
    }

    /// Return only an authenticated protected `kid`, if present.
    #[must_use]
    pub fn protected_key_id(&self) -> Option<&[u8]> {
        self.protected_kid.as_ref().map(|kid| kid.as_slice())
    }
}

impl ZeroizeOnDrop for VerifiedDetachedCoseMac0 {}
