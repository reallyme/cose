// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::MacAlgorithm;
use reallyme_crypto::hmac::{
    HMAC_SHA256_TAG_LENGTH, HMAC_SHA384_TAG_LENGTH, HMAC_SHA512_TAG_LENGTH,
};

use super::CoseMac0Error;

const HMAC_SHA256_64_TAG_BYTES: usize = 8;

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::CoseMacAlgorithm;

impl CoseMacAlgorithm {
    /// Exact registered MAC identifier.
    #[must_use]
    pub const fn cose_id(self) -> i64 {
        self.identifier()
    }
    pub(super) fn from_cose_id(id: i64) -> Result<Self, CoseMac0Error> {
        Self::from_identifier(id)
    }

    /// Return the only accepted wire tag length in bytes.
    #[must_use]
    pub const fn tag_length(self) -> usize {
        match self {
            Self::Hmac256_64 => HMAC_SHA256_64_TAG_BYTES,
            Self::Hmac256_256 => HMAC_SHA256_TAG_LENGTH,
            Self::Hmac384_384 => HMAC_SHA384_TAG_LENGTH,
            Self::Hmac512_512 => HMAC_SHA512_TAG_LENGTH,
        }
    }

    /// Return the required key length for this direct-key profile.
    ///
    /// Keys have the full underlying hash output length, including for 256/64.
    #[must_use]
    pub const fn key_length(self) -> usize {
        match self {
            Self::Hmac256_64 | Self::Hmac256_256 => HMAC_SHA256_TAG_LENGTH,
            Self::Hmac384_384 => HMAC_SHA384_TAG_LENGTH,
            Self::Hmac512_512 => HMAC_SHA512_TAG_LENGTH,
        }
    }

    pub(super) const fn primitive(self) -> MacAlgorithm {
        match self {
            Self::Hmac256_64 | Self::Hmac256_256 => MacAlgorithm::HmacSha256,
            Self::Hmac384_384 => MacAlgorithm::HmacSha384,
            Self::Hmac512_512 => MacAlgorithm::HmacSha512,
        }
    }
}
