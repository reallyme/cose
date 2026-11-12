// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::MacAlgorithm;
use reallyme_crypto::hmac::{
    HMAC_SHA256_TAG_LENGTH, HMAC_SHA384_TAG_LENGTH, HMAC_SHA512_TAG_LENGTH,
};

use super::error::CoseMac0ErrorReason;
use super::CoseMac0Error;

const HMAC_SHA256_64_TAG_BYTES: usize = 8;

/// Exact RFC 9053 HMAC registration, including its required tag length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoseMacAlgorithm {
    /// HMAC 256/64 (4): SHA-256 with a left-truncated 64-bit tag.
    Hmac256_64,
    /// HMAC 256/256 (5): SHA-256 with a 256-bit tag.
    Hmac256_256,
    /// HMAC 384/384 (6): SHA-384 with a 384-bit tag.
    Hmac384_384,
    /// HMAC 512/512 (7): SHA-512 with a 512-bit tag.
    Hmac512_512,
}

impl CoseMacAlgorithm {
    /// Return the exact COSE algorithm identifier.
    #[must_use]
    pub const fn cose_id(self) -> i64 {
        match self {
            Self::Hmac256_64 => 4,
            Self::Hmac256_256 => 5,
            Self::Hmac384_384 => 6,
            Self::Hmac512_512 => 7,
        }
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

    pub(super) fn from_cose_id(id: i64) -> Result<Self, CoseMac0Error> {
        match id {
            4 => Ok(Self::Hmac256_64),
            5 => Ok(Self::Hmac256_256),
            6 => Ok(Self::Hmac384_384),
            7 => Ok(Self::Hmac512_512),
            _ => Err(CoseMac0ErrorReason::UnsupportedAlgorithm.into()),
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
