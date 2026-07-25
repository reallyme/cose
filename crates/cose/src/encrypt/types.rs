// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_crypto::core::Algorithm;
use zeroize::Zeroizing;

/// ML-KEM parameter sets supported by the ReallyMe COSE profile.
///
/// This profile-specific selector prevents unrelated crypto algorithms from
/// entering the native encryption API and defers conversion to the broader
/// crypto dispatch enum until the primitive boundary.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseMlKemAlgorithm {
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
}

impl CoseMlKemAlgorithm {
    pub(crate) const fn crypto_algorithm(self) -> Algorithm {
        match self {
            Self::MlKem512 => Algorithm::MlKem512,
            Self::MlKem768 => Algorithm::MlKem768,
            Self::MlKem1024 => Algorithm::MlKem1024,
        }
    }
}

/// Inputs for creating one-recipient ReallyMe ML-KEM `COSE_Encrypt`.
///
/// The recipient `kid` is mandatory in the ReallyMe profile and is placed in
/// the protected recipient header. This binds key selection to the same bytes
/// that are fed into the COSE KDF context.
#[must_use]
#[non_exhaustive]
pub struct CoseMlKemEncryptRequest<'a> {
    /// ML-KEM-512, ML-KEM-768, or ML-KEM-1024.
    pub(super) kem_algorithm: CoseMlKemAlgorithm,
    /// AES-GCM algorithm used for the content layer.
    pub(super) content_algorithm: CoseContentEncryptionAlgorithm,
    /// Raw FIPS 203 ML-KEM encapsulation public key.
    pub(super) recipient_public_key: &'a [u8],
    /// SHA-256 thumbprint of the canonical public COSE_Key for this recipient.
    pub(super) recipient_kid: &'a [u8],
    /// Plaintext to encrypt.
    pub(super) plaintext: &'a [u8],
    /// Optional mutually known private KDF context agreed out of band.
    pub(super) supp_priv_info: Option<&'a [u8]>,
}

impl<'a> CoseMlKemEncryptRequest<'a> {
    /// Construct a complete bounded ML-KEM encryption request.
    pub const fn new(
        kem_algorithm: CoseMlKemAlgorithm,
        content_algorithm: CoseContentEncryptionAlgorithm,
        recipient_public_key: &'a [u8],
        recipient_kid: &'a [u8],
        plaintext: &'a [u8],
        supp_priv_info: Option<&'a [u8]>,
    ) -> Self {
        Self {
            kem_algorithm,
            content_algorithm,
            recipient_public_key,
            recipient_kid,
            plaintext,
            supp_priv_info,
        }
    }

    /// Replace the optional mutually known private KDF context.
    pub const fn with_supp_priv_info(mut self, supp_priv_info: Option<&'a [u8]>) -> Self {
        self.supp_priv_info = supp_priv_info;
        self
    }
}

/// Inputs for decrypting one-recipient ReallyMe ML-KEM `COSE_Encrypt`.
#[must_use]
#[non_exhaustive]
pub struct CoseMlKemDecryptRequest<'a> {
    /// Tagged or untagged encoded `COSE_Encrypt`.
    pub(super) cose_encrypt: &'a [u8],
    /// Raw 64-octet FIPS 203 ML-KEM seed `d || z`.
    pub(super) recipient_private_key: &'a [u8],
    /// Expected canonical public COSE_Key thumbprint for the selected private key.
    pub(super) expected_recipient_kid: &'a [u8],
    /// Optional mutually known private KDF context agreed out of band.
    pub(super) supp_priv_info: Option<&'a [u8]>,
}

impl<'a> CoseMlKemDecryptRequest<'a> {
    /// Construct a complete bounded ML-KEM decryption request.
    pub const fn new(
        cose_encrypt: &'a [u8],
        recipient_private_key: &'a [u8],
        expected_recipient_kid: &'a [u8],
        supp_priv_info: Option<&'a [u8]>,
    ) -> Self {
        Self {
            cose_encrypt,
            recipient_private_key,
            expected_recipient_kid,
            supp_priv_info,
        }
    }

    /// Replace the optional mutually known private KDF context.
    pub const fn with_supp_priv_info(mut self, supp_priv_info: Option<&'a [u8]>) -> Self {
        self.supp_priv_info = supp_priv_info;
        self
    }
}

pub(crate) struct CoseMlKemEncryptInput<'request, 'data> {
    pub(super) request: &'request CoseMlKemEncryptRequest<'data>,
    pub(super) external_aad: &'request [u8],
}

impl<'request, 'data> CoseMlKemEncryptInput<'request, 'data> {
    pub(crate) const fn new(
        request: &'request CoseMlKemEncryptRequest<'data>,
        external_aad: &'request [u8],
    ) -> Self {
        Self {
            request,
            external_aad,
        }
    }
}

pub(crate) struct CoseMlKemDecryptInput<'request, 'data> {
    pub(super) request: &'request CoseMlKemDecryptRequest<'data>,
    pub(super) external_aad: &'request [u8],
}

impl<'request, 'data> CoseMlKemDecryptInput<'request, 'data> {
    pub(crate) const fn new(
        request: &'request CoseMlKemDecryptRequest<'data>,
        external_aad: &'request [u8],
    ) -> Self {
        Self {
            request,
            external_aad,
        }
    }
}

/// Content-encryption algorithms supported by the ReallyMe ML-KEM COSE profile.
///
/// The content cipher is selected independently from the ML-KEM parameter set.
/// Applications seeking aligned strength should pair ML-KEM-512/768/1024 with
/// AES-128/192/256-GCM respectively; a mixed pairing has the strength of its
/// weaker component.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseContentEncryptionAlgorithm {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-192-GCM.
    Aes192Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
}

/// ML-KEM key-distribution mode used by a `COSE_Recipient`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseMlKemMode {
    /// KMAC256 derives the content-encryption key directly.
    Direct,
    /// KMAC256 derives an AES-KW key-encryption key that unwraps the CEK.
    KeyWrap,
}

/// Identifier namespace used by a decoded ML-KEM COSE object.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseMlKemProfile {
    /// Stable ReallyMe private-use identifiers for the pre-IANA profile.
    ReallyMeV1,
}

/// Authenticated plaintext and recipient metadata from `COSE_Encrypt`.
#[must_use]
#[non_exhaustive]
pub struct DecryptedCoseEncrypt {
    /// Authenticated plaintext, zeroized on drop.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Content-encryption algorithm from the protected body header.
    pub content_algorithm: CoseContentEncryptionAlgorithm,
    /// ML-KEM algorithm from the protected recipient header.
    pub kem_algorithm: CoseMlKemAlgorithm,
    /// Direct or AES-KW recipient mode.
    pub mode: CoseMlKemMode,
    /// Protected recipient key identifier, zeroized on drop because application
    /// key identifiers can contain privacy-sensitive routing metadata.
    pub kid: Zeroizing<Vec<u8>>,
    /// Identifier namespace decoded from the recipient algorithm.
    pub profile: CoseMlKemProfile,
}
