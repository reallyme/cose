// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::Algorithm;

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::CoseMlKemAlgorithm;

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
pub use crate::generated_contract::CoseMlKemEncryptRequest;

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
pub use crate::generated_contract::CoseMlKemDecryptRequest;

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

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::CoseContentEncryptionAlgorithm;

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::CoseMlKemMode;

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::CoseMlKemProfile;

/// Authenticated plaintext and recipient metadata from `COSE_Encrypt`.
pub use crate::generated_contract::DecryptedCoseEncrypt;
