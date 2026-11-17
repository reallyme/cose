// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::wire::{
    CoseContentEncryptionAlgorithm, CoseKemAlgorithm, CoseMlKemDecryptResult, CoseMlKemMode,
    CoseSignatureAlgorithm,
};
use buffa::EnumValue;

// Published legacy selectors remain valid metadata for older callers.
#[allow(deprecated)]
fn signature_algorithm_is_valid(value: EnumValue<CoseSignatureAlgorithm>) -> bool {
    matches!(
        value.as_known(),
        Some(
            CoseSignatureAlgorithm::Ed25519
                | CoseSignatureAlgorithm::EcdsaP256Sha256
                | CoseSignatureAlgorithm::Es256
                | CoseSignatureAlgorithm::Esp256
                | CoseSignatureAlgorithm::EcdsaP384Sha384
                | CoseSignatureAlgorithm::Esp384
                | CoseSignatureAlgorithm::EcdsaP521Sha512
                | CoseSignatureAlgorithm::Esp512
                | CoseSignatureAlgorithm::EcdsaSecp256k1Sha256
                | CoseSignatureAlgorithm::MlDsa44
                | CoseSignatureAlgorithm::MlDsa65
                | CoseSignatureAlgorithm::MlDsa87
        )
    )
}

pub(super) fn sign1_metadata_is_valid(result: &crate::wire::CoseSign1VerifyResult) -> bool {
    if let Some(cose_type) = result.protected_type.as_option() {
        match cose_type.value.as_ref() {
            Some(crate::wire::cose_type::Value::MediaType(text))
                if !text.is_empty() && text.len() <= crate::MAX_COSE_TYPE_TEXT_BYTES => {}
            Some(crate::wire::cose_type::Value::ContentFormat(_)) => {}
            _ => return false,
        }
    }
    if !signature_algorithm_is_valid(result.algorithm) {
        return false;
    }
    let Some(compatibility) = result.algorithm.as_known() else {
        return false;
    };
    if result.exact_signature_algorithm == CoseSignatureAlgorithm::Unspecified {
        return result.exact_signature_algorithm.to_i32() == 0;
    }
    let Some(exact) = result.exact_signature_algorithm.as_known() else {
        return false;
    };
    signature_algorithm_is_valid(result.algorithm)
        && exact_signature_algorithm_is_valid(exact)
        && signature_algorithms_share_primitive(compatibility, exact)
}

pub(super) const fn exact_signature_algorithm_is_valid(algorithm: CoseSignatureAlgorithm) -> bool {
    matches!(
        algorithm,
        CoseSignatureAlgorithm::Ed25519
            | CoseSignatureAlgorithm::Es256
            | CoseSignatureAlgorithm::Esp256
            | CoseSignatureAlgorithm::Esp384
            | CoseSignatureAlgorithm::Esp512
            | CoseSignatureAlgorithm::EcdsaSecp256k1Sha256
            | CoseSignatureAlgorithm::MlDsa44
            | CoseSignatureAlgorithm::MlDsa65
            | CoseSignatureAlgorithm::MlDsa87
    )
}

// Published legacy selectors remain valid metadata for older callers.
#[allow(deprecated)]
const fn signature_algorithms_share_primitive(
    compatibility: CoseSignatureAlgorithm,
    exact: CoseSignatureAlgorithm,
) -> bool {
    matches!(
        (compatibility, exact),
        (
            CoseSignatureAlgorithm::Ed25519,
            CoseSignatureAlgorithm::Ed25519,
        ) | (
            CoseSignatureAlgorithm::EcdsaP256Sha256
                | CoseSignatureAlgorithm::Es256
                | CoseSignatureAlgorithm::Esp256,
            CoseSignatureAlgorithm::Es256 | CoseSignatureAlgorithm::Esp256,
        ) | (
            CoseSignatureAlgorithm::EcdsaP384Sha384 | CoseSignatureAlgorithm::Esp384,
            CoseSignatureAlgorithm::Esp384,
        ) | (
            CoseSignatureAlgorithm::EcdsaP521Sha512 | CoseSignatureAlgorithm::Esp512,
            CoseSignatureAlgorithm::Esp512,
        ) | (
            CoseSignatureAlgorithm::EcdsaSecp256k1Sha256,
            CoseSignatureAlgorithm::EcdsaSecp256k1Sha256,
        ) | (
            CoseSignatureAlgorithm::MlDsa44,
            CoseSignatureAlgorithm::MlDsa44,
        ) | (
            CoseSignatureAlgorithm::MlDsa65,
            CoseSignatureAlgorithm::MlDsa65,
        ) | (
            CoseSignatureAlgorithm::MlDsa87,
            CoseSignatureAlgorithm::MlDsa87,
        )
    )
}

pub(super) fn decrypt_metadata_is_valid(result: &CoseMlKemDecryptResult) -> bool {
    matches!(
        result.content_algorithm.as_known(),
        Some(
            CoseContentEncryptionAlgorithm::Aes128Gcm
                | CoseContentEncryptionAlgorithm::Aes192Gcm
                | CoseContentEncryptionAlgorithm::Aes256Gcm
        )
    ) && matches!(
        result.kem_algorithm.as_known(),
        Some(CoseKemAlgorithm::MlKem512 | CoseKemAlgorithm::MlKem768 | CoseKemAlgorithm::MlKem1024)
    ) && matches!(
        result.mode.as_known(),
        Some(CoseMlKemMode::Direct | CoseMlKemMode::KeyWrap)
    )
}
