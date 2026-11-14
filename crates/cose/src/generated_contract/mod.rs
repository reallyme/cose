// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

mod constants;
mod error_aliases;
pub use constants::values;
#[cfg(feature = "wire")]
pub use constants::CONSTANTS;
#[cfg(feature = "cose-crypto")]
mod agreement_ec2_encoding_policy;
#[cfg(feature = "cose-crypto")]
mod agreement_key_policy;
#[cfg(feature = "cose-crypto")]
mod container_content;
#[cfg(feature = "cose-crypto")]
mod container_limits;
#[cfg(feature = "cose-crypto")]
mod container_policy;
#[cfg(feature = "cose-crypto")]
mod container_profile;
#[cfg(feature = "cose-crypto")]
mod container_purpose;
#[cfg(feature = "cose-crypto")]
mod container_sign_request;
#[cfg(feature = "cose-crypto")]
mod container_verify_request;
#[cfg(feature = "cose-crypto")]
mod cose_content_encryption_algorithm;
#[cfg(feature = "cose-crypto")]
mod cose_curve;
#[cfg(feature = "cose-crypto")]
mod cose_mac0_verify_request;
#[cfg(feature = "cose-crypto")]
mod cose_mac_algorithm;
#[cfg(feature = "cose-crypto")]
mod cose_ml_kem_algorithm;
#[cfg(feature = "cose-crypto")]
mod cose_ml_kem_decrypt_request;
#[cfg(feature = "cose-crypto")]
mod cose_ml_kem_encrypt_request;
#[cfg(feature = "cose-crypto")]
mod cose_ml_kem_mode;
#[cfg(feature = "cose-crypto")]
mod cose_ml_kem_profile;
mod cose_point_encoding;
mod cose_signature_algorithm;
#[cfg(feature = "cose-crypto")]
mod decrypted_cose_encrypt;
#[cfg(feature = "cose-crypto")]
mod end_entity_integrity;
#[cfg(feature = "cose-crypto")]
mod envelope_policy;
#[cfg(feature = "cose-crypto")]
mod header_provenance;
#[cfg(feature = "cose-crypto")]
mod inspected_peer_key;
#[cfg(feature = "cose-crypto")]
mod iso18013_ecdsa_hash;
#[cfg(feature = "cose-crypto")]
mod iso18013_sign1_content;
#[cfg(feature = "cose-crypto")]
mod iso18013_sign1_request;
#[cfg(feature = "cose-crypto")]
mod optional_key_policy;
#[cfg(feature = "cose-crypto")]
mod peer_key_usage;
#[cfg(feature = "cose-crypto")]
mod signature_encoding;
#[cfg(feature = "cose-crypto")]
mod signature_suite;
#[cfg(feature = "cose-crypto")]
mod signed_container;
#[cfg(feature = "cose-crypto")]
mod signing_content;
#[cfg(feature = "cose-crypto")]
mod signing_input;
#[cfg(feature = "cose-crypto")]
mod signing_mode;
#[cfg(feature = "cose-crypto")]
mod verification_source;
#[cfg(feature = "cose-crypto")]
mod verified_container;
#[cfg(feature = "cose-crypto")]
mod verified_cose_sign1;
#[cfg(feature = "cose-crypto")]
mod verified_cose_sign1_with_x5_chain;
#[cfg(feature = "cose-crypto")]
mod verified_detached_cose_mac0;
#[cfg(feature = "cose-crypto")]
mod verified_detached_cose_sign1;
#[cfg(feature = "cose-crypto")]
mod verified_iso18013_sign1;
#[cfg(feature = "cose-crypto")]
mod x5_chain_header_placement;
#[cfg(feature = "cose-crypto")]
pub use {
    agreement_ec2_encoding_policy::AgreementEc2EncodingPolicy,
    agreement_key_policy::AgreementKeyPolicy, container_content::ContainerContent,
    container_limits::ContainerLimits, container_policy::ContainerPolicy,
    container_profile::ContainerProfile, container_purpose::ContainerPurpose,
    container_sign_request::ContainerSignRequest, container_verify_request::ContainerVerifyRequest,
    cose_content_encryption_algorithm::CoseContentEncryptionAlgorithm, cose_curve::CoseCurve,
    cose_mac0_verify_request::CoseMac0VerifyRequest, cose_mac_algorithm::CoseMacAlgorithm,
    cose_ml_kem_algorithm::CoseMlKemAlgorithm,
    cose_ml_kem_decrypt_request::CoseMlKemDecryptRequest,
    cose_ml_kem_encrypt_request::CoseMlKemEncryptRequest, cose_ml_kem_mode::CoseMlKemMode,
    cose_ml_kem_profile::CoseMlKemProfile, decrypted_cose_encrypt::DecryptedCoseEncrypt,
    end_entity_integrity::EndEntityIntegrity, envelope_policy::EnvelopePolicy,
    header_provenance::HeaderProvenance, inspected_peer_key::InspectedPeerKey,
    iso18013_ecdsa_hash::Iso18013EcdsaHash, iso18013_sign1_content::Iso18013Sign1Content,
    iso18013_sign1_request::Iso18013Sign1Request, optional_key_policy::OptionalKeyPolicy,
    peer_key_usage::PeerKeyUsage, signature_encoding::SignatureEncoding,
    signature_suite::SignatureSuite, signed_container::SignedContainer,
    signing_content::SigningContent, signing_input::SigningInput, signing_mode::SigningMode,
    verification_source::VerificationSource, verified_container::VerifiedContainer,
    verified_cose_sign1::VerifiedCoseSign1,
    verified_cose_sign1_with_x5_chain::VerifiedCoseSign1WithX5Chain,
    verified_detached_cose_mac0::VerifiedDetachedCoseMac0,
    verified_detached_cose_sign1::VerifiedDetachedCoseSign1,
    verified_iso18013_sign1::VerifiedIso18013Sign1,
    x5_chain_header_placement::X5ChainHeaderPlacement,
};
pub use {
    cose_point_encoding::CosePointEncoding, cose_signature_algorithm::CoseSignatureAlgorithm,
};
