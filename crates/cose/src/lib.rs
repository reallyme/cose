// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! COSE helpers for ReallyMe identity software.
//!
//! The public surface covers COSE_Sign1, COSE_Key, and the ReallyMe ML-KEM
//! profile for COSE_Encrypt. Other COSE message families fail closed instead
//! of being partially interpreted.
//!
//! # Example
//!
//! ```
//! use reallyme_cose::{cose_sign1, cose_verify1_with_policy, Algorithm, CoseError, CosePolicy};
//! use reallyme_crypto::dispatch::generate_keypair;
//!
//! fn sign_and_verify() -> Result<(), CoseError> {
//!     let (public_key, private_key) = generate_keypair(Algorithm::Ed25519)
//!         .map_err(|_| CoseError::Crypto)?;
//!     let kid = b"example-key";
//!
//!     let cose_bytes = cose_sign1(Algorithm::Ed25519, b"payload", &private_key, Some(kid))?;
//!     let policy = CosePolicy::new()
//!         .with_require_kid(true)
//!         .allow_algorithm(Algorithm::Ed25519);
//!
//!     let verified = cose_verify1_with_policy(&cose_bytes, &policy, |algorithm, requested_kid| {
//!         (algorithm == Algorithm::Ed25519 && requested_kid == kid).then(|| public_key.clone())
//!     })?;
//!     assert_eq!(verified.payload.as_slice(), b"payload");
//!     assert_eq!(verified.alg, Algorithm::Ed25519);
//!     assert_eq!(verified.kid.as_slice(), kid);
//!     Ok(())
//! }
//! # fn main() -> Result<(), CoseError> { sign_and_verify() }
//! ```

#[cfg(all(feature = "wire", not(any(feature = "native", feature = "wasm"))))]
compile_error!(
    "reallyme-cose `wire` requires a runtime lane: enable feature `native` for Rust crypto or `wasm` for wasm32-unknown-unknown"
);

/// Crypto algorithm selector used by the COSE public API.
///
/// Consumers should import this re-export instead of depending directly on
/// `reallyme-crypto`; that keeps the algorithm type identical to the one used
/// by `reallyme-cose`.
pub use reallyme_crypto::core::Algorithm;

/// COSE algorithm mapping helpers.
pub mod algorithm;
/// Typed COSE errors.
pub mod error;
pub use error::CoseError;

mod encode_cbor;
mod failure;

#[cfg(test)]
mod failure_tests;

/// Resource limits shared by COSE byte-boundary APIs.
pub mod limits;

mod zeroize_coset;

// --- COSE_Encrypt ---
#[cfg(feature = "cose-crypto")]
pub mod encrypt;
#[cfg(feature = "cose-crypto")]
pub use encrypt::{
    cose_decrypt_ml_kem, cose_decrypt_ml_kem_with_external_aad, cose_encrypt_ml_kem_direct,
    cose_encrypt_ml_kem_direct_with_external_aad, cose_encrypt_ml_kem_key_wrap,
    cose_encrypt_ml_kem_key_wrap_with_external_aad, CoseContentEncryptionAlgorithm,
    CoseMlKemAlgorithm, CoseMlKemDecryptRequest, CoseMlKemEncryptRequest, CoseMlKemMode,
    CoseMlKemProfile, DecryptedCoseEncrypt, REALLYME_COSE_ALG_ML_KEM_1024,
    REALLYME_COSE_ALG_ML_KEM_1024_A256KW, REALLYME_COSE_ALG_ML_KEM_512,
    REALLYME_COSE_ALG_ML_KEM_512_A128KW, REALLYME_COSE_ALG_ML_KEM_768,
    REALLYME_COSE_ALG_ML_KEM_768_A192KW, REALLYME_COSE_HEADER_EK,
};

// --- COSE_Sign1 ---
pub mod sign1;
#[cfg(feature = "cose-crypto")]
pub use sign1::{
    cose_sign1, cose_sign1_detached, cose_sign1_detached_tagged, cose_sign1_detached_with_options,
    cose_sign1_detached_with_options_and_external_aad, cose_sign1_detached_with_signer,
    cose_sign1_tagged, cose_sign1_with_options, cose_sign1_with_options_and_external_aad,
    cose_sign1_with_signer, cose_verify1, cose_verify1_detached,
    cose_verify1_detached_with_metadata, cose_verify1_detached_with_policy,
    cose_verify1_detached_with_policy_and_external_aad, cose_verify1_with_metadata,
    cose_verify1_with_policy, cose_verify1_with_policy_and_external_aad, CoseSign1EncodeOptions,
    CoseSigner, CoseSignerError, VerifiedCoseSign1, VerifiedDetachedCoseSign1,
};

/// COSE semantic policy enforcement.
pub mod policy;
pub use policy::CosePolicy;

// --- COSE_Key ---
pub mod key;
pub use key::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_from_slice,
    cose_key_to_private_bytes, cose_key_to_public_bytes, cose_key_to_vec,
    derive_kid_from_cose_key_public, CoseKey,
};

/// COSE_Key and Multikey conversion helpers.
pub mod multikey;
pub use multikey::{cose_key_to_multikey, multikey_to_cose_key};

#[cfg(feature = "wire")]
mod operation_contract;

/// Protobuf-ready request, result, and error adapters.
#[cfg(feature = "wire")]
pub mod wire;
