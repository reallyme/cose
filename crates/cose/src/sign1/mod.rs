// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! COSE_Sign1 signing and verification.

mod build_sign1_signature_structure;
pub use build_sign1_signature_structure::build_sign1_signature_structure;

#[cfg(feature = "cose-crypto")]
mod build_sig_structure;
#[cfg(feature = "cose-crypto")]
mod convert_signature;
#[cfg(feature = "cose-crypto")]
pub(crate) mod cose_type;
#[cfg(feature = "cose-crypto")]
mod create_headers;
#[cfg(feature = "cose-crypto")]
mod decode;
#[cfg(feature = "cose-crypto")]
mod encode_options;
#[cfg(feature = "cose-crypto")]
mod exact;
#[cfg(feature = "cose-crypto")]
mod provider;
#[cfg(feature = "cose-crypto")]
mod resolve_key;
#[cfg(feature = "cose-crypto")]
pub(crate) mod sign;
#[cfg(feature = "cose-crypto")]
pub(crate) mod types;
#[cfg(feature = "cose-crypto")]
pub(crate) mod verify;
#[cfg(feature = "cose-crypto")]
mod x5chain;
#[cfg(feature = "cose-crypto")]
pub(crate) use convert_signature::{
    backend_signature_from_cose, der_to_fixed_width, fixed_width_to_der,
};
#[cfg(feature = "cose-crypto")]
pub(crate) use x5chain::{validate_certificate_size, validate_x5chain_value};
#[cfg(test)]
#[cfg(feature = "cose-crypto")]
mod x5chain_tests;

#[cfg(feature = "cose-crypto")]
pub use cose_type::{CoseType, MAX_COSE_TYPE_TEXT_BYTES};
#[cfg(feature = "cose-crypto")]
pub use exact::{
    cose_sign1_detached_with_signature_algorithm,
    cose_sign1_detached_with_signature_algorithm_and_external_aad,
    cose_sign1_with_signature_algorithm, cose_sign1_with_signature_algorithm_and_external_aad,
};
#[cfg(feature = "cose-crypto")]
pub use provider::{CoseSigner, CoseSignerError};
#[cfg(feature = "cose-crypto")]
pub use sign::{
    cose_sign1, cose_sign1_detached, cose_sign1_detached_tagged, cose_sign1_detached_with_options,
    cose_sign1_detached_with_options_and_external_aad, cose_sign1_detached_with_signer,
    cose_sign1_tagged, cose_sign1_with_options, cose_sign1_with_options_and_external_aad,
    cose_sign1_with_signer, CoseSign1EncodeOptions, X5ChainHeaderPlacement,
};
#[cfg(feature = "cose-crypto")]
pub use verify::{
    cose_verify1, cose_verify1_detached, cose_verify1_detached_with_exact_algorithm,
    cose_verify1_detached_with_metadata, cose_verify1_detached_with_policy,
    cose_verify1_detached_with_policy_and_external_aad, cose_verify1_with_exact_algorithm,
    cose_verify1_with_metadata, cose_verify1_with_policy,
    cose_verify1_with_policy_and_external_aad, cose_verify1_with_x5chain,
    cose_verify1_with_x5chain_and_exact_algorithm, VerifiedCoseSign1, VerifiedCoseSign1WithX5Chain,
    VerifiedDetachedCoseSign1,
};
