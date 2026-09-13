// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signing facade for exact COSE signature registrations.

use zeroize::Zeroizing;

use crate::algorithm::CoseSignatureAlgorithm;
use crate::failure::CoseFailure;
use crate::CoseError;

use super::sign::{
    create_cose_sign1, create_detached_cose_sign1, CoseSign1CreateOutput, CoseSign1EncodeOptions,
};
use super::types::CoseSign1CreateInput;

/// Create COSE_Sign1 with an attached payload and an exact COSE algorithm.
///
/// # Errors
///
/// Returns [`CoseError`] when an input, key, algorithm, signature, or bounded
/// encoding violates the supported COSE profile.
pub fn cose_sign1_with_signature_algorithm(
    algorithm: CoseSignatureAlgorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    cose_sign1_with_signature_algorithm_and_external_aad(
        algorithm,
        payload,
        private_key,
        kid,
        &[],
        CoseSign1EncodeOptions::default(),
    )
}

/// Create attached COSE_Sign1 with an exact algorithm, external AAD, and
/// explicit encoding options.
///
/// # Errors
///
/// Returns [`CoseError`] when an input, key, algorithm, signature, encoding,
/// external-AAD limit, or output-size policy is invalid.
pub fn cose_sign1_with_signature_algorithm_and_external_aad(
    algorithm: CoseSignatureAlgorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
    external_aad: &[u8],
    options: CoseSign1EncodeOptions,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    create_cose_sign1(CoseSign1CreateInput::with_signature_algorithm(
        algorithm,
        payload,
        private_key,
        kid,
        external_aad,
        options,
    ))
    .map(CoseSign1CreateOutput::into_zeroizing)
    .map_err(CoseFailure::into_native_error)
}

/// Create detached COSE_Sign1 with an exact COSE algorithm.
///
/// # Errors
///
/// Returns [`CoseError`] when an input, key, algorithm, signature, or bounded
/// encoding violates the supported COSE profile.
pub fn cose_sign1_detached_with_signature_algorithm(
    algorithm: CoseSignatureAlgorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    cose_sign1_detached_with_signature_algorithm_and_external_aad(
        algorithm,
        payload,
        private_key,
        kid,
        &[],
        CoseSign1EncodeOptions::default(),
    )
}

/// Create detached COSE_Sign1 with an exact algorithm, external AAD, and
/// explicit encoding options.
///
/// # Errors
///
/// Returns [`CoseError`] when an input, key, algorithm, signature, encoding,
/// external-AAD limit, or output-size policy is invalid.
pub fn cose_sign1_detached_with_signature_algorithm_and_external_aad(
    algorithm: CoseSignatureAlgorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
    external_aad: &[u8],
    options: CoseSign1EncodeOptions,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    create_detached_cose_sign1(CoseSign1CreateInput::with_signature_algorithm(
        algorithm,
        payload,
        private_key,
        kid,
        external_aad,
        options,
    ))
    .map(CoseSign1CreateOutput::into_zeroizing)
    .map_err(CoseFailure::into_native_error)
}
