// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::sign1::cose_type::CoseTypeExt;
use coset::{CoseSign1, ProtectedHeader};
use reallyme_crypto::core::Algorithm;

use crate::failure::CoseFailure;
use crate::{
    encode_cbor::{encode_cbor_value, encode_protected_header},
    CoseError,
};

use super::create_headers::{build_protected_header, build_unprotected_header, sign_payload};
use super::decode::SensitiveCoseSign1;
use crate::limits::{validate_cose_sign1_bytes_with_limit, validate_detached_payload_with_limit};
use zeroize::Zeroizing;

use super::provider::CoseSigner;
use super::types::CoseSign1CreateInput;
use super::x5chain::{encode_unprotected_header, validate_x5chain};

#[must_use]
pub(crate) struct CoseSign1CreateOutput {
    cose_sign1: Zeroizing<Vec<u8>>,
}

impl CoseSign1CreateOutput {
    pub(crate) fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.cose_sign1
    }
}

pub(super) fn encode_signing_protected(
    protected: &ProtectedHeader,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let encoded = encode_protected_header(protected)?;
    Ok(encoded)
}

#[derive(Clone, Copy)]
enum Sign1PayloadMode {
    Attached,
    Detached,
}

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::X5ChainHeaderPlacement;

pub use super::encode_options::CoseSign1EncodeOptions;

/// Create COSE_Sign1 with an attached payload.
///
/// # Errors
///
/// Returns [`CoseError`] when the algorithm, key, input, signature encoding,
/// or encoded output violates the supported COSE profile or resource limits.
pub fn cose_sign1(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    cose_sign1_with_options(
        alg,
        payload,
        private_key,
        kid,
        CoseSign1EncodeOptions::default(),
    )
}

/// Create tagged COSE_Sign1 with an attached payload.
///
/// # Errors
///
/// Returns [`CoseError`] when the algorithm, key, input, signature encoding,
/// or encoded output violates the supported COSE profile or resource limits.
pub fn cose_sign1_tagged(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    cose_sign1_with_options(
        alg,
        payload,
        private_key,
        kid,
        CoseSign1EncodeOptions::tagged(),
    )
}

/// Create COSE_Sign1 with an attached payload and explicit encoding options.
///
/// # Errors
///
/// Returns [`CoseError`] when the algorithm, key, input, signature encoding,
/// encoding options, or encoded output violates the supported COSE profile.
pub fn cose_sign1_with_options(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
    options: CoseSign1EncodeOptions,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    cose_sign1_with_options_and_external_aad(alg, payload, private_key, kid, &[], options)
}

/// Create COSE_Sign1 with an attached payload, external AAD, and explicit
/// encoding options.
///
/// # Errors
///
/// Returns [`CoseError`] when an input, key, algorithm, signature, encoding,
/// external-AAD limit, or output-size policy is invalid.
pub fn cose_sign1_with_options_and_external_aad(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
    external_aad: &[u8],
    options: CoseSign1EncodeOptions,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    create_cose_sign1(CoseSign1CreateInput::new(
        alg,
        payload,
        private_key,
        kid,
        external_aad,
        options,
    )?)
    .map(CoseSign1CreateOutput::into_zeroizing)
    .map_err(CoseFailure::into_native_error)
}

/// Create COSE_Sign1 with a detached payload.
///
/// # Errors
///
/// Returns [`CoseError`] when the algorithm, key, detached payload, signature
/// encoding, or encoded output violates the supported COSE profile.
pub fn cose_sign1_detached(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    cose_sign1_detached_with_options(
        alg,
        payload,
        private_key,
        kid,
        CoseSign1EncodeOptions::default(),
    )
}

/// Create tagged COSE_Sign1 with a detached payload.
///
/// # Errors
///
/// Returns [`CoseError`] when the algorithm, key, detached payload, signature
/// encoding, or encoded output violates the supported COSE profile.
pub fn cose_sign1_detached_tagged(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    cose_sign1_detached_with_options(
        alg,
        payload,
        private_key,
        kid,
        CoseSign1EncodeOptions::tagged(),
    )
}

/// Create COSE_Sign1 with a detached payload and explicit encoding options.
///
/// # Errors
///
/// Returns [`CoseError`] when the algorithm, key, detached payload, signature
/// encoding, encoding options, or output violates the supported COSE profile.
pub fn cose_sign1_detached_with_options(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
    options: CoseSign1EncodeOptions,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    cose_sign1_detached_with_options_and_external_aad(alg, payload, private_key, kid, &[], options)
}

/// Create detached COSE_Sign1 with external AAD and explicit encoding options.
///
/// # Errors
///
/// Returns [`CoseError`] when an input, key, algorithm, signature, encoding,
/// external-AAD limit, or output-size policy is invalid.
pub fn cose_sign1_detached_with_options_and_external_aad(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
    external_aad: &[u8],
    options: CoseSign1EncodeOptions,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    create_detached_cose_sign1(CoseSign1CreateInput::new(
        alg,
        payload,
        private_key,
        kid,
        external_aad,
        options,
    )?)
    .map(CoseSign1CreateOutput::into_zeroizing)
    .map_err(CoseFailure::into_native_error)
}

/// Create an attached COSE_Sign1 with a non-exportable provider-owned key.
///
/// # Errors
///
/// Returns [`CoseError`] when input validation, provider signing, signature
/// normalization, or bounded COSE encoding fails.
pub fn cose_sign1_with_signer(
    signer: &dyn CoseSigner,
    payload: &[u8],
    kid: Option<&[u8]>,
    external_aad: &[u8],
    options: CoseSign1EncodeOptions,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    create_cose_sign1(CoseSign1CreateInput::with_signer(
        signer,
        payload,
        kid,
        external_aad,
        options,
    )?)
    .map(CoseSign1CreateOutput::into_zeroizing)
    .map_err(CoseFailure::into_native_error)
}

/// Create a detached COSE_Sign1 with a non-exportable provider-owned key.
///
/// # Errors
///
/// Returns [`CoseError`] when input validation, provider signing, signature
/// normalization, or bounded COSE encoding fails.
pub fn cose_sign1_detached_with_signer(
    signer: &dyn CoseSigner,
    payload: &[u8],
    kid: Option<&[u8]>,
    external_aad: &[u8],
    options: CoseSign1EncodeOptions,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    create_detached_cose_sign1(CoseSign1CreateInput::with_signer(
        signer,
        payload,
        kid,
        external_aad,
        options,
    )?)
    .map(CoseSign1CreateOutput::into_zeroizing)
    .map_err(CoseFailure::into_native_error)
}

pub(crate) fn create_cose_sign1(
    input: CoseSign1CreateInput<'_>,
) -> Result<CoseSign1CreateOutput, CoseFailure> {
    create_cose_sign1_impl(input, Sign1PayloadMode::Attached)
        .map(|cose_sign1| CoseSign1CreateOutput { cose_sign1 })
        .map_err(CoseFailure::from)
}

pub(crate) fn create_detached_cose_sign1(
    input: CoseSign1CreateInput<'_>,
) -> Result<CoseSign1CreateOutput, CoseFailure> {
    create_cose_sign1_impl(input, Sign1PayloadMode::Detached)
        .map(|cose_sign1| CoseSign1CreateOutput { cose_sign1 })
        .map_err(CoseFailure::from)
}

fn create_cose_sign1_impl(
    input: CoseSign1CreateInput<'_>,
    payload_mode: Sign1PayloadMode,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    validate_detached_payload_with_limit(input.payload, input.options.max_payload_bytes())?;
    validate_detached_payload_with_limit(
        input.external_aad,
        input.options.max_external_aad_bytes(),
    )?;
    validate_x5chain(input.options.x5chain_der())?;
    if let Some(cose_type) = input.options.protected_type() {
        cose_type.validate()?;
    }
    if input.kid.is_some_and(<[u8]>::is_empty) {
        return Err(CoseError::InvalidFormat);
    }
    if input
        .kid
        .is_some_and(|kid| kid.len() > input.options.max_cose_sign1_bytes())
    {
        return Err(CoseError::ResourceLimitExceeded);
    }
    // Keep identifiers under a wipe owner even when a provider rejects signing.
    let mut cose = SensitiveCoseSign1::new(CoseSign1 {
        protected: build_protected_header(
            input.cose_algorithm,
            input.kid,
            input.options.protected_type(),
            input.options.x5chain_der(),
            input.options.x5chain_header_placement(),
        )?,
        unprotected: build_unprotected_header(
            input.options.x5chain_der(),
            input.options.x5chain_header_placement(),
        ),
        ..Default::default()
    });
    cose.inner_mut().signature = sign_payload(
        input.algorithm,
        input.signing_source,
        &cose.inner().protected,
        input.external_aad,
        input.payload,
    )?;
    cose.inner_mut().payload = match payload_mode {
        Sign1PayloadMode::Attached => Some(input.payload.to_vec()),
        Sign1PayloadMode::Detached => None,
    };
    encode_cose_sign1(core::mem::take(cose.inner_mut()), input.options)
}

fn encode_cose_sign1(
    cose: CoseSign1,
    options: CoseSign1EncodeOptions,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let mut cose = SensitiveCoseSign1::new(cose);
    let mut protected = encode_protected_header(&cose.inner().protected)?;
    // Coset's consuming conversion serializes protected headers into ordinary
    // temporary buffers. Move fields directly into our recursive wipe owner.
    let mut value = ciborium::value::Value::Array(vec![
        ciborium::value::Value::Bytes(core::mem::take(&mut *protected)),
        encode_unprotected_header(&mut cose.inner_mut().unprotected)?,
        cose.inner_mut()
            .payload
            .take()
            .map_or(ciborium::value::Value::Null, ciborium::value::Value::Bytes),
        ciborium::value::Value::Bytes(core::mem::take(&mut cose.inner_mut().signature)),
    ]);
    if options.tag() {
        value = ciborium::value::Value::Tag(18, Box::new(value));
    }
    let encoded = encode_cbor_value(value)?;

    validate_cose_sign1_bytes_with_limit(&encoded, options.max_cose_sign1_bytes())?;
    Ok(encoded)
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
#[path = "encode_tests.rs"]
mod encode_tests;

impl zeroize::ZeroizeOnDrop for CoseSign1EncodeOptions {}
