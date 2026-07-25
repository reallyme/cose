// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{AsCborValue, CoseSign1, Header, ProtectedHeader, RegisteredLabelWithPrivate};
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::sign;

use crate::failure::CoseFailure;
use crate::{
    encode_cbor::{encode_cbor_value, encode_protected_header},
    error::sign_error_from_algorithm_error,
    key::map_algorithm::alg_to_cose,
    CoseError,
};

use super::build_sig_structure::build_sig_structure;
use super::convert_signature::cose_signature_from_backend;
use crate::limits::{
    validate_cose_sign1_bytes_with_limit, validate_detached_payload, MAX_COSE_SIGN1_BYTES,
};
use zeroize::Zeroizing;

use super::provider::CoseSigner;
use super::types::{CoseSign1CreateInput, CoseSign1SigningSource};

#[must_use]
pub(crate) struct CoseSign1CreateOutput {
    cose_sign1: Zeroizing<Vec<u8>>,
}

impl CoseSign1CreateOutput {
    pub(crate) fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.cose_sign1
    }
}

#[derive(Clone, Copy)]
enum Sign1PayloadMode {
    Attached,
    Detached,
}

/// Encoding controls for COSE_Sign1 signing APIs.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoseSign1EncodeOptions {
    /// Emit the registered COSE_Sign1 root tag (18).
    tag: bool,

    /// Maximum encoded COSE_Sign1 size accepted after signing.
    max_cose_sign1_bytes: usize,
}

impl Default for CoseSign1EncodeOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl CoseSign1EncodeOptions {
    /// Construct the default untagged encoding options.
    pub const fn new() -> Self {
        Self {
            tag: false,
            max_cose_sign1_bytes: MAX_COSE_SIGN1_BYTES,
        }
    }

    /// Construct options that emit the registered COSE_Sign1 root tag (18).
    pub const fn tagged() -> Self {
        Self {
            tag: true,
            max_cose_sign1_bytes: MAX_COSE_SIGN1_BYTES,
        }
    }

    /// Return whether the encoded COSE_Sign1 root tag (18) is emitted.
    #[must_use]
    pub const fn tag(&self) -> bool {
        self.tag
    }

    /// Return the maximum encoded COSE_Sign1 size accepted after signing.
    #[must_use]
    pub const fn max_cose_sign1_bytes(&self) -> usize {
        self.max_cose_sign1_bytes
    }

    /// Configure whether the registered COSE_Sign1 root tag (18) is emitted.
    pub const fn with_tag(mut self, tag: bool) -> Self {
        self.tag = tag;
        self
    }

    /// Configure the maximum encoded COSE_Sign1 size accepted after signing.
    pub const fn with_max_cose_sign1_bytes(mut self, max_cose_sign1_bytes: usize) -> Self {
        self.max_cose_sign1_bytes = max_cose_sign1_bytes;
        self
    }
}

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
    ))
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
    ))
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
    ))
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
    ))
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
    validate_detached_payload(input.payload)?;
    validate_detached_payload(input.external_aad)?;
    let protected = build_protected_header(input.algorithm, input.kid)?;
    let signature = sign_payload(
        input.algorithm,
        input.signing_source,
        &protected,
        input.external_aad,
        input.payload,
    )?;
    let payload = match payload_mode {
        Sign1PayloadMode::Attached => Some(input.payload.to_vec()),
        Sign1PayloadMode::Detached => None,
    };
    encode_cose_sign1(
        CoseSign1 {
            protected,
            unprotected: Header::default(),
            payload,
            signature,
        },
        input.options,
    )
}

fn build_protected_header(
    alg: Algorithm,
    kid: Option<&[u8]>,
) -> Result<ProtectedHeader, CoseError> {
    let cose_alg = alg_to_cose(alg)?;
    let header = Header {
        alg: Some(RegisteredLabelWithPrivate::Assigned(cose_alg)),
        key_id: kid.map(<[u8]>::to_vec).unwrap_or_default(),
        ..Default::default()
    };

    Ok(ProtectedHeader {
        header,
        original_data: None,
    })
}

fn sign_payload(
    alg: Algorithm,
    signing_source: CoseSign1SigningSource<'_>,
    protected: &ProtectedHeader,
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CoseError> {
    let protected_bytes = encode_protected_header(protected)?;
    let to_sign = build_sig_structure(&protected_bytes, external_aad, payload)?;

    let mut backend_signature = match signing_source {
        CoseSign1SigningSource::PrivateKey(private_key) => Zeroizing::new(
            sign(alg, private_key, &to_sign).map_err(sign_error_from_algorithm_error)?,
        ),
        CoseSign1SigningSource::Provider(provider) => {
            provider.sign(&to_sign).map_err(CoseError::from)?
        }
    };
    let signature = core::mem::take(&mut *backend_signature);
    cose_signature_from_backend(alg, signature)
}

fn encode_cose_sign1(
    cose: CoseSign1,
    options: CoseSign1EncodeOptions,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let mut value = cose.to_cbor_value().map_err(|_| CoseError::Cbor)?;
    if options.tag() {
        value = ciborium::value::Value::Tag(18, Box::new(value));
    }
    let encoded = encode_cbor_value(value)?;

    validate_cose_sign1_bytes_with_limit(&encoded, options.max_cose_sign1_bytes())?;
    Ok(encoded)
}
