// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{
    CborSerializable, CoseSign1, Header, ProtectedHeader, RegisteredLabelWithPrivate,
    TaggedCborSerializable,
};
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::sign;

use crate::{key::map_algorithm::alg_to_cose, CoseError};

use super::build_sig_structure::build_sig_structure;
use super::convert_ecdsa_signature::cose_signature_from_backend;
use crate::limits::{
    validate_cose_sign1_bytes_with_limit, validate_detached_payload, MAX_COSE_SIGN1_BYTES,
};

/// Encoding controls for COSE_Sign1 signing APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoseSign1EncodeOptions {
    /// Emit the registered COSE_Sign1 root tag (18).
    pub tag: bool,

    /// Maximum encoded COSE_Sign1 size accepted after signing.
    pub max_cose_sign1_bytes: usize,
}

impl Default for CoseSign1EncodeOptions {
    fn default() -> Self {
        Self {
            tag: false,
            max_cose_sign1_bytes: MAX_COSE_SIGN1_BYTES,
        }
    }
}

/// Create COSE_Sign1 with an attached payload.
pub fn cose_sign1(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Vec<u8>, CoseError> {
    cose_sign1_with_options(
        alg,
        payload,
        private_key,
        kid,
        CoseSign1EncodeOptions::default(),
    )
}

/// Create tagged COSE_Sign1 with an attached payload.
pub fn cose_sign1_tagged(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Vec<u8>, CoseError> {
    cose_sign1_with_options(
        alg,
        payload,
        private_key,
        kid,
        CoseSign1EncodeOptions {
            tag: true,
            ..CoseSign1EncodeOptions::default()
        },
    )
}

/// Create COSE_Sign1 with an attached payload and explicit encoding options.
pub fn cose_sign1_with_options(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
    options: CoseSign1EncodeOptions,
) -> Result<Vec<u8>, CoseError> {
    validate_detached_payload(payload)?;
    let protected = build_protected_header(alg, kid)?;
    let signature = sign_payload(alg, private_key, &protected, payload)?;

    let cose = CoseSign1 {
        protected,
        unprotected: Header::default(),
        payload: Some(payload.to_vec()),
        signature,
    };

    encode_cose_sign1(cose, options)
}

/// Create COSE_Sign1 with a detached payload.
pub fn cose_sign1_detached(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Vec<u8>, CoseError> {
    cose_sign1_detached_with_options(
        alg,
        payload,
        private_key,
        kid,
        CoseSign1EncodeOptions::default(),
    )
}

/// Create tagged COSE_Sign1 with a detached payload.
pub fn cose_sign1_detached_tagged(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
) -> Result<Vec<u8>, CoseError> {
    cose_sign1_detached_with_options(
        alg,
        payload,
        private_key,
        kid,
        CoseSign1EncodeOptions {
            tag: true,
            ..CoseSign1EncodeOptions::default()
        },
    )
}

/// Create COSE_Sign1 with a detached payload and explicit encoding options.
pub fn cose_sign1_detached_with_options(
    alg: Algorithm,
    payload: &[u8],
    private_key: &[u8],
    kid: Option<&[u8]>,
    options: CoseSign1EncodeOptions,
) -> Result<Vec<u8>, CoseError> {
    validate_detached_payload(payload)?;
    let protected = build_protected_header(alg, kid)?;
    let signature = sign_payload(alg, private_key, &protected, payload)?;

    let cose = CoseSign1 {
        protected,
        unprotected: Header::default(),
        payload: None,
        signature,
    };

    encode_cose_sign1(cose, options)
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
    private_key: &[u8],
    protected: &ProtectedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, CoseError> {
    let protected_bytes = protected.clone().to_vec().map_err(|_| CoseError::Cbor)?;
    let to_sign = build_sig_structure(&protected_bytes, payload);

    let backend_signature = sign(alg, private_key, &to_sign).map_err(|_| CoseError::Crypto)?;
    cose_signature_from_backend(alg, backend_signature).map_err(|_| CoseError::Crypto)
}

fn encode_cose_sign1(
    cose: CoseSign1,
    options: CoseSign1EncodeOptions,
) -> Result<Vec<u8>, CoseError> {
    let encoded = if options.tag {
        cose.to_tagged_vec()
    } else {
        cose.to_vec()
    }
    .map_err(|_| CoseError::Cbor)?;

    validate_cose_sign1_bytes_with_limit(&encoded, options.max_cose_sign1_bytes)?;
    Ok(encoded)
}
