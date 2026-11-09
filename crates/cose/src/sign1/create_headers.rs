// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use coset::{Header, Label, ProtectedHeader, RegisteredLabelWithPrivate};
use reallyme_crypto::{core::Algorithm, dispatch::sign};
use zeroize::Zeroizing;

use crate::{algorithm::CoseSignatureAlgorithm, error::sign_error_from_algorithm_error, CoseError};

use super::{
    build_sig_structure::build_sig_structure,
    convert_signature::cose_signature_from_backend,
    cose_type::{CoseType, COSE_TYPE_HEADER_LABEL},
    sign::{encode_signing_protected, X5ChainHeaderPlacement},
    types::CoseSign1SigningSource,
    x5chain::x5chain_header,
};

pub(super) fn build_protected_header(
    alg: CoseSignatureAlgorithm,
    kid: Option<&[u8]>,
    cose_type: Option<&CoseType>,
    x5chain_der: &[Vec<u8>],
    x5chain_header_placement: X5ChainHeaderPlacement,
) -> Result<ProtectedHeader, CoseError> {
    let cose_alg = alg.to_iana();
    let mut header = Header {
        alg: Some(RegisteredLabelWithPrivate::Assigned(cose_alg)),
        key_id: kid.map(<[u8]>::to_vec).unwrap_or_default(),
        ..Default::default()
    };
    if let Some(cose_type) = cose_type {
        header.rest.push((
            Label::Int(COSE_TYPE_HEADER_LABEL),
            cose_type.to_cbor_value(),
        ));
    }
    if matches!(x5chain_header_placement, X5ChainHeaderPlacement::Protected) {
        if let Some(x5chain) = x5chain_header(x5chain_der) {
            // RFC 9360 requires integrity protection of the end-entity
            // certificate. Protect the entire path to avoid ambiguous identities.
            header.rest.push(x5chain);
        }
    }

    Ok(ProtectedHeader {
        header,
        original_data: None,
    })
}

pub(super) fn build_unprotected_header(
    x5chain_der: &[Vec<u8>],
    x5chain_header_placement: X5ChainHeaderPlacement,
) -> Header {
    let mut header = Header::default();
    if matches!(
        x5chain_header_placement,
        X5ChainHeaderPlacement::Unprotected
    ) {
        if let Some(x5chain) = x5chain_header(x5chain_der) {
            header.rest.push(x5chain);
        }
    }
    header
}

pub(super) fn sign_payload(
    alg: Algorithm,
    signing_source: CoseSign1SigningSource<'_>,
    protected: &ProtectedHeader,
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CoseError> {
    let protected_bytes = encode_signing_protected(protected)?;
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
