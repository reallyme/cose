// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use zeroize::Zeroizing;

use crate::zeroize_coset::SensitiveCborValue;
use crate::CoseError;

use super::validate_headers::validate;
use super::Iso18013SignatureAlgorithm;

pub(super) struct DecodedSign1 {
    pub(super) algorithm: Iso18013SignatureAlgorithm,
    pub(super) protected: Zeroizing<Vec<u8>>,
    pub(super) protected_kid: Option<Zeroizing<Vec<u8>>>,
    pub(super) payload: Option<Zeroizing<Vec<u8>>>,
    pub(super) signature: Zeroizing<Vec<u8>>,
}

pub(super) fn decode(encoded: &[u8], limit: usize) -> Result<DecodedSign1, CoseError> {
    // Shared preflight enforces bounded definite-length CBOR, minimal widths,
    // duplicate rejection and full consumption before allocating a wipe tree.
    let tree = SensitiveCborValue::decode_cose_sign1(encoded, limit)?;
    let Value::Array(items) = tree.value() else {
        // ISO role entrypoints require the untagged Sign1 form. The general
        // modern API retains its existing support for an outer tag 18.
        return Err(CoseError::InvalidFormat);
    };
    let [Value::Bytes(protected), Value::Map(unprotected), payload, Value::Bytes(signature)] =
        items.as_slice()
    else {
        return Err(CoseError::InvalidFormat);
    };
    if protected.is_empty() {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    let protected_tree = SensitiveCborValue::decode_protected_header(protected)?;
    let Value::Map(headers) = protected_tree.value() else {
        return Err(CoseError::InvalidFormat);
    };
    let (algorithm, kid) = validate(headers, unprotected)?;
    let payload = match payload {
        Value::Bytes(payload) => Some(copy_bytes(payload)?),
        Value::Null => None,
        _ => return Err(CoseError::InvalidFormat),
    };
    Ok(DecodedSign1 {
        algorithm,
        protected: copy_bytes(protected)?,
        protected_kid: kid.map(copy_bytes).transpose()?,
        payload,
        signature: copy_bytes(signature)?,
    })
}

fn copy_bytes(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let mut owned = Zeroizing::new(Vec::new());
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}
