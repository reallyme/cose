// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use zeroize::Zeroizing;

use crate::zeroize_coset::SensitiveCborValue;

use super::validate_headers::validate_headers;
use super::{CoseMac0Error, CoseMac0ErrorReason, VerifiedDetachedCoseMac0};

pub(super) struct DecodedMac0 {
    pub(super) metadata: VerifiedDetachedCoseMac0,
    pub(super) tag: Zeroizing<Vec<u8>>,
}

pub(super) fn decode(bytes: &[u8], max_len: usize) -> Result<DecodedMac0, CoseMac0Error> {
    // The shared preflight bounds allocations and recursion and rejects
    // duplicate labels, unexpected tags, and trailing data before decoding.
    let decoded = SensitiveCborValue::decode_cose_mac0(bytes, max_len)?;
    let body = match decoded.value() {
        Value::Tag(17, body) => body.as_ref(),
        value => value,
    };
    let Value::Array(items) = body else {
        return Err(CoseMac0ErrorReason::InvalidStructure.into());
    };
    let [Value::Bytes(protected), Value::Map(unprotected), payload, Value::Bytes(tag)] =
        items.as_slice()
    else {
        return Err(CoseMac0ErrorReason::InvalidStructure.into());
    };
    if !matches!(payload, Value::Null) {
        return Err(CoseMac0ErrorReason::DetachedPayloadRequired.into());
    }

    // Empty protected buckets are valid CBOR/COSE, but this direct-key profile
    // cannot select an authenticated algorithm from one.
    if protected.is_empty() {
        return Err(CoseMac0ErrorReason::MissingProtectedAlgorithm.into());
    }
    let protected_tree = SensitiveCborValue::decode_protected_header(protected)?;
    let Value::Map(protected_entries) = protected_tree.value() else {
        return Err(CoseMac0ErrorReason::InvalidStructure.into());
    };
    let (algorithm, kid) = validate_headers(protected_entries, unprotected)?;

    Ok(DecodedMac0 {
        metadata: VerifiedDetachedCoseMac0 {
            algorithm,
            protected_bytes: copy_bytes(protected)?,
            protected_kid: kid.map(copy_bytes).transpose()?,
        },
        tag: copy_bytes(tag)?,
    })
}

fn copy_bytes(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseMac0Error> {
    let mut owned = Zeroizing::new(Vec::new());
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| CoseMac0ErrorReason::ResourceLimitExceeded)?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}
