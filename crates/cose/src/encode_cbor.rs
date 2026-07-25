// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fixed-allocation encoding for sensitive CBOR values.

use std::io::Cursor;

use ciborium::value::Value;
#[cfg(feature = "cose-crypto")]
use coset::AsCborValue;
use zeroize::Zeroizing;

use crate::zeroize_coset::SensitiveCborValue;
use crate::CoseError;

const MAX_CBOR_HEAD_BYTES: usize = 9;

/// Encode a sensitive CBOR tree without permitting output-buffer growth.
///
/// A checked recursive upper bound sizes the sole output allocation. Encoding
/// then writes into a fixed-size slice, so a serializer or dependency change
/// cannot leave stale sensitive prefixes in a freed allocation. The CBOR tree
/// is recursively wiped on every exit path.
pub(crate) fn encode_cbor_value(value: Value) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let sensitive = SensitiveCborValue::from_value(value);
    let capacity = encoded_upper_bound(sensitive.value())?;

    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    encoded.resize(capacity, 0);

    let written = {
        let mut writer = Cursor::new(encoded.as_mut_slice());
        ciborium::ser::into_writer(sensitive.value(), &mut writer).map_err(|_| CoseError::Cbor)?;
        usize::try_from(writer.position()).map_err(|_| CoseError::ResourceLimitExceeded)?
    };
    if written > capacity {
        return Err(CoseError::Cbor);
    }
    encoded.truncate(written);

    Ok(encoded)
}

fn encoded_upper_bound(value: &Value) -> Result<usize, CoseError> {
    match value {
        Value::Bytes(bytes) => upper_bound_for_bytes(bytes.len()),
        Value::Text(text) => upper_bound_for_bytes(text.len()),
        Value::Array(values) => {
            let mut size = MAX_CBOR_HEAD_BYTES;
            for value in values {
                size = size
                    .checked_add(encoded_upper_bound(value)?)
                    .ok_or(CoseError::ResourceLimitExceeded)?;
            }
            Ok(size)
        }
        Value::Map(entries) => {
            let mut size = MAX_CBOR_HEAD_BYTES;
            for (key, value) in entries {
                size = size
                    .checked_add(encoded_upper_bound(key)?)
                    .ok_or(CoseError::ResourceLimitExceeded)?;
                size = size
                    .checked_add(encoded_upper_bound(value)?)
                    .ok_or(CoseError::ResourceLimitExceeded)?;
            }
            Ok(size)
        }
        Value::Tag(_, tagged) => MAX_CBOR_HEAD_BYTES
            .checked_add(encoded_upper_bound(tagged)?)
            .ok_or(CoseError::ResourceLimitExceeded),
        Value::Integer(_) | Value::Float(_) => Ok(MAX_CBOR_HEAD_BYTES),
        Value::Bool(_) | Value::Null => Ok(1),
        // `ciborium::Value` is non-exhaustive. Dependency upgrades must review
        // the maximum encoding size of new variants before they are accepted.
        _ => Err(CoseError::Cbor),
    }
}

fn upper_bound_for_bytes(length: usize) -> Result<usize, CoseError> {
    MAX_CBOR_HEAD_BYTES
        .checked_add(length)
        .ok_or(CoseError::ResourceLimitExceeded)
}

/// Return the authenticated protected-header bytes under a zeroizing owner.
#[cfg(feature = "cose-crypto")]
pub(crate) fn encode_protected_header(
    protected: &coset::ProtectedHeader,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    if let Some(original) = &protected.original_data {
        return Ok(Zeroizing::new(original.clone()));
    }

    // Converting explicitly keeps the cloned header under a recursive wipe
    // owner. `CborSerializable::to_vec` would drop its intermediate tree
    // without clearing identifiers or extension bytes.
    let value = protected
        .header
        .clone()
        .to_cbor_value()
        .map_err(|_| CoseError::Cbor)?;
    encode_cbor_value(value)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "encode_cbor_tests.rs"]
mod tests;
