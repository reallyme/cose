// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use zeroize::Zeroizing;

use crate::zeroize_coset::SensitiveCborValue;
use crate::CoseError;

use super::{Iso18013CryptoVerifier, Iso18013SignatureSuite};

const KEY_TYPE_LABEL: i64 = 1;
const KEY_ID_LABEL: i64 = 2;
const ALGORITHM_LABEL: i64 = 3;
const KEY_OPERATIONS_LABEL: i64 = 4;
const BASE_IV_LABEL: i64 = 5;
const CURVE_LABEL: i64 = -1;
const X_LABEL: i64 = -2;
const Y_LABEL: i64 = -3;
const EC2_KEY_TYPE: i64 = 2;
const OKP_KEY_TYPE: i64 = 1;
const VERIFY_OPERATION: i64 = 2;
const SIGN_OPERATION: i64 = 1;
const SEC1_PREFIX_BYTES: usize = 1;
const SEC1_COMPRESSED_EVEN: u8 = 2;
const SEC1_COMPRESSED_ODD: u8 = 3;
const SEC1_UNCOMPRESSED: u8 = 4;

type Entry = (Value, Value);

pub(super) fn import(
    suite: Iso18013SignatureSuite,
    encoded: &[u8],
) -> Result<Iso18013CryptoVerifier, CoseError> {
    let tree = SensitiveCborValue::decode_iso_cose_key(encoded)?;
    let Value::Map(entries) = tree.value() else {
        return Err(CoseError::InvalidFormat);
    };
    for (label, value) in entries {
        match integer(label)? {
            KEY_TYPE_LABEL | ALGORITHM_LABEL | CURVE_LABEL | X_LABEL | Y_LABEL => {}
            KEY_OPERATIONS_LABEL => validate_operations(value)?,
            KEY_ID_LABEL if matches!(value, Value::Bytes(_)) => {}
            BASE_IV_LABEL => {
                // Base IV is metadata. Only the public point is passed to the
                // verifier, with no IV-specific size requirement on this key.
                bytes(value)?;
            }
            // This is a public verification-key boundary. Private parameters
            // and unrelated key-family extensions must not become usable keys.
            _ => return Err(CoseError::InvalidKeyMaterial),
        }
    }
    if integer(required(entries, CURVE_LABEL)?)? != suite.curve().identifier() {
        return Err(CoseError::InvalidKeyMaterial);
    }
    if let Some(value) = find(entries, ALGORITHM_LABEL) {
        if integer(value)? != suite.algorithm().identifier() {
            return Err(CoseError::InvalidKeyMaterial);
        }
    }
    let x = bytes(required(entries, X_LABEL)?)?;
    let mut public = Zeroizing::new(Vec::new());
    if let Some(width) = suite.curve().coordinate_length() {
        if integer(required(entries, KEY_TYPE_LABEL)?)? != EC2_KEY_TYPE || x.len() != width {
            return Err(CoseError::InvalidKeyMaterial);
        }
        let capacity = width
            .checked_mul(2)
            .and_then(|size| size.checked_add(SEC1_PREFIX_BYTES))
            .ok_or(CoseError::ResourceLimitExceeded)?;
        public
            .try_reserve_exact(capacity)
            .map_err(|_| CoseError::ResourceLimitExceeded)?;
        match required(entries, Y_LABEL)? {
            Value::Bool(odd) => {
                public.push(if *odd {
                    SEC1_COMPRESSED_ODD
                } else {
                    SEC1_COMPRESSED_EVEN
                });
                public.extend_from_slice(x);
            }
            Value::Bytes(y) if y.len() == width => {
                public.push(SEC1_UNCOMPRESSED);
                public.extend_from_slice(x);
                public.extend_from_slice(y);
            }
            _ => return Err(CoseError::InvalidKeyMaterial),
        }
    } else {
        if integer(required(entries, KEY_TYPE_LABEL)?)? != OKP_KEY_TYPE
            || Some(x.len()) != suite.curve().okp_public_length()
            || find(entries, Y_LABEL).is_some()
        {
            return Err(CoseError::InvalidKeyMaterial);
        }
        public
            .try_reserve_exact(x.len())
            .map_err(|_| CoseError::ResourceLimitExceeded)?;
        public.extend_from_slice(x);
    }
    Iso18013CryptoVerifier::new(suite, public)
}

fn find(entries: &[Entry], label: i64) -> Option<&Value> {
    entries
        .iter()
        .find_map(|(key, value)| (integer(key).ok() == Some(label)).then_some(value))
}

fn required(entries: &[Entry], label: i64) -> Result<&Value, CoseError> {
    find(entries, label).ok_or(CoseError::MissingKeyMaterial)
}

fn integer(value: &Value) -> Result<i64, CoseError> {
    let Value::Integer(integer) = value else {
        return Err(CoseError::InvalidKeyMaterial);
    };
    i64::try_from(*integer).map_err(|_| CoseError::InvalidKeyMaterial)
}

fn bytes(value: &Value) -> Result<&[u8], CoseError> {
    let Value::Bytes(bytes) = value else {
        return Err(CoseError::InvalidKeyMaterial);
    };
    Ok(bytes)
}

fn validate_operations(value: &Value) -> Result<(), CoseError> {
    let Value::Array(operations) = value else {
        return Err(CoseError::InvalidKeyMaterial);
    };
    let mut verify = false;
    let mut sign = false;
    for operation in operations {
        let seen = match integer(operation)? {
            VERIFY_OPERATION => &mut verify,
            SIGN_OPERATION => &mut sign,
            _ => return Err(CoseError::InvalidKeyMaterial),
        };
        if *seen {
            return Err(CoseError::DuplicateMapLabel);
        }
        *seen = true;
    }
    if verify {
        Ok(())
    } else {
        Err(CoseError::InvalidKeyMaterial)
    }
}
