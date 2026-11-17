// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;

use super::support::{codec_parity, reason, success};
use crate::api::contract::{
    cose_operation_request::Operation, cose_operation_result::Result as Branch, CoseErrorReason,
    CoseOpaqueBytes,
};
use crate::{containers::validate_preferred_cbor, CoseError};

fn text_map(entries: usize, reverse: bool, duplicate: bool) -> Result<Vec<u8>, CoseError> {
    let mut pairs = Vec::new();
    for index in 0..entries {
        // Long common prefixes exercise comparison work, not only the key
        // count. Decimal suffixes also differ from bytewise insertion order.
        let mut label = "issuer-extension-".repeat(4);
        let suffix = if duplicate && index.checked_add(1) == Some(entries) {
            0
        } else {
            index
        };
        label.push_str(&suffix.to_string());
        pairs.push((Value::Text(label), Value::Null));
    }
    if reverse {
        pairs.reverse();
    }
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&Value::Map(pairs), &mut encoded).map_err(|_| CoseError::Cbor)?;
    Ok(encoded)
}

fn operation(encoded: &[u8]) -> Operation {
    Operation::PreferredCborValidate(Box::new(CoseOpaqueBytes {
        encoded: encoded.to_vec().into(),
    }))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn preflight_accepts_300_and_1024_text_keys_in_received_order() -> Result<(), CoseError> {
    for entries in [299, 300, 301, 1_024] {
        for reverse in [false, true] {
            let encoded = text_map(entries, reverse, false)?;
            validate_preferred_cbor(&encoded)?;
            assert!(matches!(
                success(codec_parity(operation(&encoded))?),
                Branch::PreferredCborValidate(_)
            ));
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn wide_text_maps_keep_duplicate_and_entry_limits_in_every_transport() -> Result<(), CoseError> {
    for entries in [300, 1_024] {
        for reverse in [false, true] {
            let encoded = text_map(entries, reverse, true)?;
            assert_eq!(
                validate_preferred_cbor(&encoded),
                Err(CoseError::DuplicateMapLabel)
            );
            assert_eq!(
                reason(&codec_parity(operation(&encoded))?),
                CoseErrorReason::CommonDuplicateMapLabel
            );
        }
    }
    let over = text_map(1_025, false, false)?;
    assert_eq!(
        validate_preferred_cbor(&over),
        Err(CoseError::ResourceLimitExceeded)
    );
    assert_eq!(
        reason(&codec_parity(operation(&over))?),
        CoseErrorReason::CommonResourceLimitExceeded
    );
    Ok(())
}
