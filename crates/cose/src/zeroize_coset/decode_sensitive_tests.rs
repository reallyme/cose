// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::CoseError;

use super::SensitiveCborValue;

const HOSTILE_NESTING_DEPTH: usize = 40;

#[test]
fn decode_cose_key_rejects_excessive_nesting_before_tree_decode() {
    let mut encoded = Vec::with_capacity(HOSTILE_NESTING_DEPTH.saturating_add(1));
    encoded.extend(core::iter::repeat_n(0x81, HOSTILE_NESTING_DEPTH));
    encoded.push(0xf6);

    assert!(matches!(
        SensitiveCborValue::decode_cose_key(&encoded),
        Err(CoseError::ResourceLimitExceeded),
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn codec_receipts_convert_into_a_recursively_wiping_owner() -> Result<(), CoseError> {
    use ciborium::value::Value;
    use zeroize::ZeroizeOnDrop;

    fn requires_wiping_owner<T: ZeroizeOnDrop>() {}
    requires_wiping_owner::<SensitiveCborValue>();

    let encoded = b"\xa2\x01\xa1\x61k\x41a\x02\x82\x41b\x61c";
    let mut owner = SensitiveCborValue::decode_cose_key(encoded)?;
    super::zeroize_value(owner.value_mut());
    assert_eq!(
        owner.value(),
        &Value::Map(vec![
            (
                1.into(),
                Value::Map(vec![(Value::Text(String::new()), Value::Bytes(Vec::new()))])
            ),
            (
                2.into(),
                Value::Array(vec![Value::Bytes(Vec::new()), Value::Text(String::new())])
            ),
        ])
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn invalid_utf8_is_rejected_without_copying_sensitive_prefixes() {
    let encoded = b"\xa2\x01\x41a\x61\xff\x00";
    let allocations = allocation_counter::measure(|| {
        assert_eq!(
            SensitiveCborValue::decode_cose_key(encoded).err(),
            Some(CoseError::Cbor)
        );
    });
    assert_eq!(allocations.count_total, 0);
}
