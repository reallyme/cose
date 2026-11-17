// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use ciborium::value::Value;
use reallyme_cose::sign1::build_sign1_signature_structure;
use reallyme_cose::CoseError;
use zeroize::Zeroizing;

fn independent_structure(
    protected: &[u8],
    aad: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let value = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut expected = Zeroizing::new(Vec::new());
    ciborium::ser::into_writer(&value, &mut *expected).map_err(|_| CoseError::Cbor)?;
    Ok(expected)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn public_helper_matches_rfc_signature1_bytes_with_empty_aad() -> Result<(), CoseError> {
    // RFC 9052 section 4.4, using the protected ES256 header and content from
    // the single-signer example in Appendix C.2.1. The context has four fields.
    let expected = b"\x84\x6aSignature1\x43\xa1\x01\x26\x40\x54This is the content.";
    let actual = build_sign1_signature_structure(
        &[0xa1, 0x01, 0x26],
        &[],
        b"This is the content.",
        expected.len(),
    )?;
    assert_eq!(actual.as_slice(), expected);
    assert_eq!(
        build_sign1_signature_structure(&[], &[], &[], 15)?.as_slice(),
        b"\x84\x6aSignature1\x40\x40\x40"
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn public_helper_preserves_protected_bytes_without_normalizing_maps() -> Result<(), CoseError> {
    for protected in [
        &[0xa2, 0x04, 0x41, 0xab, 0x01, 0x26][..],
        &[0xa1, 0x18, 0x01, 0x38, 0x06][..],
        &[][..],
    ] {
        let expected = independent_structure(protected, b"aad", b"payload")?;
        let actual =
            build_sign1_signature_structure(protected, b"aad", b"payload", expected.len())?;
        assert_eq!(actual, expected);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn public_helper_accepts_768_kib_headers_and_payloads_above_one_mib() -> Result<(), CoseError> {
    const PROTECTED_BYTES: usize = 786_432;
    const PAYLOAD_BYTES: usize = 1_048_577;
    const OUTPUT_BUDGET: usize = 2_097_152;
    let protected = Zeroizing::new(vec![0xa5; PROTECTED_BYTES]);
    let payload = Zeroizing::new(vec![0x42; PAYLOAD_BYTES]);
    let expected = independent_structure(&protected, &[], &payload)?;
    let actual = build_sign1_signature_structure(&protected, &[], &payload, OUTPUT_BUDGET)?;
    assert_eq!(actual, expected);
    assert!(actual.len() <= OUTPUT_BUDGET);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn public_helper_enforces_the_complete_output_budget_at_cbor_boundaries() -> Result<(), CoseError> {
    for length in [0, 1, 23, 24, 255, 256, 65_535, 65_536] {
        let field = Zeroizing::new(vec![0x55; length]);
        let expected = independent_structure(&field, b"aad", &field)?;
        let below = expected
            .len()
            .checked_sub(1)
            .ok_or(CoseError::ResourceLimitExceeded)?;
        for budget in [0, below] {
            assert_eq!(
                build_sign1_signature_structure(&field, b"aad", &field, budget).err(),
                Some(CoseError::ResourceLimitExceeded)
            );
        }
        assert_eq!(
            build_sign1_signature_structure(&field, b"aad", &field, expected.len())?,
            expected
        );
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn rejected_public_helper_budgets_allocate_nothing() {
    let allocations = allocation_counter::measure(|| {
        // The raw slices fit this budget, but the CBOR headers and fixed
        // context do not. Rejection must precede reservation and copying.
        assert_eq!(
            build_sign1_signature_structure(b"abc", &[], &[], 3).err(),
            Some(CoseError::ResourceLimitExceeded)
        );
        assert_eq!(
            build_sign1_signature_structure(&[], &[], &[], 0).err(),
            Some(CoseError::ResourceLimitExceeded)
        );
    });
    assert_eq!(allocations.count_total, 0);
    assert_eq!(allocations.bytes_total, 0);
}
