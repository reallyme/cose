// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::generated::proto::reallyme::cose::v1::{
    CoseKeyFromPrivateBytesRequest, CoseMultikeyToCoseKeyRequest,
};
use buffa::{bytes::Buf, DecodeError, Message};

#[test]
fn repeated_private_key_fields_preserve_last_value_semantics() -> Result<(), DecodeError> {
    let first = CoseKeyFromPrivateBytesRequest {
        private_key: vec![0x55; 32],
        algorithm: Default::default(),
        public_key: Vec::new(),
        has_public_key: false,
        __buffa_unknown_fields: Default::default(),
    };
    for replacement in [vec![], vec![0xaa; 8], vec![0xbb; 4096]] {
        // Include an explicit empty field: ordinary encoding omits defaults.
        let mut wire = first.encode_to_vec();
        if replacement.is_empty() {
            wire.extend_from_slice(&[0x12, 0x00]);
        } else {
            wire.extend_from_slice(
                &CoseKeyFromPrivateBytesRequest {
                    private_key: replacement.clone(),
                    algorithm: Default::default(),
                    public_key: Vec::new(),
                    has_public_key: false,
                    __buffa_unknown_fields: Default::default(),
                }
                .encode_to_vec(),
            );
        }
        let parsed = CoseKeyFromPrivateBytesRequest::decode_from_slice(&wire)?;
        assert_eq!(parsed.private_key, replacement);
    }
    Ok(())
}

#[test]
fn fragmented_string_fields_validate_utf8_across_chunks() -> Result<(), DecodeError> {
    let mut value = String::from("previous identifier");
    let mut fragmented = (&[3, 0xe2][..]).chain(&[0x82, 0xac][..]);
    super::merge_string(&mut value, &mut fragmented)?;
    assert_eq!(value, "€");
    let mut invalid = (&[2, 0xc3][..]).chain(&[0x28][..]);
    assert_eq!(
        super::merge_string(&mut value, &mut invalid),
        Err(DecodeError::InvalidUtf8)
    );
    Ok(())
}

#[test]
fn repeated_string_fields_and_malformed_replacements() -> Result<(), DecodeError> {
    let request = CoseMultikeyToCoseKeyRequest {
        multikey: String::from("previous identifier"),
        __buffa_unknown_fields: Default::default(),
    };
    let mut wire = request.encode_to_vec();
    wire.extend_from_slice(&[0x0a, 0x01, b'z']);
    assert_eq!(
        CoseMultikeyToCoseKeyRequest::decode_from_slice(&wire)?.multikey,
        "z"
    );
    wire.extend_from_slice(&[0x0a, 0x01, 0xff]);
    assert!(CoseMultikeyToCoseKeyRequest::decode_from_slice(&wire).is_err());
    Ok(())
}

#[test]
fn contiguous_string_merge_reuses_destination_allocation() -> Result<(), DecodeError> {
    let mut value = String::from("previous identifier");
    let allocation = value.as_ptr();
    super::merge_string(&mut value, &mut &[3, 0xe2, 0x82, 0xac][..])?;
    assert_eq!(value, "€");
    assert_eq!(value.as_ptr(), allocation);
    super::merge_string(&mut value, &mut &[0][..])?;
    assert!(value.is_empty());
    Ok(())
}

#[test]
fn malformed_lengths_keep_decode_errors_and_clear_previous_fields() {
    for encoded in [&[][..], &[0x80][..], &[4, b'a'][..], &[0xff; 11][..]] {
        let mut reference_bytes = Vec::new();
        let mut reference_input = encoded;
        let expected = buffa::types::merge_bytes(&mut reference_bytes, &mut reference_input);
        assert!(expected.is_err());

        let mut bytes = b"previous private key".to_vec();
        let mut input = encoded;
        assert_eq!(super::merge_bytes(&mut bytes, &mut input), expected);
        assert_eq!(input, reference_input);
        assert!(bytes.is_empty());

        let mut text = String::from("previous identifier");
        let mut input = encoded;
        assert_eq!(super::merge_string(&mut text, &mut input), expected);
        assert_eq!(input, reference_input);
        assert!(text.is_empty());
    }
}

#[test]
fn tiny_replacements_do_not_repeatedly_wipe_a_large_retained_capacity() -> Result<(), DecodeError> {
    let mut bytes = vec![0x55; 65_536];
    let mut text = "x".repeat(65_536);
    for index in 0..100 {
        super::merge_bytes(&mut bytes, &mut &[0][..])?;
        super::merge_string(&mut text, &mut &[0][..])?;
        if index > 0 {
            // An allocation bound makes this regression deterministic; wall
            // clock tests would be noisy and could miss quadratic wiping.
            assert_eq!(bytes.capacity(), 0);
            assert_eq!(text.capacity(), 0);
        }
    }
    Ok(())
}
