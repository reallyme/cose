// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::kmac::{derive_kmac256, Kmac256Key, KMAC256_MAX_CONTEXT_LENGTH};
use zeroize::Zeroizing;

use super::{derive_key, enc_structure, encode_kdf_context};
use crate::CoseError;

const BSTR_WIDTHS: [(usize, &[u8]); 5] = [
    (0, b"\x40"),
    (23, b"\x57"),
    (24, b"\x58\x18"),
    (255, b"\x58\xff"),
    (256, b"\x59\x01\x00"),
];

#[test]
fn oversized_encoded_context_has_a_resource_limit_error() {
    let supp_priv_info = vec![0x55; KMAC256_MAX_CONTEXT_LENGTH];
    let result = derive_key(&[0x33; 32], -65537, 32, &[0xa0], Some(&supp_priv_info));
    assert!(matches!(result, Err(CoseError::ResourceLimitExceeded)));
}

#[test]
fn context_bytes_bind_algorithm_output_bits_and_protected_header() {
    const EXPECTED: &[u8] = &[
        0x83, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x82, 0x19, 0x01, 0x00, 0x41, 0xa0, 0x42, 0x01, 0x02,
    ];
    let actual = encode_kdf_context(-65_537, 32, &[0xa0], Some(&[1, 2]));
    assert_eq!(actual.as_ref().map(|bytes| bytes.as_slice()), Ok(EXPECTED));
}

#[test]
fn context_matches_independent_cbor_across_integer_and_byte_string_widths() -> Result<(), CoseError>
{
    // The expected headers come from the RFC 8949 integer and bstr forms.
    // A hand-written fixture keeps them independent of the COSE serializer.
    const ALGORITHMS: [(i64, &[u8]); 9] = [
        (1, b"\x01"),
        (2, b"\x02"),
        (3, b"\x03"),
        (-3, b"\x22"),
        (-4, b"\x23"),
        (-5, b"\x24"),
        (-65_537, b"\x3a\x00\x01\x00\x00"),
        (i64::MIN, b"\x3b\x7f\xff\xff\xff\xff\xff\xff\xff"),
        (i64::MAX, b"\x1b\x7f\xff\xff\xff\xff\xff\xff\xff"),
    ];
    const OUTPUT_LENGTHS: [(usize, &[u8]); 5] = [
        (2, b"\x10"),
        (3, b"\x18\x18"),
        (16, b"\x18\x80"),
        (24, b"\x18\xc0"),
        (32, b"\x19\x01\x00"),
    ];
    let protected: Vec<u8> = (u8::MIN..=u8::MAX).collect();
    let private = Zeroizing::new((u8::MIN..=u8::MAX).rev().collect::<Vec<_>>());
    for (algorithm, algorithm_cbor) in ALGORITHMS {
        for (output_length, bits_cbor) in OUTPUT_LENGTHS {
            for (protected_len, protected_head) in BSTR_WIDTHS {
                let protected = &protected[..protected_len];
                let mut expected = Zeroizing::new(vec![0x82]);
                expected.extend_from_slice(algorithm_cbor);
                expected.push(0x82);
                expected.extend_from_slice(bits_cbor);
                expected.extend_from_slice(protected_head);
                expected.extend_from_slice(protected);
                let actual = encode_kdf_context(algorithm, output_length, protected, None)?;
                assert_eq!(actual.as_slice(), expected.as_slice());

                for (private_len, private_head) in BSTR_WIDTHS {
                    let private = &private[..private_len];
                    let mut expected = expected.clone();
                    expected[0] = 0x83;
                    expected.extend_from_slice(private_head);
                    expected.extend_from_slice(private);
                    let actual =
                        encode_kdf_context(algorithm, output_length, protected, Some(private))?;
                    assert_eq!(actual.as_slice(), expected.as_slice());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn enc_structure_matches_independent_cbor_at_both_byte_string_boundaries() -> Result<(), CoseError>
{
    let protected: Vec<u8> = (u8::MIN..=u8::MAX).collect();
    let aad: Vec<u8> = (u8::MIN..=u8::MAX).rev().collect();
    for (protected_len, protected_head) in BSTR_WIDTHS {
        for (aad_len, aad_head) in BSTR_WIDTHS {
            let protected = &protected[..protected_len];
            let aad = &aad[..aad_len];
            let mut expected = b"\x83\x67Encrypt".to_vec();
            expected.extend_from_slice(protected_head);
            expected.extend_from_slice(protected);
            expected.extend_from_slice(aad_head);
            expected.extend_from_slice(aad);
            assert_eq!(enc_structure(protected, aad)?.as_slice(), expected);
        }
    }
    Ok(())
}

#[test]
fn context_and_output_length_reach_kmac_with_empty_customization() -> Result<(), CoseError> {
    let secret = Zeroizing::new([0x31; 32]);
    let key = Kmac256Key::from_slice(secret.as_slice()).map_err(|_| CoseError::Crypto)?;
    let expected_without_private = b"\x82\x23\x82\x18\xc0\x42\xa0\x00";
    let expected_with_empty_private = b"\x83\x23\x82\x18\xc0\x42\xa0\x00\x40";
    for (private, expected_context) in [
        (None, expected_without_private.as_slice()),
        (Some([].as_slice()), expected_with_empty_private.as_slice()),
    ] {
        let expected =
            derive_kmac256(&key, expected_context, &[], 24).map_err(|_| CoseError::Crypto)?;
        let actual = derive_key(secret.as_slice(), -4, 24, &[0xa0, 0x00], private)?;
        assert_eq!(actual.as_slice(), expected.as_bytes());
    }
    Ok(())
}
