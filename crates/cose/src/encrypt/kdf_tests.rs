// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::kmac::KMAC256_MAX_CONTEXT_LENGTH;

use super::{derive_key, encode_kdf_context};
use crate::CoseError;

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
