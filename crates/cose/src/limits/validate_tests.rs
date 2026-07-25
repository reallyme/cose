// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::validate::{validate_cbor_bytes, CborItemRole};
use crate::CoseError;

const LARGE_MAP_ENTRIES: u64 = 1_024;

#[test]
fn large_map_with_unique_raw_keys_validates_linearly() {
    let cbor = integer_key_map(LARGE_MAP_ENTRIES, None);
    assert_eq!(
        validate_cbor_bytes(&cbor, cbor.len(), CborItemRole::Normal),
        Ok(()),
    );
}

#[test]
fn large_map_with_late_duplicate_raw_key_is_rejected() {
    let unique_entries = LARGE_MAP_ENTRIES.saturating_sub(1);
    let duplicate_key = unique_entries.saturating_sub(1);
    let cbor = integer_key_map(unique_entries, Some(duplicate_key));
    assert_eq!(
        validate_cbor_bytes(&cbor, cbor.len(), CborItemRole::Normal),
        Err(CoseError::DuplicateMapLabel),
    );
}

#[test]
fn impossible_map_length_is_rejected_before_key_tracking_allocation() {
    let mut cbor = vec![0xbb];
    cbor.extend_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        validate_cbor_bytes(&cbor, cbor.len(), CborItemRole::Normal),
        Err(CoseError::Cbor | CoseError::ResourceLimitExceeded),
    ));
}

#[test]
fn collection_over_limit_is_rejected_before_key_tracking_allocation() {
    let cbor = integer_key_map(LARGE_MAP_ENTRIES + 1, None);
    assert_eq!(
        validate_cbor_bytes(&cbor, cbor.len(), CborItemRole::Normal),
        Err(CoseError::ResourceLimitExceeded),
    );
}

#[test]
fn overlong_simple_value_is_non_canonical() {
    assert_eq!(
        validate_cbor_bytes(&[0xf8, 0x00], 2, CborItemRole::Normal),
        Err(CoseError::NonCanonicalCbor),
    );
}

#[test]
fn floating_point_extension_values_are_rejected() {
    let encodings: [&[u8]; 3] = [
        &[0xf9, 0x3c, 0x00],
        &[0xfa, 0x3f, 0x80, 0x00, 0x00],
        &[0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    for encoding in encodings {
        assert_eq!(
            validate_cbor_bytes(encoding, encoding.len(), CborItemRole::Normal),
            Err(CoseError::NonCanonicalCbor),
        );
    }
}

#[test]
fn invalid_utf8_is_rejected_before_sensitive_tree_decode() {
    // The first map value models a private parameter that a tree decoder would
    // allocate before reaching the malformed text label. Pre-validation must
    // reject the label so no partially decoded sensitive tree can be dropped
    // through ciborium's ordinary, non-zeroizing error path.
    let cbor = [0xa2, 0x23, 0x41, 0xaa, 0x61, 0xff, 0x00];
    assert_eq!(
        validate_cbor_bytes(&cbor, cbor.len(), CborItemRole::CoseKeyTop),
        Err(CoseError::Cbor),
    );
}

#[test]
fn cose_key_map_uses_core_deterministic_bytewise_key_order() {
    // {24: null, -1: null}. The encoded key 0x18 0x18 sorts before 0x20
    // under RFC 8949 core deterministic bytewise ordering.
    let cbor = [0xa2, 0x18, 0x18, 0xf6, 0x20, 0xf6];
    assert_eq!(
        validate_cbor_bytes(&cbor, cbor.len(), CborItemRole::CoseKeyTop),
        Ok(()),
    );
}

#[test]
fn cose_key_map_rejects_length_first_order_that_violates_core_deterministic_order() {
    let cbor = [0xa2, 0x20, 0xf6, 0x18, 0x18, 0xf6];
    assert_eq!(
        validate_cbor_bytes(&cbor, cbor.len(), CborItemRole::CoseKeyTop),
        Err(CoseError::NonCanonicalCbor),
    );
}

fn integer_key_map(unique_entries: u64, duplicate_key: Option<u64>) -> Vec<u8> {
    let total_entries = unique_entries + u64::from(duplicate_key.is_some());
    let mut cbor = Vec::new();
    append_major(&mut cbor, 5, total_entries);
    for key in 0..unique_entries {
        append_major(&mut cbor, 0, key);
        cbor.push(0xf6);
    }
    if let Some(key) = duplicate_key {
        append_major(&mut cbor, 0, key);
        cbor.push(0xf6);
    }
    cbor
}

fn append_major(output: &mut Vec<u8>, major: u8, value: u64) {
    let major_bits = major << 5;
    match value {
        0..=23 => output.push(major_bits | u8::try_from(value).unwrap_or(0)),
        24..=0xff => {
            output.push(major_bits | 24);
            output.push(u8::try_from(value).unwrap_or(0));
        }
        0x100..=0xffff => {
            output.push(major_bits | 25);
            output.extend_from_slice(&u16::try_from(value).unwrap_or(0).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(major_bits | 26);
            output.extend_from_slice(&u32::try_from(value).unwrap_or(0).to_be_bytes());
        }
        _ => {
            output.push(major_bits | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}
