// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::panic)]

use crate::failure::{CoseFailureBranch, CoseFailureOrigin, CoseFailureReason};
use crate::limits::MAX_COSE_KEY_BYTES;
use crate::{Algorithm, CoseError};

use super::convert::{cose_key_from_public_bytes, cose_key_to_vec};
use super::parse::{parse_cose_key, CoseKeyParseInput, CoseKeyParseOutput};

const RFC_8032_ED25519_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

#[test]
fn semantic_parse_preserves_canonical_key_bytes() -> Result<(), CoseError> {
    let key = cose_key_from_public_bytes(Algorithm::Ed25519, &RFC_8032_ED25519_PUBLIC_KEY)?;
    let encoded = cose_key_to_vec(&key)?;

    let parsed = parse_cose_key(CoseKeyParseInput::new(&encoded))?;
    let reencoded = reencode(parsed)?;

    assert_eq!(reencoded.as_slice(), encoded.as_slice());
    Ok(())
}

#[test]
fn semantic_parse_rejects_empty_input_with_typed_error() {
    let failure = parse_cose_key(CoseKeyParseInput::new(&[])).err();

    assert_eq!(
        failure.map(|value| (value.origin(), value.branch(), value.reason())),
        Some((
            CoseFailureOrigin::Caller,
            CoseFailureBranch::Primitive,
            CoseFailureReason::CommonCbor,
        ))
    );
}

#[test]
fn semantic_parse_rejects_oversized_input_before_decode() {
    let oversized_len = match MAX_COSE_KEY_BYTES.checked_add(1) {
        Some(value) => value,
        None => panic!("COSE_Key test length overflowed"),
    };
    let oversized = vec![0_u8; oversized_len];

    let failure = parse_cose_key(CoseKeyParseInput::new(&oversized)).err();

    assert_eq!(
        failure.map(|value| (value.origin(), value.branch(), value.reason())),
        Some((
            CoseFailureOrigin::Caller,
            CoseFailureBranch::Primitive,
            CoseFailureReason::CommonResourceLimitExceeded,
        ))
    );
}

fn reencode(output: CoseKeyParseOutput) -> Result<zeroize::Zeroizing<Vec<u8>>, CoseError> {
    cose_key_to_vec(&output.into_key())
}
