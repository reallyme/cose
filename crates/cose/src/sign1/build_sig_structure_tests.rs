// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::build_sig_structure;
use crate::limits::MAX_DETACHED_PAYLOAD_BYTES;
use crate::CoseError;

#[test]
fn encodes_the_canonical_cose_signature1_structure() -> Result<(), CoseError> {
    let encoded = build_sig_structure(&[0xa1, 0x01, 0x27], &[0x01], b"payload")?;

    assert_eq!(
        encoded.as_slice(),
        [
            0x84, 0x6a, b'S', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b'1', 0x43, 0xa1,
            0x01, 0x27, 0x41, 0x01, 0x47, b'p', b'a', b'y', b'l', b'o', b'a', b'd',
        ]
    );
    Ok(())
}

#[test]
fn accepts_the_documented_maximum_payload() -> Result<(), CoseError> {
    let payload = vec![0x5a; MAX_DETACHED_PAYLOAD_BYTES];
    let encoded = build_sig_structure(&[], &[], &payload)?;

    let payload_header_offset = 14;
    assert_eq!(
        &encoded[payload_header_offset..payload_header_offset + 5],
        &[0x5a, 0x00, 0x10, 0x00, 0x00]
    );
    assert_eq!(encoded.len(), payload.len() + payload_header_offset + 5);
    Ok(())
}
