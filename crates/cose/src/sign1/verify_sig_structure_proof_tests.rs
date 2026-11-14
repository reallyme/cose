// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use coset::{Header, ProtectedHeader};

use super::build_received_sig_structure;
use crate::CoseError;

#[kani::proof]
fn signature1_structure_requires_received_protected_bytes() {
    let result = build_received_sig_structure(&ProtectedHeader::default(), &[], &[]);
    assert!(matches!(result, Err(CoseError::InvalidFormat)));
    kani::cover!(result.is_err(), "missing original bytes are rejected");
}

#[kani::proof]
#[kani::unwind(24)]
fn signature1_structure_preserves_original_bytes_and_field_order() {
    // The original bstr contains kid before alg. Keep the identifier, AAD
    // and payload symbolic so a constant or swapped field fails the proof.
    let kid: u8 = kani::any();
    let aad: u8 = kani::any();
    let payload: u8 = kani::any();
    let protected = [0xa2, 0x04, 0x41, kid, 0x01, 0x27];
    let received = ProtectedHeader {
        original_data: Some(protected.to_vec()),
        header: Header::default(),
    };

    let result = build_received_sig_structure(&received, &[aad], &[payload]);
    assert!(result.is_ok());
    if let Ok(encoded) = result {
        // Independent RFC 9052 encoding for this bounded input.
        let mut expected = *b"\x84\x6aSignature1\x46\xa2\x04\x41\x00\x01\x27\x41\x00\x41\x00";
        expected[16] = kid;
        expected[20] = aad;
        expected[22] = payload;
        assert!(encoded.as_slice() == expected);
        kani::cover!(
            kid == 1 && aad == 2 && payload == 3,
            "distinct protected kid, AAD and payload bytes reach encoding success"
        );
    }
}
