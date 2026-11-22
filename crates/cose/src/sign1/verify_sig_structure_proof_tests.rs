// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::ManuallyDrop;

use coset::{Header, ProtectedHeader};

use super::build_received_sig_structure;
use crate::CoseError;

const BOUNDARY_LENGTHS: [usize; 4] = [23, 24, 255, 256];
const MAX_BOUNDARY_LENGTH: usize = 256;
const CONTEXT: &[u8] = b"\x84\x6aSignature1";

#[kani::proof]
fn signature1_structure_requires_received_protected_bytes() {
    let result = build_received_sig_structure(&ProtectedHeader::default(), &[], &[]);
    assert!(matches!(result, Err(CoseError::InvalidFormat)));
    kani::cover!(result.is_err(), "missing original bytes are rejected");
}

#[kani::proof]
#[kani::stub(
    zeroize::optimization_barrier,
    crate::verify_zeroize_barrier_proof_tests::observe_barrier
)]
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

#[derive(Clone, Copy)]
struct Fields {
    inputs: [*const [u8]; 3],
    next: usize,
}

std::thread_local! {
    static EXPECTED_FIELDS: Cell<Option<Fields>> = const { Cell::new(None) };
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(crate::build_authentication_structure::append_bstr, observe_field)]
fn signature1_structure_forwards_boundary_slices_in_order() {
    let protected_len = boundary_length();
    let aad_len = boundary_length();
    let payload_len = boundary_length();
    let received = ManuallyDrop::new(ProtectedHeader {
        original_data: Some(vec![0x51; protected_len]),
        header: Header::default(),
    });
    let Some(protected) = received.original_data.as_deref() else {
        assert!(false, "fixture must have the original protected bytes");
        return;
    };
    let aad = [0x52; MAX_BOUNDARY_LENGTH];
    let payload = [0x53; MAX_BOUNDARY_LENGTH];
    let aad = &aad[..aad_len];
    let payload = &payload[..payload_len];
    EXPECTED_FIELDS.set(Some(Fields {
        inputs: [protected, aad, payload],
        next: 0,
    }));

    let result = ManuallyDrop::new(build_received_sig_structure(&received, aad, payload));
    assert!(matches!(&*result, Ok(encoded) if encoded.as_slice() == CONTEXT));
    assert!(EXPECTED_FIELDS
        .take()
        .is_some_and(|fields| fields.next == fields.inputs.len()));
    kani::cover!(
        protected_len == 23 && aad_len == 24 && payload_len == 255,
        "mixed prefix widths"
    );
    kani::cover!(
        protected_len == 256 && aad_len == 255 && payload_len == 24,
        "long protected header"
    );
    kani::cover!(
        protected_len == 24 && aad_len == 256 && payload_len == 23,
        "long external AAD"
    );
    kani::cover!(
        protected_len == 255 && aad_len == 23 && payload_len == 256,
        "long payload"
    );
}

fn boundary_length() -> usize {
    let case = usize::from(kani::any::<u8>());
    kani::assume(case < BOUNDARY_LENGTHS.len());
    BOUNDARY_LENGTHS[case]
}

// The separate byte-string proof checks the real append. Observe the full
// slice identity here so a shortened, substituted, or reordered input fails.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn observe_field(_encoded: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CoseError> {
    let mut fields = EXPECTED_FIELDS.get().ok_or(CoseError::InvalidFormat)?;
    let expected = fields
        .inputs
        .get(fields.next)
        .ok_or(CoseError::InvalidFormat)?;
    assert!(core::ptr::eq(*expected, bytes));
    fields.next = fields
        .next
        .checked_add(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    EXPECTED_FIELDS.set(Some(fields));
    Ok(())
}
