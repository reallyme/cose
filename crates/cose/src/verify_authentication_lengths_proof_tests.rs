// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem::ManuallyDrop;

use super::{append_bstr, checked_bstr_size};

#[kani::proof]
fn authentication_byte_string_size_agrees_with_wide_arithmetic() {
    let current: usize = kani::any();
    let payload_len: usize = kani::any();
    let header_bytes = match payload_len {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    };
    // On the verifier's 64-bit target these two input sizes and the largest
    // CBOR prefix fit in u128, so this is independent of usize overflow.
    let expected = u128::try_from(current)
        .ok()
        .zip(u128::try_from(payload_len).ok())
        .and_then(|(prefix, payload)| prefix.checked_add(payload))
        .and_then(|total| total.checked_add(header_bytes))
        .and_then(|total| usize::try_from(total).ok());
    let actual = checked_bstr_size(current, payload_len);
    assert!(actual == expected);
    kani::cover!(
        actual == Some(usize::MAX),
        "the largest representable total succeeds"
    );
    kani::cover!(actual.is_none(), "size overflow is rejected");
    kani::cover!(
        current == 0 && payload_len == 4_294_967_296 && actual.is_some(),
        "64-bit CBOR length prefix is counted"
    );
}

#[kani::proof]
#[kani::unwind(24)]
fn authentication_byte_string_preserves_23_bytes() {
    check_boundary_bstr::<23>(&[0x57]);
}

#[kani::proof]
#[kani::unwind(24)]
fn authentication_byte_string_preserves_24_bytes() {
    check_boundary_bstr::<24>(&[0x58, 0x18]);
}

#[kani::proof]
#[kani::unwind(24)]
fn authentication_byte_string_preserves_255_bytes() {
    check_boundary_bstr::<255>(&[0x58, 0xff]);
}

#[kani::proof]
#[kani::unwind(24)]
fn authentication_byte_string_preserves_256_bytes() {
    check_boundary_bstr::<256>(&[0x59, 0x01, 0x00]);
}

fn check_boundary_bstr<const LENGTH: usize>(prefix: &[u8]) {
    // Materialize 256 arbitrary bytes from sixteen unconstrained words.
    // Fixed-size harnesses let the verifier resolve each copy's length.
    let words: [u128; 16] = kani::any();
    let bytes = words.map(u128::to_ne_bytes);
    let data = &bytes.as_flattened()[..LENGTH];
    let existing: [u8; 2] = kani::any();
    let Some(body_start) = existing.len().checked_add(prefix.len()) else {
        assert!(false, "bounded prefix length must fit");
        return;
    };
    let Some(end) = body_start.checked_add(LENGTH) else {
        assert!(false, "bounded output length must fit");
        return;
    };

    // Cleanup of the synthetic data is outside this encoding property.
    let mut output = ManuallyDrop::new(Vec::with_capacity(end));
    output.extend_from_slice(&existing);
    assert!(append_bstr(&mut output, data).is_ok());
    assert!(output.len() == end);
    assert!(output.get(..existing.len()) == Some(existing.as_slice()));
    assert!(output.get(existing.len()..body_start) == Some(prefix));

    // A universally quantified index checks every byte in the body without
    // introducing a comparison loop whose bound depends on the field size.
    let index = usize::from(kani::any::<u8>());
    if let Some(expected) = data.get(index) {
        let Some(offset) = body_start.checked_add(index) else {
            assert!(false, "bounded content position must fit");
            return;
        };
        assert!(output.get(offset) == Some(expected));
    }
    kani::cover!(
        index.checked_add(1) == Some(LENGTH),
        "the last byte of the field is checked"
    );
}
