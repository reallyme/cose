// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::checked_bstr_size;

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
