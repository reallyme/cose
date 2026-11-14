// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem::ManuallyDrop;

use ciborium::value::Value;

use super::x5chain_array_entries;

#[kani::proof]
#[kani::unwind(6)]
fn x5chain_wire_array_iteration_preserves_each_certificate_position() {
    let first: [u8; 2] = kani::any();
    let second: [u8; 2] = kani::any();
    let third: [u8; 2] = kani::any();
    let has_third: bool = kani::any();
    // The traversal borrows the parsed array. Cleanup of the synthetic CBOR
    // values is outside the property about the sequence of borrowed bytes.
    let values = ManuallyDrop::new([
        Value::Bytes(first.to_vec()),
        Value::Bytes(second.to_vec()),
        Value::Bytes(third.to_vec()),
    ]);
    let wire_order = if has_third { &values[..] } else { &values[..2] };
    let mut certificates = x5chain_array_entries(wire_order);

    assert!(certificates.next() == Some(Ok(first.as_slice())));
    assert!(certificates.next() == Some(Ok(second.as_slice())));
    if has_third {
        assert!(certificates.next() == Some(Ok(third.as_slice())));
    }
    assert!(certificates.next().is_none());
    kani::cover!(
        !has_third && first > second,
        "descending two-certificate array"
    );
    kani::cover!(
        has_third && first > second && second < third,
        "three-certificate array with interior minimum"
    );
    kani::cover!(
        has_third && first == second && second == third,
        "repeated certificates keep each position"
    );
}
