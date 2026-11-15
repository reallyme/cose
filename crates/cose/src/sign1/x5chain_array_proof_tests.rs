// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem::ManuallyDrop;

use ciborium::value::Value;

use super::{
    decode_x5chain, validate_x5chain_array_sizes, x5chain_array_entries, CoseError,
    MAX_COSE_X5CHAIN_CERTIFICATES, MAX_COSE_X5CHAIN_CERTIFICATE_BYTES,
    MAX_COSE_X5CHAIN_TOTAL_BYTES,
};

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

#[kani::proof]
#[kani::unwind(11)]
fn x5chain_wire_array_checks_every_declared_count_before_inspecting_entries() {
    let count: usize = kani::any();
    let count_allowed = (2..=MAX_COSE_X5CHAIN_CERTIFICATES).contains(&count);
    // Give the validator the full count domain without allocating an array.
    let sizes = core::iter::repeat_n((), count).map(|()| {
        assert!(
            count_allowed,
            "out-of-range counts must stop before reading entries"
        );
        Ok(1)
    });
    let result = validate_x5chain_array_sizes(sizes);
    let expected = match count {
        0 | 1 => Err(CoseError::InvalidFormat),
        n if n > MAX_COSE_X5CHAIN_CERTIFICATES => Err(CoseError::ResourceLimitExceeded),
        _ => Ok(()),
    };
    assert!(result == expected);
    kani::cover!(count == 0 && result.is_err(), "empty array");
    kani::cover!(count == 1 && result.is_err(), "single-entry array");
    kani::cover!(count == 2 && result.is_ok(), "minimum valid count");
    kani::cover!(
        count == MAX_COSE_X5CHAIN_CERTIFICATES && result.is_ok(),
        "maximum valid count"
    );
    kani::cover!(
        count > MAX_COSE_X5CHAIN_CERTIFICATES && result.is_err(),
        "excessive count"
    );
}

#[kani::proof]
#[kani::unwind(11)]
fn x5chain_wire_array_checks_each_certificate_and_the_complete_byte_budget() {
    let count: usize = kani::any();
    kani::assume((2..=MAX_COSE_X5CHAIN_CERTIFICATES).contains(&count));
    // Cover the full byte budget and every admissible individual length
    // without allocating the certificate bodies. None models a non-bstr.
    let sizes: [Option<u16>; MAX_COSE_X5CHAIN_CERTIFICATES] = kani::any();
    let relevant = &sizes[..count];
    let result = validate_x5chain_array_sizes(
        relevant
            .iter()
            .map(|size| size.map(usize::from).ok_or(CoseError::InvalidFormat)),
    );
    let well_formed = relevant
        .iter()
        .all(|size| size.is_some_and(|size| size != 0));
    let individually_bounded = relevant.iter().all(|size| {
        size.is_none_or(|size| usize::from(size) <= MAX_COSE_X5CHAIN_CERTIFICATE_BYTES)
    });
    let total: usize = relevant.iter().flatten().copied().map(usize::from).sum();
    let within_budget = individually_bounded && total <= MAX_COSE_X5CHAIN_TOTAL_BYTES;
    assert!(result.is_ok() == (well_formed && within_budget));
    if well_formed && !within_budget {
        assert!(result == Err(CoseError::ResourceLimitExceeded));
    }
    if !well_formed && within_budget {
        assert!(result == Err(CoseError::InvalidFormat));
    }

    kani::cover!(
        well_formed && total == MAX_COSE_X5CHAIN_TOTAL_BYTES && result.is_ok(),
        "exact byte budget"
    );
    kani::cover!(
        well_formed
            && individually_bounded
            && total == MAX_COSE_X5CHAIN_TOTAL_BYTES + 1
            && result.is_err(),
        "aggregate budget exceeded by one byte"
    );
    kani::cover!(
        well_formed
            && !individually_bounded
            && total <= MAX_COSE_X5CHAIN_TOTAL_BYTES
            && result.is_err(),
        "one certificate exceeds its limit before the aggregate does"
    );
    kani::cover!(
        !well_formed && within_budget && relevant.contains(&None) && result.is_err(),
        "non-bstr certificate"
    );
    kani::cover!(
        !well_formed && within_budget && relevant.contains(&Some(0)) && result.is_err(),
        "empty byte-string certificate"
    );
}

#[kani::proof]
#[kani::unwind(4)]
fn x5chain_wire_array_checks_the_full_certificate_length_domain() {
    let size: usize = kani::any();
    let result = validate_x5chain_array_sizes([Ok(1), Ok(size)].into_iter());
    let expected = if size == 0 {
        Err(CoseError::InvalidFormat)
    } else if size > MAX_COSE_X5CHAIN_CERTIFICATE_BYTES {
        Err(CoseError::ResourceLimitExceeded)
    } else {
        Ok(())
    };
    assert!(result == expected);
    kani::cover!(
        size == MAX_COSE_X5CHAIN_CERTIFICATE_BYTES && result.is_ok(),
        "exact certificate size limit"
    );
    kani::cover!(
        size == MAX_COSE_X5CHAIN_CERTIFICATE_BYTES + 1 && result.is_err(),
        "certificate one byte over limit"
    );
    kani::cover!(
        size == usize::MAX && result.is_err(),
        "maximum machine length is rejected"
    );
}

#[kani::proof]
#[kani::unwind(5)]
#[kani::stub(super::copy_validated_x5chain, unexpected_copy)]
fn x5chain_wire_array_rejects_a_late_malformed_entry_before_copying() {
    let empty: bool = kani::any();
    let invalid = if empty {
        Value::Bytes(Vec::new())
    } else {
        Value::Null
    };
    let value = ManuallyDrop::new(Value::Array(vec![Value::Bytes(vec![0x51]), invalid]));
    let result = ManuallyDrop::new(decode_x5chain(&value));
    assert!(matches!(&*result, Err(CoseError::InvalidFormat)));
    kani::cover!(empty && result.is_err(), "empty late certificate");
    kani::cover!(!empty && result.is_err(), "non-bstr late certificate");
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn unexpected_copy(_value: &Value) -> Result<Vec<Vec<u8>>, CoseError> {
    assert!(
        false,
        "a malformed array must stop before making a certificate copy"
    );
    Err(CoseError::InvalidFormat)
}
