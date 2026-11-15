// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{backend_signature_from_cose, read_der_integer, read_der_length};
use crate::{Algorithm, CoseError};

#[kani::proof]
fn der_signature_lengths_use_only_minimal_supported_forms() {
    let first: u8 = kani::any();
    let second: u8 = kani::any();
    let include_second: bool = kani::any();
    let bytes = [first, second];
    let input = if include_second {
        &bytes[..]
    } else {
        &bytes[..1]
    };
    let expected = match (first, second, include_second) {
        (0..=127, _, _) => Ok((usize::from(first), 1)),
        (129, 128..=255, true) => Ok((usize::from(second), 2)),
        _ => Err(CoseError::InvalidSignature),
    };
    assert!(read_der_length(input, 0) == expected);
    kani::cover!(first == 127, "largest short-form length");
    kani::cover!(
        first == 129 && second == 128 && include_second,
        "first canonical long-form length"
    );
    kani::cover!(
        first == 129 && second < 128 && include_second,
        "nonminimal length is rejected"
    );
    kani::cover!(
        first == 129 && !include_second,
        "truncated length is rejected"
    );
}

#[kani::proof]
#[kani::unwind(8)]
fn der_signature_scalars_require_positive_minimal_integer_contents() {
    let tag: u8 = kani::any();
    let first: u8 = kani::any();
    let second: u8 = kani::any();
    let one_byte: bool = kani::any();
    let coordinate_len = usize::from(kani::any::<u8>());
    let len = if one_byte { 1 } else { 2 };
    let source = [tag, len, first, second];
    let bytes = if one_byte { &source[..3] } else { &source[..] };
    let value = match (tag, one_byte, first, second) {
        (2, true, 1..=127, _) => Some(&bytes[2..]),
        (2, false, 0, 128..=255) => Some(&bytes[3..]),
        (2, false, 1..=127, _) => Some(&bytes[2..]),
        _ => None,
    };
    let expected = value
        .filter(|scalar| scalar.len() <= coordinate_len)
        .map(|scalar| (scalar, bytes.len()))
        .ok_or(CoseError::InvalidSignature);
    assert!(read_der_integer(bytes, 0, coordinate_len) == expected);
    kani::cover!(
        tag == 2 && !one_byte && first == 0 && second == 128 && coordinate_len == 1,
        "a single positive sign pad is retained only on the wire"
    );
    kani::cover!(
        tag == 2 && !one_byte && first == 0 && second == 127,
        "redundant leading zero is rejected"
    );
    kani::cover!(
        tag == 2 && one_byte && first == 0,
        "a zero scalar is rejected"
    );
    kani::cover!(tag == 2 && first >= 128, "negative scalar is rejected");
}

#[kani::proof]
#[kani::unwind(8)]
fn der_signature_dispatch_rejects_every_wrong_bounded_raw_width() {
    let (algorithm, coordinate_len, raw_len) = curve();
    let len = usize::from(kani::any::<u8>());
    let bytes = [0_u8; 133];
    kani::assume(len <= bytes.len() && len != raw_len);
    assert!(matches!(
        backend_signature_from_cose(algorithm, &bytes[..len]),
        Err(CoseError::InvalidSignatureEncoding)
    ));
    kani::cover!(
        coordinate_len == 32 && len == 65,
        "P-256 rejects a trailing raw byte"
    );
    kani::cover!(
        coordinate_len == 48 && len == 95,
        "P-384 rejects a truncated signature"
    );
    kani::cover!(
        coordinate_len == 66 && len == 133,
        "P-521 rejects a trailing raw byte"
    );
}

fn curve() -> (Algorithm, usize, usize) {
    let selector: u8 = kani::any();
    kani::assume(selector < 3);
    match selector {
        0 => (Algorithm::P256, 32, 64),
        1 => (Algorithm::P384, 48, 96),
        _ => (Algorithm::P521, 66, 132),
    }
}
