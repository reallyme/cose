// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem::ManuallyDrop;

use zeroize::Zeroizing;

use super::{
    ec2_public_bytes_from_params, iana, Algorithm, CoseError, Ec2Profile, Label, Value,
    P256_COORDINATE_BYTES,
};

const P256_PROFILE: Ec2Profile = Ec2Profile {
    curve: iana::EllipticCurve::P_256,
    alg: iana::Algorithm::ESP256,
    coordinate_len: P256_COORDINATE_BYTES,
};

#[kani::proof]
#[kani::unwind(36)]
#[kani::stub(super::validate_public_key, unexpected_full_point_validation)]
fn p256_compact_public_extraction_is_independent_of_private_scalar() {
    let x: [u8; 32] = kani::any();
    let d = Zeroizing::new(kani::any::<[u8; 32]>());
    let odd_y: bool = kani::any();
    let include_d: bool = kani::any();

    // The extractor borrows the parameter slice. Omitting the fixture's
    // recursive CBOR destructor keeps the model focused on the lookup.
    let params = ManuallyDrop::new([
        (Label::Int(-4), Value::Bytes(d.to_vec())),
        (Label::Int(-2), Value::Bytes(x.to_vec())),
        (Label::Int(-3), Value::Bool(odd_y)),
    ]);
    let start = usize::from(!include_d);
    let point = ec2_public_bytes_from_params(&params[start..], P256_PROFILE);
    assert!(point.is_ok());
    if let Ok(point) = point {
        assert!(point.len() == 33);
        assert!(point[0] == if odd_y { 0x03 } else { 0x02 });
        assert!(point.get(1..) == Some(x.as_slice()));
    }

    kani::cover!(
        include_d && odd_y && d[0] != x[0],
        "odd Y with distinct d and x"
    );
    kani::cover!(
        include_d && !odd_y && d[0] != x[0],
        "even Y with distinct d and x"
    );
    kani::cover!(!include_d, "the same public projection works with d absent");
}

#[kani::proof]
#[kani::unwind(36)]
#[kani::stub(super::validate_public_key, unexpected_full_point_validation)]
fn p256_private_scalar_does_not_substitute_for_a_missing_coordinate() {
    let x: [u8; 32] = kani::any();
    let d = Zeroizing::new(kani::any::<[u8; 32]>());
    let missing_x: bool = kani::any();
    let public_field = if missing_x {
        (Label::Int(-3), Value::Bool(kani::any()))
    } else {
        (Label::Int(-2), Value::Bytes(x.to_vec()))
    };
    let params = ManuallyDrop::new([(Label::Int(-4), Value::Bytes(d.to_vec())), public_field]);

    assert!(matches!(
        ec2_public_bytes_from_params(params.as_slice(), P256_PROFILE),
        Err(CoseError::MissingKeyMaterial)
    ));
    kani::cover!(missing_x, "d cannot supply a missing X coordinate");
    kani::cover!(!missing_x, "d cannot supply a missing Y coordinate");
}

#[kani::proof]
#[kani::unwind(36)]
#[kani::stub(super::validate_public_key, accept_full_point)]
fn p256_full_coordinate_extraction_is_independent_of_private_scalar() {
    let x: [u8; 32] = kani::any();
    let y: [u8; 32] = kani::any();
    let d = Zeroizing::new(kani::any::<[u8; 32]>());
    let odd_y = y[31] & 1 == 1;
    let params = ManuallyDrop::new([
        (Label::Int(-2), Value::Bytes(x.to_vec())),
        (Label::Int(-4), Value::Bytes(d.to_vec())),
        (Label::Int(-3), Value::Bytes(y.to_vec())),
    ]);

    let point = ec2_public_bytes_from_params(params.as_slice(), P256_PROFILE);
    assert!(point.is_ok());
    if let Ok(point) = point {
        assert!(point.len() == 33);
        assert!(point[0] == if odd_y { 0x03 } else { 0x02 });
        assert!(point.get(1..) == Some(x.as_slice()));
    }
    kani::cover!(odd_y && d[0] != x[0], "odd full Y with distinct d and x");
    kani::cover!(!odd_y && d[0] != x[0], "even full Y with distinct d and x");
}

#[kani::proof]
#[kani::unwind(36)]
#[kani::stub(super::validate_public_key, reject_full_point)]
fn p256_full_coordinate_extraction_propagates_point_validation_failure() {
    let x: [u8; 32] = kani::any();
    let y: [u8; 32] = kani::any();
    let d = Zeroizing::new(kani::any::<[u8; 32]>());
    let params = ManuallyDrop::new([
        (Label::Int(-4), Value::Bytes(d.to_vec())),
        (Label::Int(-2), Value::Bytes(x.to_vec())),
        (Label::Int(-3), Value::Bytes(y.to_vec())),
    ]);

    let point = ec2_public_bytes_from_params(params.as_slice(), P256_PROFILE);
    assert!(matches!(point, Err(CoseError::InvalidKeyMaterial)));
    kani::cover!(d[0] != x[0], "rejected point with distinct d and x");
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn unexpected_full_point_validation(_algorithm: Algorithm, _point: &[u8]) -> Result<(), CoseError> {
    assert!(
        false,
        "compact EC2 extraction does not invoke full-point validation"
    );
    Err(CoseError::InvalidKeyMaterial)
}

// Curve membership is the provider's responsibility. The model checks the
// shape reaching it and the proof checks what the extractor can return.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn accept_full_point(algorithm: Algorithm, point: &[u8]) -> Result<(), CoseError> {
    assert!(algorithm == Algorithm::P256);
    assert!(point.len() == 65 && point.first() == Some(&0x04));
    Ok(())
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn reject_full_point(algorithm: Algorithm, point: &[u8]) -> Result<(), CoseError> {
    accept_full_point(algorithm, point)?;
    Err(CoseError::InvalidKeyMaterial)
}
