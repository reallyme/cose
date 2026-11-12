// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{assert_error, hex};
use crate::containers::{
    cose_signature_to_der, signature_to_cose, validate_cose_signature, validate_preferred_cbor,
    ContainerError, ContainerErrorReason as Reason, SignatureEncoding,
};
use crate::iso18013::Iso18013SignatureCurve as Curve;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn preferred_serialization_covers_tags_floats_unsorted_maps_and_semantic_duplicates(
) -> Result<(), ContainerError> {
    for encoded in [
        "d8184100",
        "a202010102",
        "f93c00",
        "fa47c35000",
        "fb3ff0000000000001",
        "f98000",
        "f97c00",
        "f97e00",
        "f7",
        "f820",
    ] {
        validate_preferred_cbor(&hex(encoded))?;
    }
    for encoded in [
        "d900184100",
        "1817",
        "9fff",
        "fa3f800000",
        "fb3ff0000000000000",
        "fa80000000",
        "fa7fc00000",
        "fb7ff8000000000000",
    ] {
        assert_error(validate_preferred_cbor(&hex(encoded)), Reason::Encoding);
    }
    for encoded in ["a201000101", "a2810100810101", "a2a20102030400a20304010201"] {
        assert_error(validate_preferred_cbor(&hex(encoded)), Reason::Duplicate);
    }
    for encoded in ["", "00ff", "f818", "f81f", "1c", "d818"] {
        assert_error(validate_preferred_cbor(&hex(encoded)), Reason::Malformed);
    }
    let mut nested = vec![0x81; 34];
    nested.push(0);
    assert_error(validate_preferred_cbor(&nested), Reason::Limit);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn strict_der_scalar_checks_cover_every_named_curve_without_low_s_restrictions(
) -> Result<(), ContainerError> {
    for curve in [
        Curve::P256,
        Curve::P384,
        Curve::P521,
        Curve::BrainpoolP256r1,
        Curve::BrainpoolP320r1,
        Curve::BrainpoolP384r1,
        Curve::BrainpoolP512r1,
    ] {
        let order = crate::containers::scalar_order::scalar_order(curve).ok_or(Reason::Key)?;
        let width = order.len();
        let mut raw = vec![0; width * 2];
        raw[width - 1] = 1;
        raw[width * 2 - 1] = 1;
        let der = cose_signature_to_der(curve, &raw)?;
        assert_eq!(der.as_slice(), &hex("3006020101020101"));
        assert_eq!(
            *signature_to_cose(curve, SignatureEncoding::EcdsaDer, &der)?,
            raw
        );
        let mut high_s = raw.clone();
        high_s[width..].copy_from_slice(order);
        high_s[width * 2 - 1] -= 1;
        let der = cose_signature_to_der(curve, &high_s)?;
        assert_eq!(
            *signature_to_cose(curve, SignatureEncoding::EcdsaDer, &der)?,
            high_s
        );
        let mut invalid = raw.clone();
        invalid[..width].fill(0);
        assert_error(
            validate_cose_signature(curve, &invalid),
            Reason::SignatureEncoding,
        );
        invalid[..width].copy_from_slice(order);
        assert_error(
            validate_cose_signature(curve, &invalid),
            Reason::SignatureEncoding,
        );
        invalid.push(0);
        assert_error(
            validate_cose_signature(curve, &invalid),
            Reason::SignatureEncoding,
        );
        for bad in [
            "3006020180020101",
            "300702020001020101",
            "3006020100020101",
            "300602010102010100",
            "308106020101020101",
            "3006020101020100",
            "30050200020101",
            "30080203000001020101",
        ] {
            assert_error(
                signature_to_cose(curve, SignatureEncoding::EcdsaDer, &hex(bad)),
                Reason::SignatureEncoding,
            );
        }
        assert_error(
            signature_to_cose(
                curve,
                SignatureEncoding::EcdsaFixed,
                &hex("3006020101020101"),
            ),
            Reason::SignatureEncoding,
        );
        assert_error(
            signature_to_cose(curve, SignatureEncoding::EdDsa, &raw),
            Reason::SignatureEncoding,
        );
    }
    assert_eq!(Curve::P521.signature_length()?, 132);
    assert_eq!(Curve::BrainpoolP320r1.signature_length()?, 80);
    assert_eq!(Curve::Ed448.signature_length()?, 114);
    assert_error(
        signature_to_cose(Curve::Ed448, SignatureEncoding::EdDsa, &[0; 64]),
        Reason::SignatureEncoding,
    );
    assert_error(
        signature_to_cose(Curve::Ed25519, SignatureEncoding::EcdsaDer, &[0; 64]),
        Reason::SignatureEncoding,
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn malformed_inputs_allocate_no_sensitive_trees_or_error_context() {
    let malformed = hex("84a2014100014101a0f640");
    let result = allocation_counter::measure(|| {
        assert_error(validate_preferred_cbor(&malformed), Reason::Duplicate);
    });
    assert_eq!(result.count_total, 0);
    assert_eq!(result.bytes_total, 0);
    assert!(!std::mem::needs_drop::<ContainerError>());
    fn zeroizing<T: zeroize::ZeroizeOnDrop>() {}
    zeroizing::<crate::containers::VerifiedContainer>();
    zeroizing::<crate::containers::SignedContainer>();
    zeroizing::<crate::containers::InspectedPeerKey>();
    zeroizing::<crate::containers::ValidatedPeerKey>();
}
