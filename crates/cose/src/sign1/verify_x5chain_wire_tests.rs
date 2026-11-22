// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;

#[cfg(test)]
use ciborium::value::Value;

#[cfg(test)]
use super::decode_cose_sign1_with_x5chain;
use super::{
    cose_verify1_with_x5chain_and_exact_algorithm, CoseError, CosePolicy, CoseSignatureAlgorithm,
    DecodedCoseSign1WithX5Chain, X5ChainHeaderPlacement,
};
#[cfg(test)]
use crate::limits::{
    MAX_COSE_X5CHAIN_CERTIFICATES, MAX_COSE_X5CHAIN_CERTIFICATE_BYTES, MAX_COSE_X5CHAIN_TOTAL_BYTES,
};

const PROTECTED_CERTIFICATE: u8 = 0x51;
const UNPROTECTED_CERTIFICATE: u8 = 0x62;

// Tag 18 precedes the Sign1 array. Use distinct certificate lengths and a
// non-sorted sequence so a reversal, sort, or flattening is observable.
#[cfg(test)]
const TAGGED_PROTECTED_CHAIN: &[u8] =
    b"\xd2\x84\x4b\xa2\x01\x32\x18\x21\x82\x41\x62\x42\x51\x52\xa0\x41\x53\x41\x64";
#[cfg(test)]
const TAGGED_UNPROTECTED_CHAIN: &[u8] =
    b"\xd2\x84\x43\xa1\x01\x32\xa1\x18\x21\x83\x41\x62\x42\x51\x52\x41\x63\x41\x53\x41\x64";
const TAGGED_DUPLICATE_CHAIN: &[u8] = b"\xd2\x84\x4b\xa2\x01\x32\x18\x21\x82\x41\x62\x42\x51\x52\
      \xa1\x18\x21\x82\x41\x71\x41\x72\x41\x53\x41\x64";
#[cfg(test)]
const TAGGED_MALFORMED_CHAIN: &[u8] =
    b"\xd2\x84\x43\xa1\x01\x32\xa1\x18\x21\x82\x41\x62\xf6\x41\x53\x41\x64";

// Literal CBOR keeps the fixtures independent of the Sign1 encoder. The
// protected bstr encodes a map with alg = -19 (Ed25519) and optional label 33.
// The unprotected map carries only label 33 when present.
fn wire_fixture(protected: bool, unprotected: bool) -> &'static [u8] {
    match (protected, unprotected) {
        (true, true) => {
            b"\x84\x47\xa2\x01\x32\x18\x21\x41\x51\
                         \xa1\x18\x21\x41\x62\x41\x53\x41\x64"
        }
        (true, false) => {
            b"\x84\x47\xa2\x01\x32\x18\x21\x41\x51\
                          \xa0\x41\x53\x41\x64"
        }
        (false, true) => {
            b"\x84\x43\xa1\x01\x32\
                          \xa1\x18\x21\x41\x62\x41\x53\x41\x64"
        }
        (false, false) => b"\x84\x43\xa1\x01\x32\xa0\x41\x53\x41\x64",
    }
}

#[cfg(test)]
fn assert_decoded_headers(
    result: &Result<DecodedCoseSign1WithX5Chain, CoseError>,
    protected: bool,
    unprotected: bool,
) {
    let matches_wire = match (result, protected, unprotected) {
        (Ok(decoded), true, false) => {
            decoded.x5chain_placement == Some(X5ChainHeaderPlacement::Protected)
                && certificate_matches(&decoded.x5chain_der, PROTECTED_CERTIFICATE)
        }
        (Ok(decoded), false, true) => {
            decoded.x5chain_placement == Some(X5ChainHeaderPlacement::Unprotected)
                && certificate_matches(&decoded.x5chain_der, UNPROTECTED_CERTIFICATE)
        }
        (Ok(decoded), false, false) => {
            decoded.x5chain_placement.is_none() && decoded.x5chain_der.is_empty()
        }
        (Err(CoseError::DuplicateMapLabel), true, true) => true,
        _ => false,
    };
    assert!(
        matches_wire,
        "decoding must match the two wire header buckets"
    );
}

fn certificate_matches(certificates: &[Vec<u8>], expected: u8) -> bool {
    matches!(
        certificates,
        [certificate] if certificate.as_slice() == [expected]
    )
}

fn verify_fixture(wire: &[u8], protected: bool) -> (Option<CoseError>, bool) {
    // Enabling both placements makes duplicate rejection independent of policy.
    let policy = CosePolicy::default().with_allow_unprotected_x5chain(true);
    let trust_called = Cell::new(false);
    let result =
        cose_verify1_with_x5chain_and_exact_algorithm(wire, &policy, |algorithm, certificates| {
            trust_called.set(true);
            assert!(algorithm == CoseSignatureAlgorithm::Ed25519);
            let expected = if protected {
                PROTECTED_CERTIFICATE
            } else {
                UNPROTECTED_CERTIFICATE
            };
            assert!(certificate_matches(certificates, expected));
            None
        });
    (result.err(), trust_called.get())
}

#[cfg(test)]
fn assert_trust_gate(
    error: Option<CoseError>,
    trust_called: bool,
    protected: bool,
    unprotected: bool,
) {
    assert!(trust_called == (protected ^ unprotected));
    let expected = match (protected, unprotected) {
        (true, true) => CoseError::DuplicateMapLabel,
        (false, false) => CoseError::InvalidFormat,
        _ => CoseError::KeyNotResolved,
    };
    assert!(error == Some(expected));
}

// Exercise the same fixture domain with the production CBOR reader, byte
// preflight and cleanup, joining the two Kani proof obligations.
#[cfg(test)]
#[test]
fn x5chain_wire_fixtures_decode_and_gate_trust() {
    for protected in [false, true] {
        for unprotected in [false, true] {
            let wire = wire_fixture(protected, unprotected);
            let decoded = decode_cose_sign1_with_x5chain(wire, wire.len());
            assert_decoded_headers(&decoded, protected, unprotected);
            let (error, trust_called) = verify_fixture(wire, protected);
            assert_trust_gate(error, trust_called, protected, unprotected);
        }
    }
}

#[cfg(test)]
#[test]
fn x5chain_tagged_certificate_arrays_reach_trust_in_wire_order() -> Result<(), CoseError> {
    let policy = CosePolicy::default()
        .with_require_tagged_sign1(true)
        .with_allow_unprotected_x5chain(true);
    let first_two: &[&[u8]] = &[&[0x62], &[0x51, 0x52]];
    let all_three: &[&[u8]] = &[&[0x62], &[0x51, 0x52], &[0x63]];
    for (wire, placement, expected) in [
        (
            TAGGED_PROTECTED_CHAIN,
            X5ChainHeaderPlacement::Protected,
            first_two,
        ),
        (
            TAGGED_UNPROTECTED_CHAIN,
            X5ChainHeaderPlacement::Unprotected,
            all_three,
        ),
    ] {
        let decoded = decode_cose_sign1_with_x5chain(wire, wire.len())?;
        assert!(decoded.tagged);
        assert_eq!(decoded.x5chain_placement, Some(placement));

        let mut trust_called = false;
        let result = cose_verify1_with_x5chain_and_exact_algorithm(wire, &policy, |alg, chain| {
            trust_called = true;
            assert_eq!(alg, CoseSignatureAlgorithm::Ed25519);
            assert_eq!(chain.len(), expected.len());
            for (certificate, wire_certificate) in chain.iter().zip(expected) {
                assert_eq!(certificate.as_slice(), *wire_certificate);
            }
            None
        });
        assert!(trust_called);
        assert_eq!(result.err(), Some(CoseError::KeyNotResolved));
    }

    let (_, untagged) = TAGGED_PROTECTED_CHAIN
        .split_first()
        .ok_or(CoseError::InvalidFormat)?;
    let wrong_tag = [&[0xd3], untagged].concat();
    for (wire, expected_error) in [
        (untagged, CoseError::InvalidFormat),
        (wrong_tag.as_slice(), CoseError::UnexpectedCborTag),
        (TAGGED_DUPLICATE_CHAIN, CoseError::DuplicateMapLabel),
        (TAGGED_MALFORMED_CHAIN, CoseError::InvalidFormat),
    ] {
        assert_eq!(
            verify_refusing_trust(wire, &policy),
            (Some(expected_error), false)
        );
    }
    Ok(())
}

fn verify_refusing_trust(wire: &[u8], policy: &CosePolicy) -> (Option<CoseError>, bool) {
    let mut trust_called = false;
    let result = cose_verify1_with_x5chain_and_exact_algorithm(wire, policy, |_, _| {
        trust_called = true;
        None
    });
    (result.err(), trust_called)
}

#[cfg(test)]
#[test]
fn x5chain_wire_array_bounds_are_enforced_before_trust() -> Result<(), CoseError> {
    let next_count = MAX_COSE_X5CHAIN_CERTIFICATES
        .checked_add(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let next_size = MAX_COSE_X5CHAIN_CERTIFICATE_BYTES
        .checked_add(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let budget_entry_size = MAX_COSE_X5CHAIN_TOTAL_BYTES
        .checked_div(MAX_COSE_X5CHAIN_CERTIFICATES)
        .ok_or(CoseError::InvalidFormat)?;
    let over_budget_entry_size = budget_entry_size
        .checked_add(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    // These two paths differ by one byte, with each entry inside its own
    // size limit. This isolates the aggregate check from the other limits.
    assert_eq!(
        budget_entry_size.checked_mul(MAX_COSE_X5CHAIN_CERTIFICATES),
        Some(MAX_COSE_X5CHAIN_TOTAL_BYTES)
    );
    assert!(over_budget_entry_size <= MAX_COSE_X5CHAIN_CERTIFICATE_BYTES);
    let exact_budget = vec![certificate_fixture(budget_entry_size); MAX_COSE_X5CHAIN_CERTIFICATES];
    let mut over_budget = exact_budget.clone();
    *over_budget.last_mut().ok_or(CoseError::InvalidFormat)? =
        certificate_fixture(over_budget_entry_size);
    let cases = [
        (vec![], CoseError::InvalidFormat),
        (vec![certificate_fixture(1)], CoseError::InvalidFormat),
        (vec![certificate_fixture(1); 2], CoseError::KeyNotResolved),
        (
            vec![certificate_fixture(1); next_count],
            CoseError::ResourceLimitExceeded,
        ),
        (
            vec![certificate_fixture(1), certificate_fixture(0)],
            CoseError::InvalidFormat,
        ),
        (
            vec![certificate_fixture(1), Value::Null],
            CoseError::InvalidFormat,
        ),
        (
            vec![
                certificate_fixture(1),
                certificate_fixture(MAX_COSE_X5CHAIN_CERTIFICATE_BYTES),
            ],
            CoseError::KeyNotResolved,
        ),
        (
            vec![certificate_fixture(1), certificate_fixture(next_size)],
            CoseError::ResourceLimitExceeded,
        ),
        (exact_budget, CoseError::KeyNotResolved),
        (over_budget, CoseError::ResourceLimitExceeded),
    ];
    let policy = CosePolicy::default()
        .with_require_tagged_sign1(true)
        .with_allow_unprotected_x5chain(true);
    for (chain, expected) in cases {
        for protected in [true, false] {
            let wire = encode_tagged_chain_fixture(chain.clone(), protected)?;
            // An explicit envelope budget may exceed the default, while the
            // separate certificate count and DER byte ceilings remain fixed.
            let wire_policy = policy.clone().with_max_cose_sign1_bytes(wire.len());
            assert_eq!(wire_policy.max_cose_sign1_bytes(), wire.len());
            assert_eq!(
                verify_refusing_trust(&wire, &wire_policy),
                (Some(expected), expected == CoseError::KeyNotResolved)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
fn certificate_fixture(size: usize) -> Value {
    Value::Bytes(vec![0x51; size])
}

// Serialize the independent wire fixture without the Sign1 encoder. Its
// chain checks would reject the malformed inputs before they reach verification.
#[cfg(test)]
fn encode_tagged_chain_fixture(
    certificates: Vec<Value>,
    protected: bool,
) -> Result<Vec<u8>, CoseError> {
    let algorithm = (Value::Integer(1.into()), Value::Integer((-19).into()));
    let chain = (Value::Integer(33.into()), Value::Array(certificates));
    let (protected_entries, unprotected_entries) = if protected {
        (vec![algorithm, chain], Vec::new())
    } else {
        (vec![algorithm], vec![chain])
    };
    let mut protected_bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(protected_entries), &mut protected_bytes)
        .map_err(|_| CoseError::Cbor)?;
    let body = Value::Array(vec![
        Value::Bytes(protected_bytes),
        Value::Map(unprotected_entries),
        Value::Bytes(vec![0x53]),
        Value::Bytes(vec![0x64]),
    ]);
    let mut wire = Vec::new();
    ciborium::ser::into_writer(&Value::Tag(18, Box::new(body)), &mut wire)
        .map_err(|_| CoseError::Cbor)?;
    Ok(wire)
}

#[cfg(kani)]
mod proof {
    use super::super::VerifiedDetachedCoseSign1;
    use super::{
        verify_fixture, verify_refusing_trust, wire_fixture, CoseError, CosePolicy,
        CoseSignatureAlgorithm, DecodedCoseSign1WithX5Chain, X5ChainHeaderPlacement,
        TAGGED_DUPLICATE_CHAIN,
    };

    #[kani::proof]
    #[kani::stub(
        zeroize::optimization_barrier,
        crate::verify_zeroize_barrier_proof_tests::observe_barrier
    )]
    #[kani::unwind(28)]
    #[kani::stub(super::super::decode_cose_sign1_with_x5chain, reject_duplicate)]
    #[kani::stub(super::super::verify_x5chain_signature, unexpected_verification)]
    fn x5chain_wire_duplicate_error_stops_before_trust_resolution() {
        let tagged: bool = kani::any();
        let wire = if tagged {
            TAGGED_DUPLICATE_CHAIN
        } else {
            wire_fixture(true, true)
        };
        let (error, trust_called) = verify_fixture(wire, true);
        assert!(error == Some(CoseError::DuplicateMapLabel));
        assert!(!trust_called);
        kani::cover!(
            !tagged && error == Some(CoseError::DuplicateMapLabel) && !trust_called,
            "untagged duplicate decoder error stops trust"
        );
        kani::cover!(
            tagged && error == Some(CoseError::DuplicateMapLabel) && !trust_called,
            "tagged duplicate decoder error stops trust"
        );
    }

    #[kani::proof]
    #[kani::stub(
        zeroize::optimization_barrier,
        crate::verify_zeroize_barrier_proof_tests::observe_barrier
    )]
    #[kani::unwind(5)]
    #[kani::stub(super::super::decode_cose_sign1_with_x5chain, reject_invalid_array)]
    #[kani::stub(super::super::verify_x5chain_signature, unexpected_verification)]
    fn x5chain_wire_array_decoder_errors_stop_before_trust() {
        let oversized: bool = kani::any();
        let decoder_witness = [u8::from(oversized)];
        let policy = CosePolicy::default().with_allow_unprotected_x5chain(true);
        let (error, trust_called) = verify_refusing_trust(&decoder_witness, &policy);
        let expected = if oversized {
            CoseError::ResourceLimitExceeded
        } else {
            CoseError::InvalidFormat
        };
        assert!(error == Some(expected));
        assert!(!trust_called);
        kani::cover!(
            !oversized && error == Some(CoseError::InvalidFormat),
            "malformed array stops before trust"
        );
        kani::cover!(
            oversized && error == Some(CoseError::ResourceLimitExceeded),
            "oversized array stops before trust"
        );
    }

    // The array proofs establish these semantic errors. Model the decoding
    // boundary here so the verifier is checked independently of CBOR parsing.
    #[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
    fn reject_invalid_array(
        witness: &[u8],
        max_len: usize,
    ) -> Result<DecodedCoseSign1WithX5Chain, CoseError> {
        assert!(witness.len() <= max_len);
        match witness {
            [0] => Err(CoseError::InvalidFormat),
            [1] => Err(CoseError::ResourceLimitExceeded),
            _ => {
                assert!(false, "expected one typed array error witness");
                Err(CoseError::InvalidFormat)
            }
        }
    }

    // The bucket decoder proof establishes this error for a chain in each
    // bucket. Check the original wire bytes reach the decoder boundary.
    #[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
    fn reject_duplicate(
        wire: &[u8],
        max_len: usize,
    ) -> Result<DecodedCoseSign1WithX5Chain, CoseError> {
        assert!(wire == wire_fixture(true, true) || wire == TAGGED_DUPLICATE_CHAIN);
        assert!(wire.len() <= max_len);
        Err(CoseError::DuplicateMapLabel)
    }

    #[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
    fn unexpected_verification(
        _decoded: &DecodedCoseSign1WithX5Chain,
        _policy: &CosePolicy,
        _resolver: impl FnOnce(CoseSignatureAlgorithm, &[Vec<u8>]) -> Option<Vec<u8>>,
    ) -> Result<(VerifiedDetachedCoseSign1, X5ChainHeaderPlacement), CoseError> {
        assert!(
            false,
            "rejected chains must stop before the verification stage"
        );
        Err(CoseError::InvalidSignature)
    }
}
