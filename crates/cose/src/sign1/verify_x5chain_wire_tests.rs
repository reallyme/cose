// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;

#[cfg(test)]
use super::decode_cose_sign1_with_x5chain;
use super::{
    cose_verify1_with_x5chain_and_exact_algorithm, CoseError, CosePolicy, CoseSignatureAlgorithm,
    DecodedCoseSign1WithX5Chain, X5ChainHeaderPlacement,
};

const PROTECTED_CERTIFICATE: u8 = 0x51;
const UNPROTECTED_CERTIFICATE: u8 = 0x62;

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

#[cfg(kani)]
mod proof {
    use super::super::VerifiedDetachedCoseSign1;
    use super::{
        verify_fixture, wire_fixture, CoseError, CosePolicy, CoseSignatureAlgorithm,
        DecodedCoseSign1WithX5Chain, X5ChainHeaderPlacement,
    };

    #[kani::proof]
    #[kani::unwind(20)]
    #[kani::stub(super::super::decode_cose_sign1_with_x5chain, reject_duplicate)]
    #[kani::stub(super::super::verify_x5chain_signature, unexpected_verification)]
    fn x5chain_wire_duplicate_error_stops_before_trust_resolution() {
        let (error, trust_called) = verify_fixture(wire_fixture(true, true), true);
        assert!(error == Some(CoseError::DuplicateMapLabel));
        assert!(!trust_called);
        kani::cover!(
            error == Some(CoseError::DuplicateMapLabel) && !trust_called,
            "duplicate decoder error stops trust"
        );
    }

    // The bucket decoder proof establishes this error for a chain in each
    // bucket. Check the original wire bytes reach the decoder boundary.
    #[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
    fn reject_duplicate(
        wire: &[u8],
        max_len: usize,
    ) -> Result<DecodedCoseSign1WithX5Chain, CoseError> {
        assert!(wire == wire_fixture(true, true));
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
            "duplicate chains must stop before the verification stage"
        );
        Err(CoseError::InvalidSignature)
    }
}
