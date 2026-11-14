// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;

use coset::{iana, CoseSign1, ProtectedHeader, RegisteredLabelWithPrivate};
use zeroize::Zeroizing;

use super::super::decode::{DecodedCoseSign1, SensitiveCoseSign1};
use super::{
    verify_cose_sign1, verify_detached_cose_sign1, CoseFailure, CoseSign1DetachedVerifyInput,
    CoseSign1KeyResolution, CoseSign1VerifyInput,
};
use crate::{Algorithm, CoseError, CosePolicy, CoseSignatureAlgorithm};

#[path = "verify_sig_structure_backend_proof_tests.rs"]
mod boundary_backend;

#[cfg(feature = "wire")]
#[path = "verify_p256_dispatch_proof_tests.rs"]
mod p256_dispatch;

#[path = "verify_x5chain_gate_proof_tests.rs"]
mod x5chain;

const KID: u8 = 0x31;
const AAD: u8 = 0x42;
const PAYLOAD: u8 = 0x53;
const SIGNATURE_FIXTURE_BYTE: u8 = 0x64;
const SIGNATURE_FIXTURE_CHUNK: usize = 8;
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
const SIGNATURE: [u8; 64] = [SIGNATURE_FIXTURE_BYTE; 64];

#[kani::proof]
#[kani::unwind(12)]
#[kani::stub(super::decode_cose_sign1, decode_fixture)]
#[kani::stub(super::validate_cose_sign1_policy, validate_fixture_policy)]
#[kani::stub(
    crate::limits::validate_protected_header_bytes,
    validate_fixture_protected_bytes
)]
#[kani::stub(crate::zeroize_coset::zeroize_cose_sign1, discard_fixture)]
#[kani::stub(super::backend_signature_from_cose, adapt_fixture_signature)]
#[kani::stub(super::build_received_sig_structure, build_fixture_sig_structure)]
#[kani::stub(super::verify_signature_with_backend, verify_fixture)]
fn attached_sign1_releases_payload_only_after_verification() {
    let has_payload: bool = kani::any();
    let backend_accepts: bool = kani::any();
    let encoded_fixture = [u8::from(has_payload)];
    let policy = CosePolicy::default();
    let input = CoseSign1VerifyInput::new(&encoded_fixture, &[AAD], &policy);
    let resolver_called = Cell::new(false);
    let result = verify_cose_sign1(input, |algorithm, kid| {
        resolver_called.set(true);
        resolve(algorithm, kid, backend_accepts)
    });
    assert!(resolver_called.get() == has_payload);
    let result = result.map_err(CoseFailure::into_native_error);
    if !has_payload {
        assert!(matches!(result, Err(CoseError::MissingPayload)));
    } else if backend_accepts {
        assert!(result.is_ok());
        if let Ok(verified) = &result {
            assert!(verified.payload.as_slice() == [PAYLOAD]);
            assert!(verified.cose_algorithm == CoseSignatureAlgorithm::Ed25519);
            assert!(verified.alg == Algorithm::Ed25519);
            assert!(verified.kid.as_slice() == [KID]);
            assert!(verified.cose_type.is_none());
        }
    } else {
        assert!(matches!(result, Err(CoseError::InvalidSignature)));
    }
    kani::cover!(
        result.is_ok(),
        "backend success releases the authenticated payload"
    );
    kani::cover!(
        matches!(result, Err(CoseError::InvalidSignature)),
        "backend failure propagates"
    );
    kani::cover!(
        matches!(result, Err(CoseError::MissingPayload)),
        "attached verification requires payload presence"
    );
}

#[kani::proof]
#[kani::unwind(12)]
#[kani::stub(super::decode_cose_sign1, decode_fixture)]
#[kani::stub(super::validate_cose_sign1_policy, validate_fixture_policy)]
#[kani::stub(
    crate::limits::validate_protected_header_bytes,
    validate_fixture_protected_bytes
)]
#[kani::stub(crate::zeroize_coset::zeroize_cose_sign1, discard_fixture)]
#[kani::stub(super::backend_signature_from_cose, adapt_fixture_signature)]
#[kani::stub(super::build_received_sig_structure, build_fixture_sig_structure)]
#[kani::stub(super::verify_signature_with_backend, verify_fixture)]
fn detached_sign1_releases_metadata_only_after_verification() {
    let has_payload: bool = kani::any();
    let backend_accepts: bool = kani::any();
    let encoded_fixture = [u8::from(has_payload)];
    let policy = CosePolicy::default();
    let input = CoseSign1DetachedVerifyInput::new(&encoded_fixture, &[PAYLOAD], &[AAD], &policy);
    let resolver_called = Cell::new(false);
    let result = verify_detached_cose_sign1(input, |algorithm, kid| {
        resolver_called.set(true);
        resolve(algorithm, kid, backend_accepts)
    });
    assert!(resolver_called.get() != has_payload);
    let result = result.map_err(CoseFailure::into_native_error);
    if has_payload {
        assert!(matches!(result, Err(CoseError::InvalidFormat)));
    } else if backend_accepts {
        assert!(result.is_ok());
        if let Ok(verified) = &result {
            assert!(verified.cose_algorithm == CoseSignatureAlgorithm::Ed25519);
            assert!(verified.alg == Algorithm::Ed25519);
            assert!(verified.kid.as_slice() == [KID]);
            assert!(verified.cose_type.is_none());
        }
    } else {
        assert!(matches!(result, Err(CoseError::InvalidSignature)));
    }
    kani::cover!(
        result.is_ok(),
        "backend success releases authenticated metadata"
    );
    kani::cover!(
        matches!(result, Err(CoseError::InvalidSignature)),
        "backend failure propagates"
    );
    kani::cover!(
        matches!(result, Err(CoseError::InvalidFormat)),
        "detached verification rejects an attached payload"
    );
}

// Model wire parsing as a decoded Ed25519 object with symbolic payload
// presence. Production verification still controls how that object is used.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn decode_fixture(encoded: &[u8], _limit: usize) -> Result<DecodedCoseSign1, CoseError> {
    let mut cose = CoseSign1::default();
    cose.protected.original_data = Some(vec![0xa2, 0x04, 0x41, KID, 0x01, 0x32]);
    cose.protected.header.alg = Some(RegisteredLabelWithPrivate::Assigned(
        iana::Algorithm::Ed25519,
    ));
    cose.protected.header.key_id = vec![KID];
    if encoded == [1] {
        cose.payload = Some(vec![PAYLOAD]);
    }
    cose.signature = SIGNATURE.to_vec();
    Ok(DecodedCoseSign1 {
        cose: SensitiveCoseSign1::new(cose),
        tagged: false,
    })
}

// The fixture provides already-validated protected bytes. Keep the boundary
// assertion so a change to the bytes handed to validation is still detected.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn validate_fixture_protected_bytes(bytes: &[u8]) -> Result<(), CoseError> {
    assert!(bytes == [0xa2, 0x04, 0x41, KID, 0x01, 0x32]);
    Ok(())
}

// The harness uses the default policy with this supported registration.
// The exact-registration proof exercises the production allowlist separately.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn validate_fixture_policy(
    _cose: &CoseSign1,
    tagged: bool,
    policy: &CosePolicy,
) -> Result<(), CoseError> {
    assert!(!tagged && policy.contract().allow_any_algorithm);
    Ok(())
}

// Skip recursive wiping of the public fixture before Rust drops its owned
// buffers. The proof checks authentication flow, so it does not model wiping.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn discard_fixture(_cose: &mut CoseSign1) {}

// Ed25519 uses the same signature representation on the wire and at the
// backend. The fixture checks this handoff without exploring DER conversion.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn adapt_fixture_signature(algorithm: Algorithm, signature: &[u8]) -> Result<Vec<u8>, CoseError> {
    assert!(algorithm == Algorithm::Ed25519);
    assert_fixture_signature(signature);
    Ok(signature.to_vec())
}

// Byte-level equivalence for the production builder is verified separately.
// Check the caller supplies the fixture's actual inputs at this boundary.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn build_fixture_sig_structure(
    protected: &ProtectedHeader,
    aad: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    assert!(protected.original_data.as_deref() == Some(&[0xa2, 0x04, 0x41, KID, 0x01, 0x32]));
    assert!(aad == [AAD]);
    assert!(payload == [PAYLOAD]);
    Ok(Zeroizing::new(vec![0x42]))
}

fn resolve(
    exact: CoseSignatureAlgorithm,
    kid: &[u8],
    backend_accepts: bool,
) -> CoseSign1KeyResolution {
    assert!(exact == CoseSignatureAlgorithm::Ed25519);
    assert!(kid == [KID]);
    CoseSign1KeyResolution::Resolved(Zeroizing::new(vec![u8::from(backend_accepts)]))
}

// This backend models a typed result. The resolved key's sole byte carries
// the harness's acceptance decision so the caller can check both outcomes.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn verify_fixture(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CoseError> {
    assert!(algorithm == Algorithm::Ed25519);
    assert_fixture_signature(signature);
    assert!(message == [0x42]);
    assert!(public_key == [0] || public_key == [1]);
    kani::cover!(
        public_key == [0],
        "the verifier is invoked and rejects the signature"
    );
    kani::cover!(
        public_key == [1],
        "the verifier is invoked and accepts the signature"
    );
    if public_key == [1] {
        Ok(())
    } else {
        Err(CoseError::InvalidSignature)
    }
}

// Eight comparisons of eight bytes cover the entire signature while keeping
// both the iterator and the byte comparison within the harness unwind bound.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn assert_fixture_signature(signature: &[u8]) {
    assert!(signature.len() == SIGNATURE.len());
    assert!(signature
        .chunks_exact(SIGNATURE_FIXTURE_CHUNK)
        .all(|chunk| chunk == [SIGNATURE_FIXTURE_BYTE; SIGNATURE_FIXTURE_CHUNK]));
}
