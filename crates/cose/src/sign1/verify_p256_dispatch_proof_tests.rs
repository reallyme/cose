// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::ManuallyDrop;

use coset::{iana, CoseSign1, ProtectedHeader, RegisteredLabelWithPrivate};
use zeroize::Zeroizing;

use super::super::verify_cose_signature;
use super::{
    Algorithm, CoseError, CosePolicy, CoseSign1KeyResolution, CoseSignatureAlgorithm, AAD, KID,
    PAYLOAD,
};
use crate::failure::CoseFailureReason;

const ES256_ALG_BYTE: u8 = 0x26;
const ESP256_ALG_BYTE: u8 = 0x28;
const ES256_KEY: u8 = 0x71;
const ESP256_KEY: u8 = 0x72;
// The same synthetic scalar pair in COSE's fixed-width and backend DER forms.
const COSE_SIGNATURE: [u8; 64] = {
    let mut signature = [0; 64];
    signature[31] = 1;
    signature[63] = 1;
    signature
};
const DER_SIGNATURE: [u8; 8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

#[kani::proof]
#[kani::stub(
    zeroize::optimization_barrier,
    crate::verify_zeroize_barrier_proof_tests::observe_barrier
)]
#[kani::unwind(12)]
#[kani::stub(
    super::super::validate_cose_sign1_policy,
    super::validate_fixture_policy
)]
#[kani::stub(
    crate::limits::validate_protected_header_bytes,
    validate_p256_protected_bytes
)]
#[kani::stub(super::super::build_received_sig_structure, build_p256_fixture)]
#[kani::stub(super::super::backend_signature_from_cose, adapt_p256_fixture)]
#[kani::stub(super::super::verify_signature_with_backend, check_p256_dispatch)]
fn sign1_dispatch_resolves_exact_p256_registration() {
    let es256: bool = kani::any();
    let (cose, exact) = p256_fixture(es256);
    let resolver_called = Cell::new(false);

    let result = verify_cose_signature(
        &cose,
        false,
        &[AAD],
        &[PAYLOAD],
        &CosePolicy::default(),
        |algorithm, kid| {
            resolver_called.set(true);
            assert!(algorithm == exact);
            assert!(kid == [KID]);
            // Give the two registrations distinct resolver results for the same
            // kid so the dispatch check can detect an unintended substitution.
            let marker = if algorithm == CoseSignatureAlgorithm::Es256 {
                ES256_KEY
            } else {
                ESP256_KEY
            };
            CoseSign1KeyResolution::Resolved(Zeroizing::new(vec![marker]))
        },
    );

    assert!(resolver_called.get() && result.is_ok());
    if let Ok(verified) = result {
        assert!(verified.cose_algorithm == exact && verified.alg == Algorithm::P256);
        assert!(verified.kid.as_slice() == [KID]);
        assert!(verified.cose_type.is_none());
    }
}

#[kani::proof]
#[kani::stub(
    zeroize::optimization_barrier,
    crate::verify_zeroize_barrier_proof_tests::observe_barrier
)]
#[kani::unwind(12)]
#[kani::stub(
    super::super::validate_cose_sign1_policy,
    super::validate_fixture_policy
)]
#[kani::stub(
    crate::limits::validate_protected_header_bytes,
    validate_p256_protected_bytes
)]
#[kani::stub(
    super::super::build_received_sig_structure,
    unexpected_structure_builder
)]
#[kani::stub(
    super::super::backend_signature_from_cose,
    unexpected_signature_conversion
)]
#[kani::stub(super::super::verify_signature_with_backend, unexpected_backend)]
fn sign1_resolver_failures_stop_before_p256_backend_dispatch() {
    let (cose, exact) = p256_fixture(kani::any());
    let failure: u8 = kani::any();
    let (resolution, expected) = match failure {
        0 => (
            CoseSign1KeyResolution::NotResolved,
            CoseFailureReason::Sign1KeyNotResolved,
        ),
        1 => (
            CoseSign1KeyResolution::KidMismatch,
            CoseFailureReason::Sign1KidKeyMismatch,
        ),
        _ => (
            CoseSign1KeyResolution::AlgorithmMismatch,
            CoseFailureReason::KeyAlgorithmMismatch,
        ),
    };
    let resolver_called = Cell::new(false);
    let result = verify_cose_signature(
        &cose,
        false,
        &[AAD],
        &[PAYLOAD],
        &CosePolicy::default(),
        |algorithm, kid| {
            resolver_called.set(true);
            assert!(algorithm == exact);
            assert!(kid == [KID]);
            resolution
        },
    );

    assert!(resolver_called.get());
    let reason = result.err().map(|error| error.reason());
    assert!(reason == Some(expected));

    let es256 = exact == CoseSignatureAlgorithm::Es256;
    let not_resolved = reason == Some(CoseFailureReason::Sign1KeyNotResolved);
    let kid_mismatch = reason == Some(CoseFailureReason::Sign1KidKeyMismatch);
    let algorithm_mismatch = reason == Some(CoseFailureReason::KeyAlgorithmMismatch);
    kani::cover!(es256 && not_resolved, "ES256 key not resolved");
    kani::cover!(!es256 && not_resolved, "ESP256 key not resolved");
    kani::cover!(es256 && kid_mismatch, "ES256 kid mismatch");
    kani::cover!(!es256 && kid_mismatch, "ESP256 kid mismatch");
    kani::cover!(es256 && algorithm_mismatch, "ES256 algorithm mismatch");
    kani::cover!(!es256 && algorithm_mismatch, "ESP256 algorithm mismatch");
}

fn p256_fixture(es256: bool) -> (ManuallyDrop<CoseSign1>, CoseSignatureAlgorithm) {
    let (wire, exact, encoded) = if es256 {
        (
            iana::Algorithm::ES256,
            CoseSignatureAlgorithm::Es256,
            ES256_ALG_BYTE,
        )
    } else {
        (
            iana::Algorithm::ESP256,
            CoseSignatureAlgorithm::Esp256,
            ESP256_ALG_BYTE,
        )
    };
    // The shared verifier borrows the decoded object. The synthetic fixture
    // owns only public bytes, and its recursive destructor is outside this proof.
    let mut cose = ManuallyDrop::new(CoseSign1::default());
    cose.protected.original_data = Some(vec![0xa2, 0x04, 0x41, KID, 0x01, encoded]);
    cose.protected.header.key_id = vec![KID];
    cose.protected.header.alg = Some(RegisteredLabelWithPrivate::Assigned(wire));
    cose.signature = COSE_SIGNATURE.to_vec();
    (cose, exact)
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn validate_p256_protected_bytes(bytes: &[u8]) -> Result<(), CoseError> {
    assert!(bytes.len() == 6);
    assert!(bytes[..5] == [0xa2, 0x04, 0x41, KID, 0x01]);
    assert!(matches!(bytes[5], ES256_ALG_BYTE | ESP256_ALG_BYTE));
    Ok(())
}

// The authentication structure has its own byte-level proof. Carry the exact
// registration byte into the backend witness independently of the resolver.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn build_p256_fixture(
    protected: &ProtectedHeader,
    aad: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let bytes = protected
        .original_data
        .as_deref()
        .ok_or(CoseError::InvalidFormat)?;
    validate_p256_protected_bytes(bytes)?;
    assert!(aad == [AAD] && payload == [PAYLOAD]);
    Ok(Zeroizing::new(vec![bytes[5]]))
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn adapt_p256_fixture(algorithm: Algorithm, signature: &[u8]) -> Result<Vec<u8>, CoseError> {
    assert!(algorithm == Algorithm::P256);
    assert!(signature.len() == COSE_SIGNATURE.len());
    assert!(signature
        .chunks_exact(super::SIGNATURE_FIXTURE_CHUNK)
        .zip(COSE_SIGNATURE.chunks_exact(super::SIGNATURE_FIXTURE_CHUNK))
        .all(|(actual, expected)| actual == expected));
    Ok(DER_SIGNATURE.to_vec())
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn check_p256_dispatch(
    algorithm: Algorithm,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CoseError> {
    assert!(algorithm == Algorithm::P256);
    assert!(signature == DER_SIGNATURE);
    let es256 = message == [ES256_ALG_BYTE] && key == [ES256_KEY];
    let esp256 = message == [ESP256_ALG_BYTE] && key == [ESP256_KEY];
    assert!(es256 || esp256);
    kani::cover!(es256, "ES256 reaches P-256 with the ES256 resolver result");
    kani::cover!(
        esp256,
        "ESP256 reaches P-256 with the ESP256 resolver result"
    );
    Ok(())
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn unexpected_structure_builder(
    _protected: &ProtectedHeader,
    _aad: &[u8],
    _payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    assert!(
        false,
        "the structure builder must be unreachable after a resolver failure"
    );
    Err(CoseError::InvalidSignature)
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn unexpected_signature_conversion(
    _algorithm: Algorithm,
    _signature: &[u8],
) -> Result<Vec<u8>, CoseError> {
    assert!(
        false,
        "signature conversion must be unreachable after a resolver failure"
    );
    Err(CoseError::InvalidSignature)
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn unexpected_backend(
    _algorithm: Algorithm,
    _key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), CoseError> {
    assert!(
        false,
        "the crypto backend must be unreachable after a resolver failure"
    );
    Err(CoseError::InvalidSignature)
}
