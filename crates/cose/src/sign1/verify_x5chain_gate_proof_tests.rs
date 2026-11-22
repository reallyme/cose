// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::ManuallyDrop;

use coset::{iana, CoseSign1, ProtectedHeader, RegisteredLabelWithPrivate};
use zeroize::Zeroizing;

use super::super::super::decode::{DecodedCoseSign1WithX5Chain, SensitiveCoseSign1};
use super::super::{verify_x5chain_signature, VerifiedDetachedCoseSign1, X5ChainHeaderPlacement};
use super::{Algorithm, CoseError, CosePolicy, CoseSignatureAlgorithm, KID, PAYLOAD, SIGNATURE};
use super::{CoseFailure, CoseSign1KeyResolution};

const PROTECTED: u8 = 1;
const UNPROTECTED: u8 = 2;
const CERTIFICATE: u8 = 0x51;
const PROTECTED_CHAIN_HEADER: [u8; 10] = [
    0xa3,
    0x04,
    0x41,
    KID,
    0x01,
    0x32,
    0x18,
    0x21,
    0x41,
    CERTIFICATE,
];
const UNPROTECTED_CHAIN_HEADER: [u8; 6] = [0xa2, 0x04, 0x41, KID, 0x01, 0x32];

#[kani::proof]
#[kani::stub(
    zeroize::optimization_barrier,
    crate::verify_zeroize_barrier_proof_tests::observe_barrier
)]
#[kani::unwind(8)]
#[kani::stub(super::super::verify_cose_signature, resolve_ordered_fixture)]
fn x5chain_tagged_resolver_preserves_decoded_certificate_order() {
    let protected: bool = kani::any();
    let has_third: bool = kani::any();
    let first: [u8; 2] = kani::any();
    let second: [u8; 2] = kani::any();
    let third: [u8; 2] = kani::any();
    let certificates = if has_third {
        vec![first.to_vec(), second.to_vec(), third.to_vec()]
    } else {
        vec![first.to_vec(), second.to_vec()]
    };
    let placement = if protected {
        X5ChainHeaderPlacement::Protected
    } else {
        X5ChainHeaderPlacement::Unprotected
    };
    let mut cose = CoseSign1::default();
    cose.payload = Some(vec![PAYLOAD]);
    // The production verifier borrows the decoded chain. Keep recursive
    // cleanup of the synthetic data outside the order proof.
    let decoded = ManuallyDrop::new(DecodedCoseSign1WithX5Chain {
        cose: SensitiveCoseSign1::new(cose),
        x5chain_der: Zeroizing::new(certificates),
        x5chain_placement: Some(placement),
        tagged: true,
    });
    let policy = CosePolicy::default()
        .with_require_tagged_sign1(true)
        .with_allow_unprotected_x5chain(true);
    let trust_called = Cell::new(false);
    let result = verify_x5chain_signature(&decoded, &policy, |algorithm, certificates| {
        trust_called.set(true);
        assert!(algorithm == CoseSignatureAlgorithm::Ed25519);
        let ordered = match (has_third, certificates) {
            (false, [a, b]) => a.as_slice() == first && b.as_slice() == second,
            (true, [a, b, c]) => {
                a.as_slice() == first && b.as_slice() == second && c.as_slice() == third
            }
            _ => false,
        };
        assert!(ordered);
        None
    });

    assert!(trust_called.get());
    assert!(matches!(result, Err(CoseError::KeyNotResolved)));
    kani::cover!(
        protected && !has_third && first > second && trust_called.get(),
        "protected two-certificate descending order"
    );
    kani::cover!(
        !protected && has_third && first > second && second < third && trust_called.get(),
        "unprotected three-certificate array with interior minimum"
    );
    kani::cover!(
        first == second && trust_called.get(),
        "equal entries stay in both positions"
    );
}

// Exercise the adapter's actual resolver closure. The separate trust-gate
// proof checks where the shared signature verifier calls that closure.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn resolve_ordered_fixture(
    _cose: &CoseSign1,
    tagged: bool,
    _aad: &[u8],
    _payload: &[u8],
    policy: &CosePolicy,
    resolver: impl FnOnce(CoseSignatureAlgorithm, &[u8]) -> CoseSign1KeyResolution,
) -> Result<VerifiedDetachedCoseSign1, CoseFailure> {
    assert!(tagged && policy.require_tagged_sign1());
    assert!(matches!(
        resolver(CoseSignatureAlgorithm::Ed25519, &[]),
        CoseSign1KeyResolution::NotResolved
    ));
    Err(CoseFailure::from(CoseError::KeyNotResolved))
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
    validate_fixture_protected_bytes
)]
#[kani::stub(
    super::super::build_received_sig_structure,
    unexpected_signature_structure
)]
#[kani::stub(
    super::super::backend_signature_from_cose,
    unexpected_signature_conversion
)]
#[kani::stub(super::super::verify_signature_with_backend, unexpected_backend)]
fn x5chain_rejects_placement_before_trust_and_untrusted_paths_before_crypto() {
    let placement: u8 = kani::any();
    let has_certificate: bool = kani::any();
    let allow_unprotected: bool = kani::any();
    let decoded = decoded_fixture(placement, has_certificate);
    let policy = CosePolicy::default().with_allow_unprotected_x5chain(allow_unprotected);
    let resolver_called = Cell::new(false);

    let result = verify_x5chain_signature(&decoded, &policy, |algorithm, certificates| {
        resolver_called.set(true);
        assert_trust_input(algorithm, certificates);
        None
    });

    let missing_placement = !matches!(placement, PROTECTED | UNPROTECTED);
    let placement_denied = placement == UNPROTECTED && !allow_unprotected;
    let has_path = !missing_placement && has_certificate;
    assert!(resolver_called.get() == (has_path && !placement_denied));
    let error = result.err();
    if !has_path {
        assert!(error == Some(CoseError::InvalidFormat));
    } else if placement_denied {
        assert!(error == Some(CoseError::UnprotectedHeaderNotAllowed));
    } else {
        assert!(error == Some(CoseError::KeyNotResolved));
    }

    kani::cover!(
        missing_placement && error == Some(CoseError::InvalidFormat),
        "missing certificate placement stops verification"
    );
    kani::cover!(
        !missing_placement && !has_certificate && error == Some(CoseError::InvalidFormat),
        "empty certificate path stops verification"
    );
    kani::cover!(
        placement_denied && has_path && error == Some(CoseError::UnprotectedHeaderNotAllowed),
        "unprotected path is rejected before trust resolution"
    );
    kani::cover!(
        placement == PROTECTED && resolver_called.get(),
        "trust rejects a protected path"
    );
    kani::cover!(
        placement == UNPROTECTED && resolver_called.get(),
        "trust rejects an explicitly permitted unprotected path"
    );
}

// The verifier borrows this decoded fixture. Skipping its recursive drop
// keeps the model focused on placement, resolution, and backend dispatch.
fn decoded_fixture(
    placement: u8,
    has_certificate: bool,
) -> ManuallyDrop<DecodedCoseSign1WithX5Chain> {
    let x5chain_placement = match placement {
        PROTECTED => Some(X5ChainHeaderPlacement::Protected),
        UNPROTECTED => Some(X5ChainHeaderPlacement::Unprotected),
        _ => None,
    };
    // The certificate is an opaque witness supplied by the decoded fixture.
    // The production verifier must apply placement policy and pass it to trust.
    let x5chain_der = if x5chain_placement.is_some() && has_certificate {
        Zeroizing::new(vec![vec![CERTIFICATE]])
    } else {
        Zeroizing::new(Vec::new())
    };
    let protected_header: &[u8] = if placement == PROTECTED {
        &PROTECTED_CHAIN_HEADER
    } else {
        &UNPROTECTED_CHAIN_HEADER
    };
    let mut cose = CoseSign1::default();
    cose.protected.original_data = Some(protected_header.to_vec());
    cose.protected.header.alg = Some(RegisteredLabelWithPrivate::Assigned(
        iana::Algorithm::Ed25519,
    ));
    cose.protected.header.key_id = vec![KID];
    cose.payload = Some(vec![PAYLOAD]);
    cose.signature = SIGNATURE.to_vec();
    ManuallyDrop::new(DecodedCoseSign1WithX5Chain {
        cose: SensitiveCoseSign1::new(cose),
        x5chain_der,
        x5chain_placement,
        tagged: false,
    })
}

fn assert_trust_input(algorithm: CoseSignatureAlgorithm, certificates: &[Vec<u8>]) {
    assert!(algorithm == CoseSignatureAlgorithm::Ed25519);
    assert!(certificates.len() == 1 && certificates[0].as_slice() == [CERTIFICATE]);
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn validate_fixture_protected_bytes(bytes: &[u8]) -> Result<(), CoseError> {
    assert!(bytes == PROTECTED_CHAIN_HEADER || bytes == UNPROTECTED_CHAIN_HEADER);
    Ok(())
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn unexpected_signature_structure(
    _protected: &ProtectedHeader,
    _aad: &[u8],
    _payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    assert!(
        false,
        "an invalid or untrusted path must stop before signature structure construction"
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
        "an invalid or untrusted path must stop before signature conversion"
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
        "an invalid or untrusted path must stop before backend verification"
    );
    Err(CoseError::InvalidSignature)
}
