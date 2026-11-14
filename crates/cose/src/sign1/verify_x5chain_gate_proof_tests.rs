// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::ManuallyDrop;

use coset::{iana, CoseSign1, ProtectedHeader, RegisteredLabelWithPrivate};
use zeroize::Zeroizing;

use super::super::super::decode::{DecodedCoseSign1WithX5Chain, SensitiveCoseSign1};
use super::super::{verify_x5chain_signature, X5ChainHeaderPlacement};
use super::{Algorithm, CoseError, CosePolicy, CoseSignatureAlgorithm, KID, PAYLOAD, SIGNATURE};

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
