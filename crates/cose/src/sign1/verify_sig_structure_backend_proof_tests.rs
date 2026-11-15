// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;

use coset::{iana, CoseSign1, ProtectedHeader, RegisteredLabelWithPrivate};
use reallyme_crypto::dispatch::AlgorithmError;
use zeroize::Zeroizing;

use super::super::{verify_cose_sign1, verify_detached_cose_sign1};
use super::{
    Algorithm, CoseError, CosePolicy, CoseSign1DetachedVerifyInput, CoseSign1KeyResolution,
    CoseSign1VerifyInput, CoseSignatureAlgorithm, DecodedCoseSign1, SensitiveCoseSign1, KID,
    SIGNATURE,
};

const LENGTHS: [usize; 4] = [23, 24, 255, 256];
const ENCODED_FIELD_LEN: [usize; 4] = [24, 26, 257, 259];
const CONTEXT_LEN: usize = 12;
const MAX_FIELD_LEN: usize = 256;
const MAX_MESSAGE_LEN: usize = CONTEXT_LEN + 3 * (MAX_FIELD_LEN + 3);
const PROTECTED_BYTE: u8 = 0x51;
const AAD_BYTE: u8 = 0x62;
const PAYLOAD_BYTE: u8 = 0x73;
const KEY: u8 = 0x91;

#[derive(Clone, Copy)]
struct Observation {
    cases: [usize; 3],
    attached: bool,
    picked: usize,
    expected_len: usize,
    expected_byte: u8,
    fields: [Option<*const [u8]>; 3],
    encoded: Option<*const [u8]>,
}

std::thread_local! {
    static OBSERVATION: Cell<Option<Observation>> = const { Cell::new(None) };
}

#[kani::proof]
#[kani::unwind(18)]
#[kani::stub(super::super::decode_cose_sign1, decoded_boundary_fixture)]
#[kani::stub(crate::limits::validate_protected_header_bytes, checked_fixture)]
#[kani::stub(
    super::super::validate_cose_sign1_policy,
    super::validate_fixture_policy
)]
#[kani::stub(
    super::super::backend_signature_from_cose,
    super::adapt_fixture_signature
)]
#[kani::stub(crate::zeroize_coset::zeroize_cose_sign1, super::discard_fixture)]
#[kani::stub(super::super::build_received_sig_structure, model_built_structure)]
#[kani::stub(reallyme_crypto::dispatch::verify, observe_backend)]
fn sign1_boundary_structure_reaches_the_backend_byte_for_byte() {
    let attached: bool = kani::any();
    let cases: [usize; 3] = [boundary_case(), boundary_case(), boundary_case()];
    let [_, aad_len, payload_len] = cases.map(|case| LENGTHS[case]);
    let wire = [u8::from(attached)];
    let aad = [AAD_BYTE; MAX_FIELD_LEN];
    let external_aad = &aad[..aad_len];
    let body = [PAYLOAD_BYTE; MAX_FIELD_LEN];
    let detached_payload = &body[..payload_len];
    let policy = CosePolicy::default();

    let Some(expected_len) = cases.iter().try_fold(CONTEXT_LEN, |total, &case| {
        total.checked_add(ENCODED_FIELD_LEN[case])
    }) else {
        assert!(
            false,
            "the boundary Sig_structure must have a representable size"
        );
        return;
    };
    let picked = usize::from(kani::any::<u16>());
    kani::assume(picked < expected_len);
    OBSERVATION.set(Some(Observation {
        cases,
        attached,
        picked,
        expected_len,
        expected_byte: 0,
        fields: [
            None,
            Some(external_aad),
            (!attached).then_some(detached_payload),
        ],
        encoded: None,
    }));
    if attached {
        let input = CoseSign1VerifyInput::new(&wire, external_aad, &policy);
        let _result = verify_cose_sign1(input, resolve_fixture);
    } else {
        let input =
            CoseSign1DetachedVerifyInput::new(&wire, detached_payload, external_aad, &policy);
        let _result = verify_detached_cose_sign1(input, resolve_fixture);
    }
    assert!(
        false,
        "a valid boundary fixture must reach backend observation"
    );
}

fn boundary_case() -> usize {
    let case = usize::from(kani::any::<u8>());
    kani::assume(case < LENGTHS.len());
    case
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn decoded_boundary_fixture(wire: &[u8], max_len: usize) -> Result<DecodedCoseSign1, CoseError> {
    let mut observation = OBSERVATION.get().ok_or(CoseError::InvalidFormat)?;
    assert!(wire == [u8::from(observation.attached)] && wire.len() <= max_len);
    let mut cose = CoseSign1::default();
    let original = vec![PROTECTED_BYTE; LENGTHS[observation.cases[0]]];
    observation.fields[0] = Some(original.as_slice());
    cose.protected.original_data = Some(original);
    cose.protected.header.alg = Some(RegisteredLabelWithPrivate::Assigned(
        iana::Algorithm::Ed25519,
    ));
    cose.protected.header.key_id = vec![KID];
    if observation.attached {
        let payload = vec![PAYLOAD_BYTE; LENGTHS[observation.cases[2]]];
        observation.fields[2] = Some(payload.as_slice());
        cose.payload = Some(payload);
    }
    cose.signature = SIGNATURE.to_vec();
    OBSERVATION.set(Some(observation));
    Ok(DecodedCoseSign1 {
        cose: SensitiveCoseSign1::new(cose),
        tagged: false,
    })
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn checked_fixture(bytes: &[u8]) -> Result<(), CoseError> {
    let observation = OBSERVATION.get().ok_or(CoseError::InvalidFormat)?;
    assert!(observation.fields[0].is_some_and(|expected| core::ptr::eq(expected, bytes)));
    Ok(())
}

fn resolve_fixture(algorithm: CoseSignatureAlgorithm, kid: &[u8]) -> CoseSign1KeyResolution {
    assert!(algorithm == CoseSignatureAlgorithm::Ed25519);
    assert!(kid == [KID]);
    CoseSign1KeyResolution::Resolved(Zeroizing::new(vec![KEY]))
}

// The separate builder proofs establish the encoded bytes. Check the three
// input slices here and supply arbitrary contents at the boundary-case length
// so the dispatch check also covers changes conditioned on other bytes.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn model_built_structure(
    protected: &ProtectedHeader,
    aad: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let mut observation = OBSERVATION.get().ok_or(CoseError::InvalidFormat)?;
    let original = protected
        .original_data
        .as_deref()
        .ok_or(CoseError::InvalidFormat)?;
    for (expected, actual) in observation.fields.into_iter().zip([original, aad, payload]) {
        assert!(expected.is_some_and(|expected| core::ptr::eq(expected, actual)));
    }
    let bytes: [u8; MAX_MESSAGE_LEN] = kani::any();
    let encoded = Zeroizing::new(bytes[..observation.expected_len].to_vec());
    observation.expected_byte = encoded[observation.picked];
    observation.encoded = Some(encoded.as_slice());
    OBSERVATION.set(Some(observation));
    Ok(encoded)
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn observe_backend(
    algorithm: Algorithm,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), AlgorithmError> {
    let Some(observation) = OBSERVATION.get() else {
        assert!(false, "backend reached without an observation");
        return Ok(());
    };
    assert!(algorithm == Algorithm::Ed25519 && key == [KEY]);
    super::assert_fixture_signature(signature);
    assert!(observation
        .encoded
        .is_some_and(|expected| core::ptr::eq(expected, message)));
    assert!(message.len() == observation.expected_len);
    assert!(message.get(observation.picked) == Some(&observation.expected_byte));
    kani::cover!(
        observation.attached
            && observation.cases[0] == 0
            && observation.cases[1] == 1
            && observation.cases[2] == 2,
        "attached mixed boundaries reach the backend"
    );
    kani::cover!(
        !observation.attached
            && observation.cases[0] == 3
            && observation.cases[1] == 2
            && observation.cases[2] == 1,
        "detached mixed boundaries reach the backend"
    );
    kani::cover!(
        observation.picked.checked_add(1) == Some(observation.expected_len),
        "the last encoded byte reaches the backend"
    );
    // The authentication-gate proofs cover backend outcomes. End this proof
    // at dispatch to keep allocation cleanup outside the handoff property.
    kani::assume(false);
    Ok(())
}
