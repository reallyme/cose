// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::ManuallyDrop;

use ciborium::Value;
use coset::{iana, CoseEncrypt, Header, ProtectedHeader, RegisteredLabelWithPrivate};
use zeroize::Zeroizing;

use super::{authenticate_body, CoseContentEncryptionAlgorithm, CoseError};
use crate::encrypt::codec::{AES_GCM_NONCE_LENGTH, AES_GCM_TAG_LENGTH};

const MAX_CONTENT_KEY_BYTES: usize = 32;
const FIXTURE_CIPHERTEXT_BYTES: usize = AES_GCM_TAG_LENGTH + 1;
const CONTEXT_PREFIX: &[u8] = b"\x83\x67Encrypt";

#[derive(Clone, Copy)]
struct ExpectedAeadInput {
    algorithm: CoseContentEncryptionAlgorithm,
    aad: [u8; 16],
    aad_len: usize,
    key: *const [u8],
    nonce: *const [u8],
    ciphertext: *const [u8],
}

std::thread_local! {
    static EXPECTED_AEAD: Cell<Option<ExpectedAeadInput>> = const { Cell::new(None) };
}

#[kani::proof]
#[kani::unwind(22)]
#[kani::stub(crate::encode_cbor::encode_cbor_value, serialize_fixture)]
#[kani::stub(super::encode_protected_header, model_received_protected)]
#[kani::stub(super::decrypt_content, observe_aead_input)]
fn ml_kem_body_authentication_preserves_enc_structure_and_aead_inputs() {
    let algorithm_id: u8 = kani::any();
    kani::assume(matches!(algorithm_id, 1..=3));
    let (algorithm, cose_algorithm, key_len) = match algorithm_id {
        1 => (
            CoseContentEncryptionAlgorithm::Aes128Gcm,
            iana::Algorithm::A128GCM,
            16,
        ),
        2 => (
            CoseContentEncryptionAlgorithm::Aes192Gcm,
            iana::Algorithm::A192GCM,
            24,
        ),
        _ => (
            CoseContentEncryptionAlgorithm::Aes256Gcm,
            iana::Algorithm::A256GCM,
            32,
        ),
    };
    let key = ManuallyDrop::new(Zeroizing::new(kani::any::<[u8; MAX_CONTENT_KEY_BYTES]>()));
    let nonce: [u8; AES_GCM_NONCE_LENGTH] = kani::any();
    let ciphertext: [u8; FIXTURE_CIPHERTEXT_BYTES] = kani::any();
    let aad: [u8; 2] = kani::any();
    let include_aad: bool = kani::any();
    let external_aad = if include_aad { &aad[..] } else { &[] };
    let key = &key[..key_len];

    // The verifier borrows the decoded body. Recursive cleanup of this
    // synthetic fixture lies outside the handoff check.
    let cose = ManuallyDrop::new(CoseEncrypt {
        protected: ProtectedHeader {
            original_data: Some(vec![0xa1, 0x01, algorithm_id]),
            header: Header {
                alg: Some(RegisteredLabelWithPrivate::Assigned(cose_algorithm)),
                ..Header::default()
            },
        },
        unprotected: Header {
            iv: nonce.to_vec(),
            ..Header::default()
        },
        ciphertext: Some(ciphertext.to_vec()),
        ..CoseEncrypt::default()
    });
    let Some(ciphertext) = cose.ciphertext.as_deref() else {
        assert!(false, "the fixture has a received ciphertext");
        return;
    };
    // Independent RFC 9052 encoding of the received protected bstr and AAD.
    let mut expected = *b"\x83\x67Encrypt\x43\xa1\x01\x00\x40\x00\x00";
    expected[12] = algorithm_id;
    let aad_len = if include_aad {
        expected[13] = 0x42;
        expected[14..].copy_from_slice(external_aad);
        16
    } else {
        14
    };
    EXPECTED_AEAD.set(Some(ExpectedAeadInput {
        algorithm,
        aad: expected,
        aad_len,
        key,
        nonce: cose.unprotected.iv.as_slice(),
        ciphertext,
    }));
    let _result = authenticate_body(&cose, algorithm, key, external_aad);
    assert!(false, "a valid body must reach the AEAD boundary");
}

// Observe the real Enc_structure fields and model CBOR serialization for
// this bounded shape. Native vectors exercise the real serializer.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn serialize_fixture(value: Value) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let value = ManuallyDrop::new(value);
    let Some([Value::Text(context), Value::Bytes(protected), Value::Bytes(aad)]) =
        value.as_array().map(Vec::as_slice)
    else {
        assert!(false, "only the Enc_structure may be serialized");
        return Err(CoseError::InvalidFormat);
    };
    assert!(context == "Encrypt");
    assert!(protected.len() == 3 && matches!(aad.len(), 0 | 2));
    let mut bytes = Zeroizing::new(Vec::with_capacity(16));
    bytes.extend_from_slice(CONTEXT_PREFIX);
    bytes.push(0x43);
    bytes.extend_from_slice(protected);
    bytes.push(if aad.is_empty() { 0x40 } else { 0x42 });
    bytes.extend_from_slice(aad);
    Ok(bytes)
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn observe_aead_input(
    algorithm: CoseContentEncryptionAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let expected = EXPECTED_AEAD.get().ok_or(CoseError::InvalidFormat)?;
    assert!(algorithm == expected.algorithm);
    assert!(core::ptr::eq(key, expected.key));
    assert!(core::ptr::eq(nonce, expected.nonce));
    assert!(core::ptr::eq(ciphertext, expected.ciphertext));
    assert!(aad == &expected.aad[..expected.aad_len]);
    kani::cover!(
        algorithm == CoseContentEncryptionAlgorithm::Aes128Gcm && aad.len() == 14,
        "AES-128-GCM authenticates an empty external AAD bstr"
    );
    kani::cover!(
        algorithm == CoseContentEncryptionAlgorithm::Aes192Gcm && aad.len() == 16,
        "AES-192-GCM authenticates the supplied external AAD bytes"
    );
    kani::cover!(
        algorithm == CoseContentEncryptionAlgorithm::Aes256Gcm && aad.len() == 16,
        "AES-256-GCM authenticates the supplied external AAD bytes"
    );
    // The authentication-gate proof covers backend outcomes.
    kani::assume(false);
    Err(CoseError::AuthenticationFailed)
}

#[kani::proof]
#[kani::stub(
    zeroize::optimization_barrier,
    crate::verify_zeroize_barrier_proof_tests::observe_barrier
)]
#[kani::unwind(12)]
#[kani::stub(crate::encode_cbor::encode_cbor_value, reject_reserialization)]
fn ml_kem_body_authentication_preserves_the_received_protected_bstr() {
    let received: [u8; 3] = kani::any();
    let header = ManuallyDrop::new(ProtectedHeader {
        original_data: Some(received.to_vec()),
        header: Header::default(),
    });
    let encoded = super::encode_protected_header(&header);
    assert!(matches!(encoded, Ok(bytes) if bytes.as_slice() == received));
    kani::cover!(
        received == [0xa1, 0x01, 0x03],
        "received AES-256-GCM header bytes are preserved"
    );
}

// The separate protected-header proof checks the real original-data branch.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn model_received_protected(header: &ProtectedHeader) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    header
        .original_data
        .as_ref()
        .map(|bytes| Zeroizing::new(bytes.clone()))
        .ok_or(CoseError::InvalidFormat)
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn reject_reserialization(_value: Value) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    assert!(
        false,
        "received protected bytes must bypass header serialization"
    );
    Err(CoseError::Cbor)
}
