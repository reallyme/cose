// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use coset::{Header, ProtectedHeader};

use super::{build_received_sig_structure, build_sig_structure};
use crate::limits::MAX_DETACHED_PAYLOAD_BYTES;
use crate::{
    cose_verify1_detached_with_exact_algorithm, cose_verify1_with_exact_algorithm, Algorithm,
    CoseError, CosePolicy, CoseSignatureAlgorithm,
};

#[test]
fn encodes_the_canonical_cose_signature1_structure() -> Result<(), CoseError> {
    let encoded = build_sig_structure(&[0xa1, 0x01, 0x27], &[0x01], b"payload")?;

    assert_eq!(
        encoded.as_slice(),
        [
            0x84, 0x6a, b'S', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b'1', 0x43, 0xa1,
            0x01, 0x27, 0x41, 0x01, 0x47, b'p', b'a', b'y', b'l', b'o', b'a', b'd',
        ]
    );
    Ok(())
}

#[test]
fn accepts_the_documented_maximum_payload() -> Result<(), CoseError> {
    let payload = vec![0x5a; MAX_DETACHED_PAYLOAD_BYTES];
    let encoded = build_sig_structure(&[], &[], &payload)?;

    let payload_header_offset = 14;
    assert_eq!(
        &encoded[payload_header_offset..payload_header_offset + 5],
        &[0x5a, 0x00, 0x10, 0x00, 0x00]
    );
    assert_eq!(encoded.len(), payload.len() + payload_header_offset + 5);
    Ok(())
}

#[test]
fn signature1_structure_preserves_original_bytes_and_field_order() -> Result<(), CoseError> {
    // The original bstr contains kid before alg. Vary every identifier byte and
    // use distinct AAD and payload bytes to detect substituted fields.
    for kid in u8::MIN..=u8::MAX {
        check_received_structure(kid, kid ^ 0x55, kid ^ 0xaa)?;
    }
    Ok(())
}

fn check_received_structure(kid: u8, aad: u8, payload: u8) -> Result<(), CoseError> {
    let protected = [0xa2, 0x04, 0x41, kid, 0x01, 0x27];
    let received = ProtectedHeader {
        original_data: Some(protected.to_vec()),
        header: Header::default(),
    };

    let encoded = build_received_sig_structure(&received, &[aad], &[payload])?;
    // Independent RFC 9052 encoding for this input.
    let mut expected = *b"\x84\x6aSignature1\x46\xa2\x04\x41\x00\x01\x27\x41\x00\x41\x00";
    expected[16] = kid;
    expected[20] = aad;
    expected[22] = payload;
    assert_eq!(encoded.as_slice(), expected);
    Ok(())
}

#[test]
fn received_signature1_fields_match_independent_cbor_at_mixed_boundaries() -> Result<(), CoseError>
{
    check_boundary_fixtures(|protected, aad, payload, expected| {
        let received = ProtectedHeader {
            original_data: Some(protected.to_vec()),
            header: Header::default(),
        };
        let encoded = build_received_sig_structure(&received, aad, payload)?;
        assert_eq!(
            encoded.as_slice(),
            expected,
            "field lengths {}, {}, {}",
            protected.len(),
            aad.len(),
            payload.len()
        );
        Ok(())
    })
}

#[test]
fn boundary_sign1_verification_authenticates_independently_encoded_bytes() -> Result<(), CoseError>
{
    let (public, private) = reallyme_crypto::dispatch::generate_keypair(Algorithm::Ed25519)
        .map_err(|_| CoseError::Crypto)?;
    let policy = CosePolicy::default();
    check_boundary_fixtures(|protected, aad, payload, expected| {
        // Sign the independent CBOR encoding with the primitive so agreement
        // between the library's signing and verification builders cannot
        // conceal a shared serialization error.
        let signature = reallyme_crypto::dispatch::sign(Algorithm::Ed25519, &private, expected)
            .map_err(|_| CoseError::Crypto)?;
        let attached = encode_sign1_fixture(protected, Some(payload), &signature)?;
        let detached = encode_sign1_fixture(protected, None, &signature)?;
        let resolve = |algorithm, _: &[u8]| {
            assert_eq!(algorithm, CoseSignatureAlgorithm::Ed25519);
            Some(public.clone())
        };

        let verified = cose_verify1_with_exact_algorithm(&attached, aad, &policy, resolve)?;
        assert_eq!(verified.payload.as_slice(), payload);
        let detached_verified =
            cose_verify1_detached_with_exact_algorithm(&detached, payload, aad, &policy, resolve)?;
        assert_eq!(detached_verified.cose_algorithm, verified.cose_algorithm);

        let mut changed_aad = aad.to_vec();
        *changed_aad.last_mut().ok_or(CoseError::InvalidFormat)? ^= 1;
        assert_eq!(
            cose_verify1_with_exact_algorithm(&attached, &changed_aad, &policy, resolve).err(),
            Some(CoseError::InvalidSignature)
        );
        assert_eq!(
            cose_verify1_detached_with_exact_algorithm(
                &detached,
                payload,
                &changed_aad,
                &policy,
                resolve,
            )
            .err(),
            Some(CoseError::InvalidSignature)
        );

        let mut changed_payload = payload.to_vec();
        *changed_payload.last_mut().ok_or(CoseError::InvalidFormat)? ^= 1;
        let changed_attached = encode_sign1_fixture(protected, Some(&changed_payload), &signature)?;
        assert_eq!(
            cose_verify1_with_exact_algorithm(&changed_attached, aad, &policy, resolve).err(),
            Some(CoseError::InvalidSignature)
        );
        assert_eq!(
            cose_verify1_detached_with_exact_algorithm(
                &detached,
                &changed_payload,
                aad,
                &policy,
                resolve,
            )
            .err(),
            Some(CoseError::InvalidSignature)
        );

        // Both alg bytes follow the key ID in this fixture. Changing the
        // last key ID byte leaves the map valid and the resolver available.
        let mut changed_protected = protected.to_vec();
        let last_kid = protected
            .len()
            .checked_sub(3)
            .ok_or(CoseError::InvalidFormat)?;
        changed_protected[last_kid] ^= 1;
        let changed_attached = encode_sign1_fixture(&changed_protected, Some(payload), &signature)?;
        let changed_detached = encode_sign1_fixture(&changed_protected, None, &signature)?;
        assert_eq!(
            cose_verify1_with_exact_algorithm(&changed_attached, aad, &policy, resolve).err(),
            Some(CoseError::InvalidSignature)
        );
        assert_eq!(
            cose_verify1_detached_with_exact_algorithm(
                &changed_detached,
                payload,
                aad,
                &policy,
                resolve,
            )
            .err(),
            Some(CoseError::InvalidSignature)
        );
        Ok(())
    })
}

fn check_boundary_fixtures(
    mut check: impl FnMut(&[u8], &[u8], &[u8], &[u8]) -> Result<(), CoseError>,
) -> Result<(), CoseError> {
    const FIELD_LENGTHS: [usize; 4] = [23, 24, 255, 256];

    for (protected_len, kid_len) in [(23, 18), (24, 19), (255, 249), (256, 250)] {
        // The key ID comes before alg on the wire. Its own length prefix
        // widens for the two larger fixtures.
        let protected = encode_fixture(&Value::Map(vec![
            (
                Value::Integer(4.into()),
                Value::Bytes(patterned_bytes(kid_len, 0x33)),
            ),
            (Value::Integer(1.into()), Value::Integer((-19).into())),
        ]))?;
        assert_eq!(protected.len(), protected_len);
        for aad_len in FIELD_LENGTHS {
            for payload_len in FIELD_LENGTHS {
                let aad = patterned_bytes(aad_len, 0x55);
                let payload = patterned_bytes(payload_len, 0xaa);
                let expected = encode_fixture(&Value::Array(vec![
                    Value::Text("Signature1".into()),
                    Value::Bytes(protected.clone()),
                    Value::Bytes(aad.clone()),
                    Value::Bytes(payload.clone()),
                ]))?;
                check(&protected, &aad, &payload, &expected)?;
            }
        }
    }
    Ok(())
}

fn encode_sign1_fixture(
    protected: &[u8],
    payload: Option<&[u8]>,
    signature: &[u8],
) -> Result<Vec<u8>, CoseError> {
    encode_fixture(&Value::Array(vec![
        Value::Bytes(protected.to_vec()),
        Value::Map(Vec::new()),
        payload.map_or(Value::Null, |bytes| Value::Bytes(bytes.to_vec())),
        Value::Bytes(signature.to_vec()),
    ]))
}

fn patterned_bytes(length: usize, mask: u8) -> Vec<u8> {
    (u8::MIN..=u8::MAX)
        .take(length)
        .map(|byte| byte ^ mask)
        .collect()
}

fn encode_fixture(value: &Value) -> Result<Vec<u8>, CoseError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|_| CoseError::Cbor)?;
    Ok(bytes)
}
