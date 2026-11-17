// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::rsa_support::{encode, fixture, request, sign1, suite};
use super::support::{codec_parity, hex, reason, success};
use crate::api::contract::{
    self as wire, cose_operation_request::Operation, cose_operation_result::Result as Branch,
};
use crate::CoseError;

fn verify(
    input: wire::CoseRsaSign1VerifyRequest,
) -> Result<wire::CoseOperationResponseV2, CoseError> {
    codec_parity(Operation::RsaSign1Verify(Box::new(input)))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_sign1_all_six_independent_suites_verify_exact_protected_bytes() -> Result<(), CoseError> {
    let vectors = fixture()?;
    let payload = hex(&vectors.payload);
    for case in &vectors.cases {
        assert!(case.id.starts_with("PS") || case.id.starts_with("RS"));
        assert_eq!(
            crate::sign1::build_sign1_signature_structure(
                &hex(&case.protected),
                &hex(&vectors.aad),
                &hex(&vectors.payload),
                1_048_576
            )?
            .as_slice(),
            hex(&case.sign1_structure)
        );
        for detached in [false, true] {
            let result = success(verify(request(&vectors, case, detached)?)?);
            let Branch::RsaSign1Verify(result) = &result else {
                return Err(CoseError::InvalidFormat);
            };
            assert_eq!(result.suite.as_option(), Some(&suite(case)?));
            assert_eq!(result.protected.as_slice(), hex(&case.protected));
            assert_eq!(result.protected_kid.as_deref(), Some(b"rsa".as_slice()));
            assert_eq!(
                result.attached_payload.as_deref(),
                if detached {
                    None
                } else {
                    Some(payload.as_slice())
                }
            );
        }
        let mut input = request(&vectors, case, false)?;
        input.encoded = hex(&case.empty_aad_sign1).into();
        input.external_aad = Vec::new().into();
        let _ = success(verify(input)?);
        let mut input = request(&vectors, case, true)?;
        input.encoded = hex(&case.empty_payload_detached).into();
        input.detached_payload = Some(Vec::new().into());
        let _ = success(verify(input)?);
    }
    fn zeroizing<T: zeroize::ZeroizeOnDrop>() {}
    zeroizing::<wire::CoseRsaSign1VerifyRequest>();
    zeroizing::<wire::CoseRsaSign1VerifyResult>();
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_sign1_rejects_changed_payload_aad_protected_signature_and_key() -> Result<(), CoseError> {
    let vectors = fixture()?;
    for case in &vectors.cases {
        for detached in [false, true] {
            let baseline = request(&vectors, case, detached)?;
            for changed in 0..5 {
                let mut input = baseline.clone();
                let mut protected = hex(&case.protected);
                let mut payload = hex(&vectors.payload);
                let mut signature = hex(&case.signature);
                match changed {
                    0 => *payload.first_mut().ok_or(CoseError::InvalidFormat)? ^= 1,
                    1 => input.external_aad = vec![0].into(),
                    2 => {
                        // Same semantic map, different exact authenticated order.
                        let mut reordered = vec![0xa2, 1];
                        let original = hex(&case.protected);
                        reordered
                            .extend_from_slice(original.get(7..).ok_or(CoseError::InvalidFormat)?);
                        reordered.extend_from_slice(b"\x04\x43rsa");
                        protected = reordered;
                    }
                    3 => *signature.last_mut().ok_or(CoseError::InvalidFormat)? ^= 1,
                    _ => {
                        input
                            .key
                            .as_option_mut()
                            .ok_or(CoseError::InvalidFormat)?
                            .public_key = hex(&vectors.wrong_public_spki).into()
                    }
                }
                input.encoded = sign1(
                    &protected,
                    if detached { None } else { Some(&payload) },
                    &signature,
                )?
                .into();
                if detached {
                    input.detached_payload = Some(payload.into());
                }
                assert_eq!(
                    reason(&verify(input)?),
                    CoseError::InvalidSignature.reason()
                );
            }
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_pss_rejects_non_cose_mgf_and_salt_parameters() -> Result<(), CoseError> {
    let vectors = fixture()?;
    for case in &vectors.cases {
        for signature in [&case.wrong_mgf_signature, &case.wrong_salt_signature]
            .into_iter()
            .flatten()
        {
            let mut input = request(&vectors, case, false)?;
            input.encoded = sign1(
                &hex(&case.protected),
                Some(&hex(&vectors.payload)),
                &hex(signature),
            )?
            .into();
            assert_eq!(
                reason(&verify(input)?),
                CoseError::InvalidSignature.reason()
            );
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_profile_requires_exact_registration_allowlist_curve_and_kid_binding() -> Result<(), CoseError>
{
    let vectors = fixture()?;
    for case in &vectors.cases {
        let baseline = request(&vectors, case, false)?;
        for changed in 0..7 {
            let mut input = baseline.clone();
            let expected = match changed {
                0 => {
                    input.allowed_suites.clear();
                    CoseError::UnsupportedAlgorithm.reason()
                }
                1 => {
                    input.allowed_suites.push(suite(case)?);
                    CoseError::InvalidFormat.reason()
                }
                2 => {
                    input
                        .key
                        .as_option_mut()
                        .ok_or(CoseError::InvalidFormat)?
                        .suite
                        .as_option_mut()
                        .ok_or(CoseError::InvalidFormat)?
                        .curve = wire::CoseNamedCurve::P256.into();
                    CoseError::InvalidKeyMaterial.reason()
                }
                3 => {
                    input
                        .key
                        .as_option_mut()
                        .ok_or(CoseError::InvalidFormat)?
                        .signature_index = 1;
                    CoseError::InvalidKeyMaterial.reason()
                }
                4 => {
                    input.expected_kid = Some(b"other".to_vec().into());
                    wire::CoseErrorReason::Sign1KidKeyMismatch
                }
                5 => {
                    input
                        .key
                        .as_option_mut()
                        .ok_or(CoseError::InvalidFormat)?
                        .suite
                        .as_option_mut()
                        .ok_or(CoseError::InvalidFormat)?
                        .registration = wire::CoseSignatureAlgorithm::Unspecified.into();
                    wire::CoseErrorReason::CommonInvalidParameter
                }
                _ => {
                    input
                        .key
                        .as_option_mut()
                        .ok_or(CoseError::InvalidFormat)?
                        .suite
                        .as_option_mut()
                        .ok_or(CoseError::InvalidFormat)?
                        .registration = if case.registration == -37 {
                        wire::CoseSignatureAlgorithm::Rs256
                    } else {
                        wire::CoseSignatureAlgorithm::Ps256
                    }
                    .into();
                    CoseError::UnsupportedAlgorithm.reason()
                }
            };
            assert_eq!(reason(&verify(input)?), expected);
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_profile_rejects_weak_non_spki_trailing_keys_and_wrong_signature_lengths(
) -> Result<(), CoseError> {
    let vectors = fixture()?;
    let case = vectors.cases.first().ok_or(CoseError::InvalidFormat)?;
    for public in [
        &vectors.public_pkcs1,
        &vectors.weak_public_spki,
        &vectors.below_minimum_public_spki,
    ] {
        let mut input = request(&vectors, case, false)?;
        input
            .key
            .as_option_mut()
            .ok_or(CoseError::InvalidFormat)?
            .public_key = hex(public).into();
        assert_eq!(
            reason(&verify(input)?),
            CoseError::InvalidKeyMaterial.reason()
        );
    }
    let public = hex(&vectors.public_spki);
    for end in [
        0,
        1,
        public
            .len()
            .checked_sub(1)
            .ok_or(CoseError::InvalidFormat)?,
    ] {
        let mut input = request(&vectors, case, false)?;
        input
            .key
            .as_option_mut()
            .ok_or(CoseError::InvalidFormat)?
            .public_key = public
            .get(..end)
            .ok_or(CoseError::InvalidFormat)?
            .to_vec()
            .into();
        assert_eq!(
            reason(&verify(input)?),
            CoseError::InvalidKeyMaterial.reason()
        );
    }
    let mut input = request(&vectors, case, false)?;
    let mut trailing = public;
    trailing.push(0);
    input
        .key
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?
        .public_key = trailing.into();
    assert_eq!(
        reason(&verify(input)?),
        CoseError::InvalidKeyMaterial.reason()
    );
    for length in [0, 255, 257] {
        let mut input = request(&vectors, case, false)?;
        input.encoded = sign1(
            &hex(&case.protected),
            Some(&hex(&vectors.payload)),
            &vec![0; length],
        )?
        .into();
        assert_eq!(
            reason(&verify(input)?),
            CoseError::InvalidSignatureEncoding.reason()
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_profile_keeps_modern_defaults_and_resource_limits_closed() -> Result<(), CoseError> {
    let vectors = fixture()?;
    let case = vectors.cases.first().ok_or(CoseError::InvalidFormat)?;
    let called = core::cell::Cell::new(false);
    assert_eq!(
        crate::cose_verify1(&hex(&case.sign1), |_, _| {
            called.set(true);
            None
        })
        .err(),
        Some(CoseError::UnsupportedAlgorithm)
    );
    assert!(!called.get());
    for changed in 0..4 {
        let mut input = request(&vectors, case, true)?;
        match changed {
            0 => input.encoded = vec![0; 1_048_577].into(),
            1 => input.detached_payload = Some(vec![0; 1_048_577].into()),
            2 => input.external_aad = vec![0; 65_537].into(),
            _ => {
                input
                    .key
                    .as_option_mut()
                    .ok_or(CoseError::InvalidFormat)?
                    .public_key = vec![
                    0;
                    reallyme_crypto::rsa::RSA_PUBLIC_KEY_DER_MAX_LEN
                        .checked_add(1)
                        .ok_or(CoseError::ResourceLimitExceeded)?
                ]
                .into()
            }
        }
        assert_eq!(
            reason(&verify(input)?),
            CoseError::ResourceLimitExceeded.reason()
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_profile_rejects_wrong_tags_trailing_content_duplicates_and_critical_headers(
) -> Result<(), CoseError> {
    use ciborium::value::Value;
    let vectors = fixture()?;
    let case = vectors.cases.first().ok_or(CoseError::InvalidFormat)?;
    let baseline = request(&vectors, case, false)?;
    for changed in 0..6 {
        let mut input = baseline.clone();
        let expected = match changed {
            0 => {
                let mut encoded = input.encoded.to_vec();
                *encoded.first_mut().ok_or(CoseError::InvalidFormat)? = 0xd1;
                input.encoded = encoded.into();
                CoseError::UnexpectedCborTag
            }
            1 => {
                let mut encoded = input.encoded.to_vec();
                encoded.push(0);
                input.encoded = encoded.into();
                CoseError::Cbor
            }
            2 => {
                input.detached_payload = Some(hex(&vectors.payload).into());
                CoseError::InvalidFormat
            }
            3 => {
                input.encoded = hex(&case.sign1_detached).into();
                CoseError::InvalidFormat
            }
            4 => {
                let duplicate = encode(Value::Map(vec![
                    (1.into(), case.registration.into()),
                    (1.into(), case.registration.into()),
                ]))?;
                input.encoded = sign1(
                    &duplicate,
                    Some(&hex(&vectors.payload)),
                    &hex(&case.signature),
                )?
                .into();
                CoseError::DuplicateMapLabel
            }
            _ => {
                let critical = encode(Value::Map(vec![
                    (1.into(), case.registration.into()),
                    (2.into(), Value::Array(vec![99.into()])),
                    (99.into(), Value::Null),
                ]))?;
                input.encoded = sign1(
                    &critical,
                    Some(&hex(&vectors.payload)),
                    &hex(&case.signature),
                )?
                .into();
                CoseError::UnsupportedCriticalHeader
            }
        };
        assert_eq!(reason(&verify(input)?), expected.reason());
    }
    for (payload, expected) in [
        (Value::Bool(false), CoseError::InvalidFormat),
        (
            Value::Float(half::f16::from_bits(22).to_f64()),
            CoseError::Cbor,
        ),
    ] {
        let encoded = encode(Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(hex(&case.protected)),
                Value::Map(vec![]),
                payload,
                Value::Bytes(hex(&case.signature)),
            ])),
        ))?;
        let mut input = request(&vectors, case, true)?;
        input.encoded = encoded.into();
        assert_eq!(reason(&verify(input)?), expected.reason());
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_result_metadata_is_checked_and_sensitive_owners_are_redacted() -> Result<(), CoseError> {
    use buffa::Message;
    use wire::cose_operation_response_v2::Outcome;
    let vectors = fixture()?;
    let case = vectors.cases.first().ok_or(CoseError::InvalidFormat)?;
    let baseline = verify(request(&vectors, case, false)?)?;
    let debug = format!("{baseline:?}");
    assert!(!debug.contains("Independent RSA COSE payload"));
    for changed in 0..4 {
        let mut response = baseline.clone();
        let Some(Outcome::Result(result)) = response.outcome.as_mut() else {
            return Err(CoseError::InvalidFormat);
        };
        let Some(Branch::RsaSign1Verify(value)) = result.result.as_mut() else {
            return Err(CoseError::InvalidFormat);
        };
        match changed {
            0 => {
                value
                    .suite
                    .as_option_mut()
                    .ok_or(CoseError::InvalidFormat)?
                    .curve = wire::CoseNamedCurve::P256.into()
            }
            1 => value.protected = vec![0xa0].into(),
            2 => value.protected_kid = Some(b"other".to_vec().into()),
            _ => value.attached_payload = Some(vec![0; 1_048_577].into()),
        }
        let Err(failure) = crate::wire::decode_operation_response(&response.encode_to_vec()) else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(reason(&failure), wire::CoseErrorReason::BackendInternal);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_profile_accepts_exact_one_mib_envelope_and_rejects_the_next_byte() -> Result<(), CoseError> {
    let vectors = fixture()?;
    let case = vectors.cases.first().ok_or(CoseError::InvalidFormat)?;
    assert_eq!(case.registration, -37);
    let payload = vec![0x5a; vectors.max_payload_bytes];
    let mut input = request(&vectors, case, false)?;
    let mut encoded = sign1(
        &hex(&case.protected),
        Some(&payload),
        &hex(&vectors.max_signature),
    )?;
    assert_eq!(encoded.len(), 1_048_576);
    input.encoded = encoded.clone().into();
    let result = success(verify(input.clone())?);
    let Branch::RsaSign1Verify(result) = &result else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(result.attached_payload.as_deref(), Some(payload).as_deref());
    encoded.push(0);
    input.encoded = encoded.into();
    assert_eq!(
        reason(&verify(input)?),
        CoseError::ResourceLimitExceeded.reason()
    );
    Ok(())
}
