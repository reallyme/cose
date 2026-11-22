// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, hex, reason, success, suite, Cases};
use crate::api::contract::{
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
    CoseErrorReason, CoseIsoSign1Content, CoseIsoSign1VerifyRequest, CoseKeySource,
    CoseSignatureConvertRequest, CoseSignatureEncoding, CoseSuiteInfoRequest,
    CoseVerificationKeyImportRequest,
};
use crate::CoseError;
use serde::Deserialize;

#[derive(Deserialize)]
struct IsoCase {
    algorithm: i64,
    curve: i64,
    public_key_hex: String,
    cose_key_hex: String,
    protected_hex: String,
    payload_hex: String,
    attached_hex: String,
    detached_hex: String,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn iso_exact_registration_import_and_verification_match_independent_answers(
) -> Result<(), CoseError> {
    let vectors: Cases<IsoCase> =
        serde_json::from_str(include_str!("../../tests/fixtures/iso18013-sign1.json"))
            .map_err(|_| CoseError::Cbor)?;
    assert_eq!(vectors.cases.len(), 10);
    for case in vectors.cases {
        let selected = suite(case.algorithm, case.curve)?;
        let native_suite = super::super::profile_input::iso_suite(&selected)
            .map_err(|_| CoseError::UnsupportedAlgorithm)?;
        let supported = native_suite.has_builtin_provider();
        for cose in [false, true] {
            let input = CoseVerificationKeyImportRequest {
                suite: field(selected.clone()),
                public_key: hex(if cose {
                    &case.cose_key_hex
                } else {
                    &case.public_key_hex
                })
                .into(),
                public_key_is_cose: cose,
                context_id: vec![0; 32].into(),
                require_iso_pair: false,
            };
            let response = codec_parity(Operation::VerificationKeyImport(Box::new(input)))?;
            if supported {
                let Branch::VerificationKeyImport(key) = &mut success(response) else {
                    return Err(CoseError::InvalidFormat);
                };
                assert!(!key.public_key.is_empty());
            } else {
                assert_eq!(reason(&response), CoseErrorReason::ProviderUnavailable);
            }
        }
        for (role, encoded) in [
            (CoseIsoSign1Content::IssuerAttached, &case.attached_hex),
            (CoseIsoSign1Content::DeviceDetached, &case.detached_hex),
            (CoseIsoSign1Content::ReaderDetached, &case.detached_hex),
        ] {
            let input = CoseIsoSign1VerifyRequest {
                encoded: hex(encoded).into(),
                content: role.into(),
                detached_payload: if role == CoseIsoSign1Content::IssuerAttached {
                    Vec::new().into()
                } else {
                    hex(&case.payload_hex).into()
                },
                allowed_suites: vec![selected.clone()].into(),
                key_suite: field(selected.clone()),
                public_key: hex(&case.public_key_hex).into(),
                public_key_is_cose: false,
                key_source: CoseKeySource::Direct.into(),
                capability: super::support::capability(
                    0,
                    crate::api::contract::CoseProviderKind::VerificationKey,
                ),
                limits: Default::default(),
            };
            let response = codec_parity(Operation::IsoSign1Verify(Box::new(input)))?;
            if supported {
                let Branch::IsoSign1Verify(value) = &mut success(response) else {
                    return Err(CoseError::InvalidFormat);
                };
                assert_eq!(value.suite.as_option(), Some(&selected));
                assert_eq!(value.protected_headers, hex(&case.protected_hex));
                assert_eq!(
                    value.attached_payload.is_some(),
                    role == CoseIsoSign1Content::IssuerAttached
                );
                if value.attached_payload.is_some() {
                    assert_eq!(
                        value.attached_payload.as_deref(),
                        Some(hex(&case.payload_hex).as_slice())
                    );
                }
            } else {
                assert_eq!(reason(&response), CoseErrorReason::ProviderUnavailable);
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct SignatureCase {
    curve: i64,
    algorithm: i64,
    signature: String,
    der: String,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn exact_suite_inspection_and_signature_representations_match_every_named_curve(
) -> Result<(), CoseError> {
    let vectors: Cases<SignatureCase> =
        serde_json::from_str(include_str!("../../tests/fixtures/peer-keys.json"))
            .map_err(|_| CoseError::Cbor)?;
    for case in vectors.cases.into_iter().filter(|c| c.algorithm != 0) {
        let curve = i32::try_from(case.curve).map_err(|_| CoseError::InvalidFormat)?;
        let encoded = if matches!(case.curve, 6 | 7) {
            CoseSignatureEncoding::Eddsa
        } else {
            CoseSignatureEncoding::CoseEcdsa
        };
        let raw = hex(&case.signature);
        let validate = CoseSignatureConvertRequest {
            curve: curve.into(),
            encoding: encoded.into(),
            signature: raw.clone().into(),
        };
        let validation = codec_parity(Operation::SignatureValidate(Box::new(validate)))?;
        if raw.is_empty() {
            // The P320 fixture provides a named point, but no signature answer.
            // Empty signatures must fail; suite identity remains independently tested.
            assert_eq!(
                reason(&validation),
                CoseErrorReason::Sign1InvalidSignatureEncoding
            );
        } else {
            assert!(matches!(success(validation), Branch::SignatureValidate(_)));
        }
        if !case.der.is_empty() {
            let input = CoseSignatureConvertRequest {
                curve: curve.into(),
                encoding: CoseSignatureEncoding::EcdsaDer.into(),
                signature: hex(&case.der).into(),
            };
            let Branch::SignatureToCose(value) =
                &mut success(codec_parity(Operation::SignatureToCose(Box::new(input)))?)
            else {
                return Err(CoseError::InvalidFormat);
            };
            assert_eq!(value.encoded, raw);
            let input = CoseSignatureConvertRequest {
                curve: curve.into(),
                encoding: CoseSignatureEncoding::CoseEcdsa.into(),
                signature: raw.into(),
            };
            let Branch::SignatureToDer(value) =
                &mut success(codec_parity(Operation::SignatureToDer(Box::new(input)))?)
            else {
                return Err(CoseError::InvalidFormat);
            };
            assert_eq!(value.encoded, hex(&case.der));
        }
        let info = CoseSuiteInfoRequest {
            suite: field(suite(case.algorithm, case.curve)?),
            require_iso_pair: true,
        };
        let Branch::SignatureSuiteInfo(value) =
            &mut success(codec_parity(Operation::SignatureSuiteInfo(Box::new(info)))?)
        else {
            return Err(CoseError::InvalidFormat);
        };
        assert!(value.signature_bytes != 0);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn brainpool_p320_reader_conversion_preserves_der_and_fixed_width_bytes() -> Result<(), CoseError> {
    use crate::containers::{cose_signature_to_der, signature_to_cose, SignatureEncoding};
    use crate::iso18013::Iso18013SignatureCurve;
    use zeroize::Zeroizing;

    // Canonical DER SEQUENCE { INTEGER 1, INTEGER 2 }. This tests encoding,
    // not cryptographic verification or availability of a P320 provider.
    const DER: &[u8] = b"\x30\x06\x02\x01\x01\x02\x01\x02";
    const COORDINATE_BYTES: usize = 40;
    let width = COORDINATE_BYTES
        .checked_mul(2)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let mut expected = Zeroizing::new(vec![0; width]);
    let r = COORDINATE_BYTES
        .checked_sub(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let s = width
        .checked_sub(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    expected[r] = 1;
    expected[s] = 2;
    let curve = Iso18013SignatureCurve::BrainpoolP320r1;
    let raw = signature_to_cose(curve, SignatureEncoding::EcdsaDer, DER)?;
    assert_eq!(raw, expected);
    assert_eq!(cose_signature_to_der(curve, &raw)?.as_slice(), DER);

    let curve = i32::try_from(curve.identifier()).map_err(|_| CoseError::InvalidFormat)?;
    let input = CoseSignatureConvertRequest {
        curve: curve.into(),
        encoding: CoseSignatureEncoding::EcdsaDer.into(),
        signature: DER.to_vec().into(),
    };
    let output = success(codec_parity(Operation::SignatureToCose(Box::new(input)))?);
    let Branch::SignatureToCose(output) = &output else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(output.encoded.as_slice(), expected.as_slice());
    let input = CoseSignatureConvertRequest {
        curve: curve.into(),
        encoding: CoseSignatureEncoding::CoseEcdsa.into(),
        signature: raw.to_vec().into(),
    };
    let output = success(codec_parity(Operation::SignatureToDer(Box::new(input)))?);
    let Branch::SignatureToDer(output) = &output else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(output.encoded.as_slice(), DER);
    Ok(())
}
