// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, hex, reason, success, suite, Cases};
use crate::api::contract::{
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
    CoseAgreementOptionalParameters, CoseErrorReason as Reason, CoseIsoSign1Content,
    CoseIsoSign1VerifyRequest, CoseKeySource, CosePeerKeyPurpose, CosePeerKeyRequest,
    CoseVerificationKeyImportRequest,
};
use crate::containers::{
    inspect_peer_key, CryptoPeerKeyValidator, CryptoVerificationKey, OptionalKeyPolicy,
    PeerKeyUsage, SignatureSuite, VerificationKey,
};
use crate::iso18013::{Iso18013CryptoVerifier, Iso18013Verifier};
use crate::CoseError;
use buffa::Message;
use ciborium::value::Value;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Case {
    algorithm: i64,
    curve: i64,
    cose_key_hex: String,
    public_key_hex: String,
    signature_hex: String,
    sig_structure_hex: String,
    detached_hex: String,
    payload_hex: String,
    protected_hex: String,
}

fn fixtures() -> Result<Vec<Case>, CoseError> {
    serde_json::from_str::<Cases<Case>>(include_str!("../../tests/fixtures/iso18013-sign1.json"))
        .map(|v| v.cases)
        .map_err(|_| CoseError::Cbor)
}

fn int(n: i64) -> Value {
    Value::Integer(n.into())
}

fn parameters(case: &Case) -> Result<Vec<(Value, Value)>, CoseError> {
    let decoded = ciborium::de::from_reader(hex(&case.cose_key_hex).as_slice())
        .map_err(|_| CoseError::Cbor)?;
    let Value::Map(params) = decoded else {
        return Err(CoseError::InvalidFormat);
    };
    Ok(params)
}

fn encode(params: Vec<(Value, Value)>) -> Result<Vec<u8>, CoseError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(params), &mut bytes).map_err(|_| CoseError::Cbor)?;
    Ok(bytes)
}

fn input(encoded: &[u8], selected: SignatureSuite) -> Result<CosePeerKeyRequest, CoseError> {
    Ok(CosePeerKeyRequest {
        cose_key: encoded.to_vec().into(),
        purpose: CosePeerKeyPurpose::Signature.into(),
        signature_suite: field(suite(
            selected.registration().identifier(),
            selected.curve().identifier(),
        )?),
        optional_parameters: CoseAgreementOptionalParameters::ValidateCose.into(),
        capability: Default::default(),
    })
}

fn import_request(encoded: &[u8], selected: SignatureSuite) -> Operation {
    Operation::VerificationKeyImport(Box::new(CoseVerificationKeyImportRequest {
        suite: field(selected.into()),
        public_key: encoded.to_vec().into(),
        public_key_is_cose: true,
        context_id: vec![0xa1; 32].into(),
        require_iso_pair: false,
    }))
}

fn inspect_and_validate(encoded: &[u8], selected: SignatureSuite) -> Result<(), CoseError> {
    let usage = PeerKeyUsage::Signature(selected);
    let native = inspect_peer_key(encoded, usage, OptionalKeyPolicy::Cose)?;
    assert_eq!(native.original_cose_key(), encoded);
    let Branch::VerificationKeyImport(imported) =
        &success(codec_parity(import_request(encoded, selected))?)
    else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(imported.suite.as_option(), Some(&selected.into()));
    assert_eq!(imported.public_key, native.public_material());
    assert_eq!(imported.context_id.as_slice(), &[0xa1; 32]);
    for validated in [false, true] {
        let input = Box::new(input(encoded, selected)?);
        let mut output = success(codec_parity(if validated {
            Operation::PeerKeyValidate(input)
        } else {
            Operation::PeerKeyInspect(input)
        })?);
        let output = match &mut output {
            Branch::PeerKeyInspect(output) | Branch::PeerKeyValidate(output) => output,
            _ => return Err(CoseError::InvalidFormat),
        };
        assert_eq!(output.cose_key, native.original_cose_key());
        assert_eq!(output.public_key, native.public_material());
        assert_eq!(output.validated, validated);
        assert_eq!(
            output.purpose.as_known(),
            Some(CosePeerKeyPurpose::Signature)
        );
        // Explicit clear exercises the generated sensitive owner on WASM too;
        // native allocator observation separately proves wiping before release.
        output.clear();
        assert!(output.cose_key.is_empty());
        assert!(output.public_key.is_empty());
    }
    native.validate(&CryptoPeerKeyValidator)?;
    Ok(())
}

fn assert_failure(
    encoded: &[u8],
    selected: SignatureSuite,
    expected: Reason,
) -> Result<(), CoseError> {
    let native = inspect_peer_key(
        encoded,
        PeerKeyUsage::Signature(selected),
        OptionalKeyPolicy::Cose,
    );
    assert_eq!(native.err().map(CoseError::reason), Some(expected));
    for validate in [false, true] {
        let input = Box::new(input(encoded, selected)?);
        assert_eq!(
            reason(&codec_parity(if validate {
                Operation::PeerKeyValidate(input)
            } else {
                Operation::PeerKeyInspect(input)
            })?),
            expected
        );
    }
    Ok(())
}

fn assert_import_failure(
    encoded: &[u8],
    selected: SignatureSuite,
    expected: CoseError,
) -> Result<(), CoseError> {
    assert_eq!(
        Iso18013CryptoVerifier::from_cose_key(selected, encoded).err(),
        Some(expected)
    );
    assert_eq!(
        reason(&codec_parity(import_request(encoded, selected))?),
        expected.reason()
    );
    Ok(())
}

fn select(case: &Case) -> Result<SignatureSuite, CoseError> {
    super::super::profile_input::suite(&suite(case.algorithm, case.curve)?)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn signature_base_iv_preserves_exact_keys_and_independent_verification() -> Result<(), CoseError> {
    let mut tested = 0;
    for case in fixtures()?.into_iter().filter(|case| {
        matches!(
            (case.algorithm, case.curve),
            (-7, 1) | (-35, 2) | (-36, 3) | (-8, 6)
        )
    }) {
        let selected = select(&case)?;
        let base = parameters(&case)?;
        // The only difference between these encodings is the optional parameter.
        // Both an empty bstr and arbitrary contents must leave signatures alone.
        for iv in [
            None,
            Some(Vec::new()),
            Some(vec![0xa5; 12]),
            Some(vec![0x24; 32]),
        ] {
            let mut params = base.clone();
            if let Some(iv) = iv {
                params.push((int(5), Value::Bytes(iv)));
            }
            let encoded = encode(params)?;
            inspect_and_validate(&encoded, selected)?;
            let key = inspect_peer_key(
                &encoded,
                PeerKeyUsage::Signature(selected),
                OptionalKeyPolicy::Cose,
            )?
            .validate(&CryptoPeerKeyValidator)?;
            assert_eq!(
                key.public_view().public_material(),
                hex(&case.public_key_hex)
            );
            let verifier = CryptoVerificationKey::new(
                selected,
                Zeroizing::new(key.public_view().public_material().to_vec()),
                [0; 32],
            )?;
            // Use the unchanged independent fixture's exact structure/signature;
            // Base IV is not an input to signature verification.
            verifier.verify(&hex(&case.sig_structure_hex), &hex(&case.signature_hex))?;
            Iso18013CryptoVerifier::from_cose_key(selected, &encoded)?
                .verify(&hex(&case.sig_structure_hex), &hex(&case.signature_hex))?;
            let request = CoseIsoSign1VerifyRequest {
                encoded: hex(&case.detached_hex).into(),
                content: CoseIsoSign1Content::DeviceDetached.into(),
                detached_payload: hex(&case.payload_hex).into(),
                allowed_suites: vec![selected.into()].into(),
                key_suite: field(selected.into()),
                public_key: encoded.into(),
                public_key_is_cose: true,
                key_source: CoseKeySource::Direct.into(),
                limits: Default::default(),
                capability: Default::default(),
            };
            let Branch::IsoSign1Verify(verified) =
                &success(codec_parity(Operation::IsoSign1Verify(Box::new(request)))?)
            else {
                return Err(CoseError::InvalidFormat);
            };
            assert_eq!(verified.protected_headers, hex(&case.protected_hex));
            assert_eq!(verified.suite.as_option(), Some(&selected.into()));
        }
        tested += 1;
    }
    assert_eq!(tested, 4);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn signature_base_iv_rejects_wrong_types_malformed_encoding_and_duplicates() -> Result<(), CoseError>
{
    let cases = fixtures()?;
    let case = cases.first().ok_or(CoseError::InvalidFormat)?;
    let selected = select(case)?;
    let base = parameters(case)?;
    for (malformed, expected) in [
        (int(0), CoseError::InvalidKeyMaterial),
        (int(-1), CoseError::InvalidKeyMaterial),
        (Value::Text("iv".to_owned()), CoseError::InvalidKeyMaterial),
        (Value::Bool(false), CoseError::InvalidKeyMaterial),
        (Value::Null, CoseError::InvalidKeyMaterial),
        (Value::Array(vec![int(1)]), CoseError::InvalidKeyMaterial),
        (Value::Map(Vec::new()), CoseError::InvalidKeyMaterial),
        (
            Value::Tag(24, Box::new(Value::Bytes(vec![0xa5]))),
            CoseError::UnexpectedCborTag,
        ),
        (Value::Float(1.5), CoseError::NonCanonicalCbor),
    ] {
        let mut params = base.clone();
        params.push((int(5), malformed));
        let encoded = encode(params)?;
        assert_failure(&encoded, selected, Reason::CommonCbor)?;
        assert_import_failure(&encoded, selected, expected)?;
    }
    for second in [vec![0xa5], vec![0x24]] {
        let mut params = base.clone();
        params.push((int(5), Value::Bytes(vec![0xa5])));
        params.push((int(5), Value::Bytes(second)));
        let encoded = encode(params)?;
        assert_failure(&encoded, selected, Reason::CommonDuplicateMapLabel)?;
        assert_import_failure(&encoded, selected, CoseError::DuplicateMapLabel)?;
    }
    let mut params = base.clone();
    params.push((int(5), Value::Bytes(vec![0xa5])));
    let valid = encode(params)?;
    let mut truncated = valid.clone();
    truncated.pop();
    assert_failure(&truncated, selected, Reason::CommonCbor)?;
    assert_import_failure(&truncated, selected, CoseError::Cbor)?;
    let mut trailing = valid;
    trailing.push(0);
    assert_failure(&trailing, selected, Reason::CommonCbor)?;
    assert_import_failure(&trailing, selected, CoseError::Cbor)?;
    for raw in [vec![0x58, 0], vec![0x5f, 0x41, 0xa5, 0xff]] {
        let mut encoded = encode(base.clone())?;
        assert_eq!(encoded[0], 0xa6);
        encoded[0] = 0xa7;
        encoded.push(5);
        encoded.extend_from_slice(&raw);
        assert_failure(&encoded, selected, Reason::CommonNonCanonicalCbor)?;
        assert_import_failure(&encoded, selected, CoseError::NonCanonicalCbor)?;
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn signature_base_iv_retains_algorithm_usage_public_only_and_point_checks() -> Result<(), CoseError>
{
    let cases = fixtures()?;
    let case = cases.first().ok_or(CoseError::InvalidFormat)?;
    let selected = select(case)?;
    let mut base = parameters(case)?;
    base.push((int(5), Value::Bytes(vec![0xa5; 12])));
    let invalid_material = CoseError::InvalidKeyMaterial;
    for (label, value, expected) in [
        (3, int(-8), invalid_material),
        (3, int(-9), invalid_material), // No original/modern registration substitution.
        (4, Value::Array(vec![int(1)]), invalid_material),
        (4, Value::Array(vec![int(7)]), invalid_material),
        (4, Value::Array(vec![int(8)]), invalid_material),
        (4, Value::Array(vec![int(3)]), invalid_material),
        (
            4,
            Value::Array(vec![int(2), int(2)]),
            CoseError::DuplicateMapLabel,
        ),
        (4, Value::Array(Vec::new()), invalid_material),
        (-1, int(2), invalid_material),
    ] {
        let mut params = base.clone();
        for (key, prior) in &mut params {
            if *key == int(label) {
                *prior = value.clone();
            }
        }
        let encoded = encode(params)?;
        assert_failure(&encoded, selected, Reason::KeyInvalidKeyMaterial)?;
        assert_import_failure(&encoded, selected, expected)?;
    }
    for label in [-4, -5, -99, 99] {
        let mut params = base.clone();
        params.push((int(label), Value::Bytes(vec![0x42; 32])));
        let encoded = encode(params)?;
        assert_failure(&encoded, selected, Reason::KeyInvalidKeyMaterial)?;
        assert_import_failure(&encoded, selected, CoseError::InvalidKeyMaterial)?;
    }
    // Adding this signature-only allowance must not relax agreement/HPKE
    // parameter policy. Remove signing metadata to isolate the Base IV check.
    let agreement = encode(
        base.iter()
            .filter(|(label, _)| *label != int(3) && *label != int(4))
            .cloned()
            .collect(),
    )?;
    for usage in [PeerKeyUsage::Agreement, PeerKeyUsage::HpkeRecipient] {
        assert_eq!(
            inspect_peer_key(&agreement, usage, OptionalKeyPolicy::Cose)
                .err()
                .map(CoseError::reason),
            Some(Reason::KeyInvalidKeyMaterial)
        );
    }
    let mut invalid = base;
    for (label, value) in &mut invalid {
        if *label == int(-2) || *label == int(-3) {
            *value = Value::Bytes(vec![0; 32]);
        }
    }
    let encoded = encode(invalid)?;
    // Inspection remains a shape-only operation. Mathematical validation must
    // reject the invalid point even though Base IV and coordinate widths pass.
    let inspected = inspect_peer_key(
        &encoded,
        PeerKeyUsage::Signature(selected),
        OptionalKeyPolicy::Cose,
    )?;
    assert_eq!(
        inspected
            .validate(&CryptoPeerKeyValidator)
            .err()
            .map(CoseError::reason),
        Some(Reason::KeyInvalidKeyMaterial)
    );
    assert_eq!(
        reason(&codec_parity(Operation::PeerKeyValidate(Box::new(input(
            &encoded, selected
        )?)))?),
        Reason::KeyInvalidKeyMaterial
    );
    assert_import_failure(&encoded, selected, CoseError::InvalidKeyMaterial)?;
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn signature_base_iv_respects_exact_key_byte_limit() -> Result<(), CoseError> {
    let cases = fixtures()?;
    let case = cases.first().ok_or(CoseError::InvalidFormat)?;
    let selected = select(case)?;
    let mut base = parameters(case)?;
    base.push((int(5), Value::Bytes(vec![0; 256])));
    // A 256-byte placeholder has the same CBOR length-header width as the
    // largest fitting IV. Compute the boundary from the actual key encoding.
    let overhead = encode(base.clone())?
        .len()
        .checked_sub(256)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let limit = crate::limits::MAX_COSE_KEY_BYTES;
    let length = limit
        .checked_sub(overhead)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    for (delta, accepted) in [(0, true), (1, false)] {
        let mut params = base.clone();
        let length = length
            .checked_add(delta)
            .ok_or(CoseError::ResourceLimitExceeded)?;
        let (_, value) = params.last_mut().ok_or(CoseError::InvalidFormat)?;
        *value = Value::Bytes(vec![0xa5; length]);
        let encoded = encode(params)?;
        assert_eq!(
            encoded.len(),
            limit
                .checked_add(delta)
                .ok_or(CoseError::ResourceLimitExceeded)?
        );
        if accepted {
            inspect_and_validate(&encoded, selected)?;
        } else {
            assert_failure(&encoded, selected, Reason::CommonResourceLimitExceeded)?;
            assert_import_failure(&encoded, selected, CoseError::ResourceLimitExceeded)?;
        }
    }
    let mut too_many = base;
    for label in 100..126 {
        too_many.push((int(label), Value::Bytes(Vec::new())));
    }
    assert_eq!(too_many.len(), 33);
    let encoded = encode(too_many)?;
    assert_failure(&encoded, selected, Reason::CommonResourceLimitExceeded)?;
    assert_import_failure(&encoded, selected, CoseError::ResourceLimitExceeded)?;
    Ok(())
}
