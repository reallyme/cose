// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, hex, reason, success, Cases};
use crate::api::contract::{
    self as wire,
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
};
use crate::zeroize_coset::SensitiveCborValue;
use crate::{cose_decrypt_ml_kem_with_external_aad, CoseError, CoseMlKemDecryptRequest};
use ciborium::value::Value;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Case {
    mode: String,
    private_key_seed_hex: String,
    recipient_kid_hex: String,
    plaintext_hex: String,
    external_aad_hex: String,
    supp_priv_info_hex: Option<String>,
    supp_priv_info_present: Option<bool>,
    cose_encrypt_hex: String,
}

fn cases() -> Result<Vec<Case>, CoseError> {
    serde_json::from_str::<Cases<Case>>(include_str!(
        "../../../../vectors/cose-encrypt-ml-kem.json"
    ))
    .map(|v| v.cases)
    .map_err(|_| CoseError::Cbor)
}

fn recipient_slot(value: &mut Value) -> Result<&mut Value, CoseError> {
    let value = match value {
        Value::Tag(96, value) => value.as_mut(),
        value => value,
    };
    let Value::Array(body) = value else {
        return Err(CoseError::InvalidFormat);
    };
    let Some(Value::Array(recipients)) = body.get_mut(3) else {
        return Err(CoseError::InvalidFormat);
    };
    let Some(Value::Array(recipient)) = recipients.first_mut() else {
        return Err(CoseError::InvalidFormat);
    };
    recipient.get_mut(2).ok_or(CoseError::InvalidFormat)
}

fn input(case: &Case, encoded: &[u8], private: &[u8]) -> wire::CoseMlKemDecryptRequest {
    wire::CoseMlKemDecryptRequest {
        cose_encrypt: encoded.to_vec().into(),
        recipient_private_key: private.to_vec().into(),
        expected_recipient_kid: hex(&case.recipient_kid_hex).into(),
        external_aad: hex(&case.external_aad_hex).into(),
        // The independent fixture set predates protobuf optional bytes and
        // explicitly marks its absent-context case. Honor that fixture metadata
        // without collapsing absent and present-empty API fields.
        supp_priv_info: case
            .supp_priv_info_hex
            .as_ref()
            .filter(|_| case.supp_priv_info_present != Some(false))
            .map(|v| hex(v).into()),
    }
}

fn native(input: &wire::CoseMlKemDecryptRequest) -> Result<crate::DecryptedCoseEncrypt, CoseError> {
    cose_decrypt_ml_kem_with_external_aad(
        &CoseMlKemDecryptRequest::new(
            &input.cose_encrypt,
            &input.recipient_private_key,
            &input.expected_recipient_kid,
            input.supp_priv_info.as_deref(),
        ),
        &input.external_aad,
    )
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn independent_private_profile_vectors_keep_exact_nil_and_wrapped_recipient_forms(
) -> Result<(), CoseError> {
    let cases = cases()?;
    assert_eq!(cases.len(), 8);
    for case in cases {
        let encoded = hex(&case.cose_encrypt_hex);
        let private = Zeroizing::new(hex(&case.private_key_seed_hex));
        let mut value = SensitiveCborValue::decode_cose_encrypt(&encoded)?;
        let slot = recipient_slot(value.value_mut())?;
        if case.mode == "direct" {
            assert_eq!(*slot, Value::Null);
        } else {
            assert!(matches!(slot, Value::Bytes(bytes) if !bytes.is_empty()));
        }
        let input = input(&case, &encoded, &private);
        assert_eq!(
            native(&input)?.plaintext.as_slice(),
            hex(&case.plaintext_hex)
        );
        let output = success(codec_parity(Operation::MlKemDecrypt(Box::new(input)))?);
        let Branch::MlKemDecrypt(output) = &output else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(output.plaintext.as_slice(), hex(&case.plaintext_hex));
        // Reading the slot must not rewrite authenticated protected byte strings.
        assert_eq!(
            crate::encode_cbor::encode_cbor_value(value.take_value())?.as_slice(),
            encoded
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn recipient_ciphertext_shape_rejects_before_private_key_binding() -> Result<(), CoseError> {
    for case in cases()? {
        let encoded = hex(&case.cose_encrypt_hex);
        let private = Zeroizing::new(hex(&case.private_key_seed_hex));
        let forbidden = if case.mode == "direct" {
            vec![Value::Bytes(vec![]), Value::Bytes(vec![0x42])]
        } else {
            vec![Value::Null]
        };
        let expected = if case.mode == "direct" {
            CoseError::InvalidRecipient
        } else {
            CoseError::MissingCiphertext
        };
        for forbidden in forbidden {
            let mut value = SensitiveCborValue::decode_cose_encrypt(&encoded)?;
            *recipient_slot(value.value_mut())? = forbidden;
            let mutated = crate::encode_cbor::encode_cbor_value(value.take_value())?;
            for selected in [private.as_slice(), &[0xa5; 64]] {
                let input = input(&case, &mutated, selected);
                assert_eq!(native(&input).err(), Some(expected));
                assert_eq!(
                    reason(&codec_parity(Operation::MlKemDecrypt(Box::new(input)))?),
                    expected.reason()
                );
            }
        }
    }
    Ok(())
}
