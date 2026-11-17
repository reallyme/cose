// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::rsa_support::{fixture, key, suite, target};
use super::support::{codec_parity, field, hex, reason, success};
use crate::api::contract::{
    self as wire, cose_operation_request::Operation, cose_operation_result::Result as Branch,
};
use crate::CoseError;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_sign_and_both_counter_forms_verify_independent_contexts() -> Result<(), CoseError> {
    let vectors = fixture()?;
    for case in &vectors.cases {
        let input = wire::CoseSignVerifyRequest {
            encoded: hex(&case.sign).into(),
            external_aad: hex(&vectors.aad).into(),
            envelope: wire::CoseEnvelopePolicy::Either.into(),
            allowed_suites: vec![suite(case)?].into(),
            keys: vec![key(&vectors, case)?].into(),
            detached_payload: None,
        };
        let result = success(codec_parity(Operation::SignVerify(Box::new(
            input.clone(),
        )))?);
        let Branch::SignVerify(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(
            result.body_protected.as_slice(),
            hex(&vectors.body_protected)
        );
        assert_eq!(
            result.attached_payload.as_deref(),
            Some(hex(&vectors.payload)).as_deref()
        );
        assert_eq!(result.signatures.len(), 1);
        assert_eq!(result.signatures[0].suite.as_option(), Some(&suite(case)?));
        assert_eq!(
            result.signatures[0].protected.as_slice(),
            hex(&case.protected)
        );
        let mut wrong = input;
        wrong.external_aad = vec![0].into();
        assert_eq!(
            reason(&codec_parity(Operation::SignVerify(Box::new(wrong)))?),
            CoseError::InvalidSignature.reason()
        );

        let full = wire::CoseCounterSignatureVerifyRequest {
            target: field(target(&vectors)),
            key: field(key(&vectors, case)?),
            allowed_suites: vec![suite(case)?].into(),
            external_aad: hex(&vectors.aad).into(),
            signature: Some(
                wire::cose_counter_signature_verify_request::Signature::Standalone(Box::new(
                    wire::CoseCounterSignatureEncoded {
                        encoded: hex(&case.counter).into(),
                        envelope: wire::CoseEnvelopePolicy::Either.into(),
                    },
                )),
            ),
        };
        let result = success(codec_parity(Operation::CounterSignatureVerify(Box::new(
            full.clone(),
        )))?);
        let Branch::CounterSignatureVerify(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(result.suite.as_option(), Some(&suite(case)?));
        assert_eq!(result.protected.as_slice(), hex(&case.protected));
        let mut wrong = full;
        wrong.external_aad = vec![0].into();
        assert_eq!(
            reason(&codec_parity(Operation::CounterSignatureVerify(Box::new(
                wrong
            )))?),
            CoseError::InvalidSignature.reason()
        );

        let abbreviated = wire::CoseCounterSignature0VerifyRequest {
            target: field(target(&vectors)),
            key: field(key(&vectors, case)?),
            allowed_suites: vec![suite(case)?].into(),
            external_aad: hex(&vectors.aad).into(),
            signature: Some(
                wire::cose_counter_signature0verify_request::Signature::Standalone(
                    hex(&case.counter0).into(),
                ),
            ),
        };
        let result = success(codec_parity(Operation::CounterSignature0Verify(Box::new(
            abbreviated.clone(),
        )))?);
        let Branch::CounterSignature0Verify(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(result.suite.as_option(), Some(&suite(case)?));
        assert!(result.protected.is_empty());
        let mut wrong = abbreviated;
        let target = wrong
            .target
            .as_option_mut()
            .ok_or(CoseError::InvalidFormat)?;
        let mut encoded = target.encoded.to_vec();
        *encoded.last_mut().ok_or(CoseError::InvalidFormat)? ^= 1;
        target.encoded = encoded.into();
        assert_eq!(
            reason(&codec_parity(Operation::CounterSignature0Verify(
                Box::new(wrong)
            ))?),
            CoseError::InvalidSignature.reason()
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rsa_creation_fails_closed_until_crypto_provides_signing() -> Result<(), CoseError> {
    let vectors = fixture()?;
    for case in &vectors.cases {
        let signer = wire::CoseSignSigner {
            headers: field(wire::CoseMessageHeaders {
                protected: hex(&case.protected).into(),
                unprotected: vec![0xa0].into(),
            }),
            suite: field(suite(case)?),
            private_key: vec![1].into(),
        };
        let sign = wire::CoseSignCreateRequest {
            headers: field(wire::CoseMessageHeaders {
                protected: Vec::new().into(),
                unprotected: vec![0xa0].into(),
            }),
            payload: hex(&vectors.payload).into(),
            external_aad: hex(&vectors.aad).into(),
            content_mode: wire::CoseContentMode::Attached.into(),
            tagged: true,
            signers: vec![signer.clone()].into(),
            allowed_suites: vec![suite(case)?].into(),
        };
        let full = wire::CoseCounterSignatureCreateRequest {
            target: field(target(&vectors)),
            signer: field(signer),
            allowed_suites: vec![suite(case)?].into(),
            external_aad: hex(&vectors.aad).into(),
            tagged: false,
        };
        let abbreviated = wire::CoseCounterSignature0CreateRequest {
            target: field(target(&vectors)),
            suite: field(suite(case)?),
            private_key: vec![1].into(),
            allowed_suites: vec![suite(case)?].into(),
            external_aad: hex(&vectors.aad).into(),
        };
        for operation in [
            Operation::SignCreate(Box::new(sign)),
            Operation::CounterSignatureCreate(Box::new(full)),
            Operation::CounterSignature0Create(Box::new(abbreviated)),
        ] {
            assert_eq!(
                reason(&codec_parity(operation)?),
                CoseError::ProviderUnavailable.reason()
            );
        }
    }
    Ok(())
}
