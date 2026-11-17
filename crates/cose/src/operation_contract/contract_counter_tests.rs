// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, hex, reason, success};
use crate::api::contract::{
    self as contract,
    __buffa::oneof::{
        cose_counter_signature0verify_request::Signature as ShortSource,
        cose_counter_signature_attach_request::Signature as AttachSource,
        cose_counter_signature_verify_request::Signature as FullSource,
        cose_operation_request::Operation, cose_operation_result::Result as Branch,
    },
    CoseCounterSignatureTargetKind as Kind, CoseNamedCurve as Curve, CoseSignatureAlgorithm as Alg,
};
use crate::CoseError;
#[path = "contract_counter_boundary_tests.rs"]
mod boundary;
#[path = "contract_counter_vectors.rs"]
mod vectors;

const ED_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ED_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
fn suite(algorithm: Alg, curve: Curve) -> contract::CoseSignatureSuite {
    contract::CoseSignatureSuite {
        registration: algorithm.into(),
        curve: curve.into(),
    }
}
fn ed() -> contract::CoseSignatureSuite {
    suite(Alg::Eddsa, Curve::Ed25519)
}
fn target(encoded: &[u8], kind: Kind) -> contract::CoseCounterSignatureTarget {
    contract::CoseCounterSignatureTarget {
        encoded: encoded.to_vec().into(),
        kind: kind.into(),
        envelope: contract::CoseEnvelopePolicy::Either.into(),
        detached_content: None,
    }
}
fn signer() -> contract::CoseSignSigner {
    contract::CoseSignSigner {
        headers: field(contract::CoseMessageHeaders {
            protected: hex("a204400127").into(),
            unprotected: vec![0xa0].into(),
        }),
        suite: field(ed()),
        private_key: hex(ED_SEED).into(),
    }
}
fn binding(
    suite: contract::CoseSignatureSuite,
    public: &[u8],
    index: u32,
) -> contract::CoseSignKeyBinding {
    contract::CoseSignKeyBinding {
        signature_index: index,
        suite: field(suite),
        public_key: public.to_vec().into(),
    }
}
fn verify_full(
    target: contract::CoseCounterSignatureTarget,
    key: contract::CoseSignKeyBinding,
    signature: FullSource,
) -> contract::CoseCounterSignatureVerifyRequest {
    contract::CoseCounterSignatureVerifyRequest {
        target: field(target),
        allowed_suites: vec![key.suite.as_option().cloned().unwrap_or_default()].into(),
        key: field(key),
        external_aad: Vec::new().into(),
        signature: Some(signature),
    }
}
fn verify_short(
    target: contract::CoseCounterSignatureTarget,
    signature: ShortSource,
) -> contract::CoseCounterSignature0VerifyRequest {
    contract::CoseCounterSignature0VerifyRequest {
        target: field(target),
        key: field(binding(ed(), &hex(ED_PUBLIC), 0)),
        allowed_suites: vec![ed()].into(),
        external_aad: Vec::new().into(),
        signature: Some(signature),
    }
}
fn full_create(
    target: contract::CoseCounterSignatureTarget,
) -> contract::CoseCounterSignatureCreateRequest {
    contract::CoseCounterSignatureCreateRequest {
        target: field(target),
        signer: field(signer()),
        allowed_suites: vec![ed()].into(),
        external_aad: Vec::new().into(),
        tagged: true,
    }
}
fn short_create(
    target: contract::CoseCounterSignatureTarget,
) -> contract::CoseCounterSignature0CreateRequest {
    contract::CoseCounterSignature0CreateRequest {
        target: field(target),
        suite: field(ed()),
        private_key: hex(ED_SEED).into(),
        allowed_suites: vec![ed()].into(),
        external_aad: Vec::new().into(),
    }
}
fn full_standalone(encoded: &[u8]) -> FullSource {
    FullSource::Standalone(Box::new(contract::CoseCounterSignatureEncoded {
        encoded: encoded.to_vec().into(),
        envelope: contract::CoseEnvelopePolicy::Either.into(),
    }))
}
fn created(output: &Branch) -> Result<&[u8], CoseError> {
    match output {
        Branch::CounterSignatureCreate(value)
        | Branch::CounterSignature0Create(value)
        | Branch::CounterSignatureAttach(value) => Ok(&value.encoded),
        _ => Err(CoseError::InvalidFormat),
    }
}
fn kinds() -> [Kind; 6] {
    [
        Kind::Sign,
        Kind::Sign1,
        Kind::Encrypt,
        Kind::Encrypt0,
        Kind::Mac,
        Kind::Mac0,
    ]
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn counter_all_six_independent_rfc9338_examples_verify_embedded_v2() -> Result<(), CoseError> {
    for ((_, encoded), kind) in vectors::RFC.iter().zip(kinds()) {
        let (suite,public)=match kind {
            Kind::Sign=>(suite(Alg::Es256,Curve::P256),hex("04bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")),
            Kind::Sign1|Kind::Encrypt=>(suite(Alg::Es512,Curve::P521),hex("040072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475")),
            _=>(ed(),hex(ED_PUBLIC)),
        };
        let input = verify_full(
            target(&hex(encoded), kind),
            binding(suite, &public, 0),
            FullSource::HeaderIndex(0),
        );
        let result = success(codec_parity(Operation::CounterSignatureVerify(Box::new(
            input,
        )))?);
        let Branch::CounterSignatureVerify(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        assert!(!result.protected.is_empty());
        assert_eq!(result.protected_kid, None);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn counter_abbreviated_independent_openssl_vectors_cover_both_contexts() -> Result<(), CoseError> {
    for (kind, encoded, counter, preimage) in [
        (
            Kind::Encrypt0,
            vectors::ENCRYPT0_BARE,
            vectors::ABBREVIATED_ENCRYPT0,
            vectors::PREIMAGE_ENCRYPT0,
        ),
        (
            Kind::Mac0,
            vectors::MAC0_BARE,
            vectors::ABBREVIATED_MAC0,
            vectors::PREIMAGE_MAC0,
        ),
    ] {
        let encoded_counter = hex(counter);
        reallyme_crypto::dispatch::verify(
            crate::Algorithm::Ed25519,
            &hex(ED_PUBLIC),
            &hex(preimage),
            encoded_counter.get(2..).ok_or(CoseError::InvalidFormat)?,
        )
        .map_err(crate::error::signature_error_from_algorithm_error)?;
        let target = target(&hex(encoded), kind);
        let input = verify_short(target.clone(), ShortSource::Standalone(hex(counter).into()));
        let result = success(codec_parity(Operation::CounterSignature0Verify(Box::new(
            input,
        )))?);
        let Branch::CounterSignature0Verify(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        assert!(result.protected.is_empty());
        assert!(result.protected_kid.is_none());
        let result = success(codec_parity(Operation::CounterSignature0Create(Box::new(
            short_create(target),
        )))?);
        assert_eq!(created(&result)?, hex(counter));
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn counter_full_and_abbreviated_creation_support_every_target_and_chaining() -> Result<(), CoseError>
{
    let mut targets: Vec<_> = vectors::RFC
        .iter()
        .zip(kinds())
        .map(|((_, encoded), kind)| target(&hex(encoded), kind))
        .collect();
    targets.extend([
        target(&hex(vectors::SIGNATURE), Kind::Signature),
        target(&hex(vectors::RECIPIENT), Kind::Recipient),
        target(&hex(vectors::FULL_COUNTER), Kind::Countersignature),
    ]);
    for target in targets {
        let result = success(codec_parity(Operation::CounterSignatureCreate(Box::new(
            full_create(target.clone()),
        )))?);
        let input = verify_full(
            target.clone(),
            binding(ed(), &hex(ED_PUBLIC), 0),
            full_standalone(created(&result)?),
        );
        let _ = success(codec_parity(Operation::CounterSignatureVerify(Box::new(
            input,
        )))?);
        let result = success(codec_parity(Operation::CounterSignature0Create(Box::new(
            short_create(target.clone()),
        )))?);
        let input = verify_short(
            target,
            ShortSource::Standalone(created(&result)?.to_vec().into()),
        );
        let _ = success(codec_parity(Operation::CounterSignature0Verify(Box::new(
            input,
        )))?);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn counter_attachment_preserves_primary_fields_and_selects_full_collections(
) -> Result<(), CoseError> {
    let original = target(&hex(vectors::ENCRYPT0_BARE), Kind::Encrypt0);
    let output = success(codec_parity(Operation::CounterSignatureCreate(Box::new(
        full_create(original.clone()),
    )))?);
    let signature = created(&output)?.to_vec();
    let mut target = original.clone();
    for index in 0..3 {
        let input = contract::CoseCounterSignatureAttachRequest {
            target: field(target.clone()),
            signature: Some(AttachSource::Full(signature.clone().into())),
        };
        let output = success(codec_parity(Operation::CounterSignatureAttach(Box::new(
            input,
        )))?);
        target.encoded = created(&output)?.to_vec().into();
        let input = verify_full(
            target.clone(),
            binding(ed(), &hex(ED_PUBLIC), index),
            FullSource::HeaderIndex(index),
        );
        let _ = success(codec_parity(Operation::CounterSignatureVerify(Box::new(
            input,
        )))?);
    }
    let abbreviated = success(codec_parity(Operation::CounterSignature0Create(Box::new(
        short_create(original.clone()),
    )))?);
    let input = contract::CoseCounterSignatureAttachRequest {
        target: field(target.clone()),
        signature: Some(AttachSource::Abbreviated(
            created(&abbreviated)?.to_vec().into(),
        )),
    };
    let output = success(codec_parity(Operation::CounterSignatureAttach(Box::new(
        input,
    )))?);
    target.encoded = created(&output)?.to_vec().into();
    let input = verify_short(target.clone(), ShortSource::Header(Box::default()));
    let _ = success(codec_parity(Operation::CounterSignature0Verify(Box::new(
        input,
    )))?);
    // The AEAD tag still authenticates after attachment, and the authenticated
    // protected bstr and ciphertext retain their complete original encodings.
    let input = contract::CoseEncrypt0DecryptRequest {
        encoded: target.encoded.clone(),
        detached_ciphertext: None,
        external_aad: Vec::new().into(),
        key_algorithm: contract::CoseContentEncryptionAlgorithm::Aes128Gcm.into(),
        key: hex("849b57219dae48de646d07dbb533566e").into(),
        allowed_algorithms: vec![contract::CoseContentEncryptionAlgorithm::Aes128Gcm.into()].into(),
        base_iv: None,
        envelope: contract::CoseEnvelopePolicy::Either.into(),
    };
    let _ = success(codec_parity(Operation::Encrypt0Decrypt(Box::new(input)))?);
    assert_primary_bytes(&original.encoded, &target.encoded)?;
    let input = contract::CoseCounterSignatureAttachRequest {
        target: field(target),
        signature: Some(AttachSource::Abbreviated(
            created(&abbreviated)?.to_vec().into(),
        )),
    };
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureAttach(Box::new(
            input
        )))?),
        CoseError::DuplicateMapLabel.reason()
    );
    Ok(())
}

fn assert_primary_bytes(before: &[u8], after: &[u8]) -> Result<(), CoseError> {
    use reallyme_codec::cbor::general::{frame_exact, LengthPolicy, Limits};
    let before = frame_exact(before, Limits::default(), LengthPolicy::DefiniteOnly)
        .map_err(crate::cbor_boundary::error)?;
    let after = frame_exact(after, Limits::default(), LengthPolicy::DefiniteOnly)
        .map_err(crate::cbor_boundary::error)?;
    let before = before
        .children()
        .map_err(crate::cbor_boundary::error)?
        .next()
        .ok_or(CoseError::Cbor)?
        .map_err(crate::cbor_boundary::error)?;
    let after = after
        .children()
        .map_err(crate::cbor_boundary::error)?
        .next()
        .ok_or(CoseError::Cbor)?
        .map_err(crate::cbor_boundary::error)?;
    for (index, (before, after)) in before
        .children()
        .map_err(crate::cbor_boundary::error)?
        .zip(after.children().map_err(crate::cbor_boundary::error)?)
        .enumerate()
    {
        let before = before.map_err(crate::cbor_boundary::error)?;
        let after = after.map_err(crate::cbor_boundary::error)?;
        if index != 1 {
            assert_eq!(before.received_bytes(), after.received_bytes());
        }
    }
    Ok(())
}
