// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    binding, codec_parity, contract, created, ed, field, full_create, full_standalone, hex, reason,
    short_create, success, target, vectors, verify_full, verify_short, CoseError, FullSource, Kind,
    Operation, ShortSource, ED_PUBLIC,
};
use buffa::Message;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn counter_tampering_payload_other_fields_aad_key_and_protected_bytes_fail() -> Result<(), CoseError>
{
    let target = target(&hex(vectors::MAC0_BARE), Kind::Mac0);
    let output = success(codec_parity(Operation::CounterSignatureCreate(Box::new(
        full_create(target.clone()),
    )))?);
    let valid = verify_full(
        target.clone(),
        binding(ed(), &hex(ED_PUBLIC), 0),
        full_standalone(created(&output)?),
    );
    let mut changed = valid.clone();
    changed.external_aad = vec![1].into();
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureVerify(Box::new(
            changed
        )))?),
        CoseError::InvalidSignature.reason()
    );
    for position in [4, 15, 60] {
        let mut changed = valid.clone();
        let target = changed
            .target
            .as_option_mut()
            .ok_or(CoseError::InvalidFormat)?;
        let mut bytes = target.encoded.to_vec();
        *bytes.get_mut(position).ok_or(CoseError::InvalidFormat)? ^= 1;
        target.encoded = bytes.into();
        let response = codec_parity(Operation::CounterSignatureVerify(Box::new(changed)))?;
        assert_eq!(reason(&response), CoseError::InvalidSignature.reason());
    }
    let mut changed = valid.clone();
    let Some(FullSource::Standalone(counter)) = changed.signature.as_mut() else {
        return Err(CoseError::InvalidFormat);
    };
    let mut bytes = counter.encoded.to_vec();
    *bytes.last_mut().ok_or(CoseError::InvalidFormat)? ^= 1;
    counter.encoded = bytes.into();
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureVerify(Box::new(
            changed
        )))?),
        CoseError::InvalidSignature.reason()
    );
    let mut changed = valid;
    let key = changed
        .key
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?;
    key.suite = field(super::suite(
        contract::CoseSignatureAlgorithm::Ed25519,
        contract::CoseNamedCurve::Ed25519,
    ));
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureVerify(Box::new(
            changed
        )))?),
        CoseError::UnsupportedAlgorithm.reason()
    );
    let short = success(codec_parity(Operation::CounterSignature0Create(Box::new(
        short_create(target.clone()),
    )))?);
    let mut short = verify_short(
        target,
        ShortSource::Standalone(created(&short)?.to_vec().into()),
    );
    short.external_aad = vec![1].into();
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignature0Verify(
            Box::new(short)
        ))?),
        CoseError::InvalidSignature.reason()
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn counter_rejects_legacy_headers_malformed_slots_trailing_data_and_wrong_source(
) -> Result<(), CoseError> {
    let original = target(&hex(vectors::ENCRYPT0_BARE), Kind::Encrypt0);
    for (encoded, expected) in [
        ("d08343a10101a0f90016", CoseError::InvalidFormat),
        ("d08343a10101a0f6", CoseError::InvalidFormat),
        ("d08343a10101a007", CoseError::InvalidFormat),
        ("d28343a10101a040", CoseError::UnexpectedCborTag),
    ] {
        let input = full_create(target(&hex(encoded), Kind::Encrypt0));
        assert_eq!(
            reason(&codec_parity(Operation::CounterSignatureCreate(Box::new(
                input
            )))?),
            expected.reason()
        );
    }
    let mut encoded = hex(vectors::ENCRYPT0_BARE);
    encoded.push(0);
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureCreate(Box::new(
            full_create(target(&encoded, Kind::Encrypt0))
        )))?),
        CoseError::Cbor.reason()
    );
    let mut bytes = hex(vectors::RFC[3].1);
    let offset = bytes
        .windows(5)
        .position(|part| part == [0x0b, 0x83, 0x43, 0xa1, 0x01])
        .ok_or(CoseError::InvalidFormat)?;
    *bytes.get_mut(offset).ok_or(CoseError::InvalidFormat)? = 7;
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureCreate(Box::new(
            full_create(target(&bytes, Kind::Encrypt0))
        )))?),
        CoseError::UnsupportedCriticalHeader.reason()
    );
    let mut input = verify_short(
        original.clone(),
        ShortSource::Standalone(hex("f90016").into()),
    );
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignature0Verify(
            Box::new(input.clone())
        ))?),
        CoseError::Cbor.reason()
    );
    input.signature = Some(ShortSource::Header(Box::default()));
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignature0Verify(
            Box::new(input)
        ))?),
        CoseError::InvalidFormat.reason()
    );
    let input = verify_full(
        original,
        binding(ed(), &hex(ED_PUBLIC), 0),
        full_standalone(&hex("d28340a040")),
    );
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureVerify(Box::new(
            input
        )))?),
        CoseError::UnexpectedCborTag.reason()
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn counter_detached_content_is_explicit_and_never_replaces_attached_data() -> Result<(), CoseError>
{
    let mut target = target(&hex(vectors::MAC0_BARE), Kind::Mac0);
    let mut bytes = target.encoded.to_vec();
    bytes.splice(7..28, [0xf6]);
    target.encoded = bytes.into();
    target.detached_content = Some(b"This is the content.".to_vec().into());
    let output = success(codec_parity(Operation::CounterSignature0Create(Box::new(
        short_create(target.clone()),
    )))?);
    let valid = verify_short(
        target,
        ShortSource::Standalone(created(&output)?.to_vec().into()),
    );
    let _ = success(codec_parity(Operation::CounterSignature0Verify(Box::new(
        valid.clone(),
    )))?);
    let mut changed = valid.clone();
    changed
        .target
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?
        .detached_content = Some(b"wrong".to_vec().into());
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignature0Verify(
            Box::new(changed)
        ))?),
        CoseError::InvalidSignature.reason()
    );
    let mut changed = valid;
    changed
        .target
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?
        .detached_content = None;
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignature0Verify(
            Box::new(changed)
        ))?),
        CoseError::InvalidFormat.reason()
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn counter_provider_limits_and_sensitive_ownership_fail_closed() -> Result<(), CoseError> {
    let original = target(&hex(vectors::ENCRYPT0_BARE), Kind::Encrypt0);
    let mut input = full_create(original.clone());
    input.external_aad = vec![0; 65_537].into();
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureCreate(Box::new(
            input
        )))?),
        CoseError::ResourceLimitExceeded.reason()
    );
    let mut input = full_create(original.clone());
    let suite = super::suite(
        contract::CoseSignatureAlgorithm::Eddsa,
        contract::CoseNamedCurve::Ed448,
    );
    input
        .signer
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?
        .suite = field(suite.clone());
    input.allowed_suites = vec![suite].into();
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureCreate(Box::new(
            input
        )))?),
        CoseError::ProviderUnavailable.reason()
    );
    let mut input = full_create(original);
    let debug = format!("{input:?}");
    assert!(!debug.contains(super::ED_SEED));
    input.clear();
    assert!(input.target.as_option().is_none());
    assert!(input.signer.as_option().is_none());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn counter_exact_protected_bytes_wrong_key_width_and_index_are_enforced() -> Result<(), CoseError> {
    let target = target(&hex(vectors::ENCRYPT0_BARE), Kind::Encrypt0);
    let output = success(codec_parity(Operation::CounterSignatureCreate(Box::new(
        full_create(target.clone()),
    )))?);
    let valid = verify_full(
        target.clone(),
        binding(ed(), &hex(ED_PUBLIC), 0),
        full_standalone(created(&output)?),
    );
    let mut changed = valid.clone();
    let key = changed
        .key
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?;
    key.public_key = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c").into();
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureVerify(Box::new(
            changed
        )))?),
        CoseError::InvalidSignature.reason()
    );
    let mut changed = valid.clone();
    let Some(FullSource::Standalone(counter)) = changed.signature.as_mut() else {
        return Err(CoseError::InvalidFormat);
    };
    let mut bytes = counter.encoded.to_vec();
    bytes
        .get_mut(3..8)
        .ok_or(CoseError::InvalidFormat)?
        .copy_from_slice(&hex("a201270440"));
    counter.encoded = bytes.into();
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureVerify(Box::new(
            changed
        )))?),
        CoseError::InvalidSignature.reason()
    );
    let mut changed = valid.clone();
    let Some(FullSource::Standalone(counter)) = changed.signature.as_mut() else {
        return Err(CoseError::InvalidFormat);
    };
    let mut bytes = counter.encoded.to_vec();
    *bytes.get_mut(10).ok_or(CoseError::InvalidFormat)? = 63;
    bytes.pop();
    counter.encoded = bytes.into();
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureVerify(Box::new(
            changed
        )))?),
        CoseError::InvalidSignatureEncoding.reason()
    );
    let mut changed = valid;
    changed
        .key
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?
        .signature_index = 1;
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureVerify(Box::new(
            changed
        )))?),
        CoseError::InvalidKeyMaterial.reason()
    );
    for (protected, expected) in [
        ("a201270127", CoseError::DuplicateMapLabel),
        ("a301270281182a182a00", CoseError::UnsupportedCriticalHeader),
    ] {
        let mut input = full_create(target.clone());
        input
            .signer
            .as_option_mut()
            .ok_or(CoseError::InvalidFormat)?
            .headers
            .as_option_mut()
            .ok_or(CoseError::InvalidFormat)?
            .protected = hex(protected).into();
        assert_eq!(
            reason(&codec_parity(Operation::CounterSignatureCreate(Box::new(
                input
            )))?),
            expected.reason()
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn counter_collection_boundaries_and_oversized_inputs_are_fixed() -> Result<(), CoseError> {
    let mut target = target(&hex(vectors::ENCRYPT0_BARE), Kind::Encrypt0);
    let signature = success(codec_parity(Operation::CounterSignatureCreate(Box::new(
        full_create(target.clone()),
    )))?);
    for index in 0..32 {
        let input = contract::CoseCounterSignatureAttachRequest {
            target: field(target.clone()),
            signature: Some(super::AttachSource::Full(
                created(&signature)?.to_vec().into(),
            )),
        };
        let output = success(codec_parity(Operation::CounterSignatureAttach(Box::new(
            input,
        )))?);
        target.encoded = created(&output)?.to_vec().into();
        if index == 31 {
            let input = verify_full(
                target.clone(),
                binding(ed(), &hex(ED_PUBLIC), 31),
                FullSource::HeaderIndex(31),
            );
            let _ = success(codec_parity(Operation::CounterSignatureVerify(Box::new(
                input,
            )))?);
        }
    }
    let input = contract::CoseCounterSignatureAttachRequest {
        target: field(target.clone()),
        signature: Some(super::AttachSource::Full(
            created(&signature)?.to_vec().into(),
        )),
    };
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureAttach(Box::new(
            input
        )))?),
        CoseError::ResourceLimitExceeded.reason()
    );
    target.encoded = vec![0; 1_048_577].into();
    assert_eq!(
        reason(&codec_parity(Operation::CounterSignatureCreate(Box::new(
            full_create(target)
        )))?),
        CoseError::ResourceLimitExceeded.reason()
    );
    Ok(())
}
