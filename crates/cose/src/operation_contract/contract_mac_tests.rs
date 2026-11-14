// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, hex, reason, success};
use crate::api::contract::{
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
    CoseErrorReason, CoseKeySource, CoseMac0VerifyRequest, CoseMacAlgorithm,
};
use crate::CoseError;

pub(super) fn input() -> CoseMac0VerifyRequest {
    // COSE Working Group HMac-01, unchanged authentication bytes/tag; detached
    // transport replaces only the payload slot with null, as RFC 9052 permits.
    CoseMac0VerifyRequest {
        encoded: hex(
            "8443a10105a0f65820a1a848d3471f9d61ee49018d244c824772f223ad4f935293f1789fc3a08d8c58",
        )
        .into(),
        detached_payload: b"This is the content.".to_vec().into(),
        external_aad: Vec::new().into(),
        allowed_algorithms: vec![CoseMacAlgorithm::Hmac256256.into()].into(),
        key_algorithm: CoseMacAlgorithm::Hmac256256.into(),
        key_source: CoseKeySource::Direct.into(),
        key: hex("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").into(),
        capability: super::support::capability(
            0,
            crate::api::contract::CoseProviderKind::MacVerifier,
        ),
        limits: Default::default(),
    }
}

struct MacPort(crate::CoseMacKey);
impl crate::api::OperationProviders for MacPort {
    fn mac_key(
        &self,
        handle: u64,
    ) -> Result<&crate::CoseMacKey, crate::containers::ContainerError> {
        if handle != 1 {
            return Err(crate::containers::ContainerErrorReason::Provider.into());
        }
        Ok(&self.0)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn protected_key_handle_never_exports_a_key_or_payload() -> Result<(), CoseError> {
    let mut request = input();
    let key = crate::CoseMacKey::new(
        crate::CoseMacAlgorithm::Hmac256_256,
        core::mem::take(&mut request.key).into_zeroizing(),
    )
    .map_err(|_| CoseError::InvalidKeyMaterial)?;
    request.key_source = CoseKeySource::Provider.into();
    request.capability =
        super::support::capability(1, crate::api::contract::CoseProviderKind::MacVerifier);
    let ports = MacPort(key);
    let Branch::Mac0VerifyDetached(value) =
        &mut success(super::support::codec_parity_with_providers(
            Operation::Mac0VerifyDetached(Box::new(request.clone())),
            &ports,
        )?)
    else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(value.protected_headers, hex("a10105"));
    let mut unavailable = request.clone();
    unavailable.capability =
        super::support::capability(2, crate::api::contract::CoseProviderKind::MacVerifier);
    assert_eq!(
        reason(&super::support::codec_parity_with_providers(
            Operation::Mac0VerifyDetached(Box::new(unavailable)),
            &ports
        )?),
        CoseErrorReason::ProviderUnavailable
    );
    request.key_algorithm = CoseMacAlgorithm::Hmac25664.into();
    assert_eq!(
        reason(&super::support::codec_parity_with_providers(
            Operation::Mac0VerifyDetached(Box::new(request)),
            &ports
        )?),
        CoseErrorReason::KeyAlgorithmMismatch
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn limits_clamp_before_platform_conversion_and_preserve_explicit_zero() -> Result<(), CoseError> {
    let mut input = input();
    input.limits = super::support::field(crate::api::contract::CoseByteLimits {
        encoded_bytes: u64::MAX,
        payload_bytes: u64::MAX,
        external_aad_bytes: u64::MAX,
    });
    assert!(matches!(
        success(codec_parity(Operation::Mac0VerifyDetached(Box::new(
            input.clone()
        )))?),
        Branch::Mac0VerifyDetached(_)
    ));
    input
        .limits
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?
        .encoded_bytes = 0;
    assert_eq!(
        reason(&codec_parity(Operation::Mac0VerifyDetached(Box::new(
            input
        )))?),
        CoseErrorReason::CommonResourceLimitExceeded
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn independent_mac_answer_and_native_authenticated_metadata_are_identical() -> Result<(), CoseError>
{
    let input = input();
    let key = crate::CoseMacKey::new(
        crate::CoseMacAlgorithm::Hmac256_256,
        input.key.clone().into_zeroizing(),
    )
    .map_err(|_| CoseError::InvalidKeyMaterial)?;
    let native = crate::cose_verify_mac0_detached(
        crate::CoseMac0VerifyRequest {
            encoded: &input.encoded,
            detached_payload: &input.detached_payload,
            external_aad: &input.external_aad,
            allowed_algorithms: &[crate::CoseMacAlgorithm::Hmac256_256],
            limits: crate::CoseMac0Limits::default(),
        },
        &key,
    )
    .map_err(|_| CoseError::InvalidSignature)?;
    let Branch::Mac0VerifyDetached(value) = &mut success(codec_parity(
        Operation::Mac0VerifyDetached(Box::new(input)),
    )?) else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(value.protected_headers, native.protected_header_bytes());
    assert_eq!(
        value.algorithm.to_i32(),
        i32::try_from(native.algorithm().cose_id()).map_err(|_| CoseError::InvalidFormat)?
    );
    assert!(value.protected_kid.is_none());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn changed_mac_inputs_and_resource_limits_preserve_fixed_failures() -> Result<(), CoseError> {
    let mut changed = input();
    changed.detached_payload[0] ^= 1;
    let mut aad = input();
    aad.external_aad = vec![1].into();
    let mut key = input();
    key.key[0] ^= 1;
    let mut tag = input();
    *tag.encoded.last_mut().ok_or(CoseError::InvalidFormat)? ^= 1;
    for value in [changed, aad, key, tag] {
        assert_eq!(
            reason(&codec_parity(Operation::Mac0VerifyDetached(Box::new(
                value
            )))?),
            CoseErrorReason::CommonAuthenticationFailed
        );
    }
    let mut input = input();
    input.allowed_algorithms.clear();
    assert_eq!(
        reason(&codec_parity(Operation::Mac0VerifyDetached(Box::new(
            input
        )))?),
        CoseErrorReason::CommonUnsupportedAlgorithm
    );
    Ok(())
}
