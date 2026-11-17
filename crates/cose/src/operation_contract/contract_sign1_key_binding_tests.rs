// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{
    capability, codec_parity, codec_parity_with_providers, field, hex, reason, success,
};
use crate::api::{contract as wire, OperationProviders};
use crate::{CoseError, CosePolicy, CoseSignatureAlgorithm as Exact};
use core::cell::Cell;
use wire::__buffa::oneof::{
    cose_operation_request::Operation, cose_operation_result::Result as Branch,
};
use zeroize::Zeroizing;

// RFC 9052 C.7.2 key "11", shared deliberately across two exact registrations.
fn private() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(hex(
        "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
    ))
}
fn public() -> Vec<u8> {
    hex("04bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")
}
fn broad() -> CosePolicy {
    CosePolicy::new().with_allowed_cose_algorithms([Exact::Es256, Exact::Esp256])
}
fn encoded(algorithm: Exact, detached: bool) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    if detached {
        crate::cose_sign1_detached_with_signature_algorithm(
            algorithm,
            b"payload",
            &private(),
            Some(b"k"),
        )
    } else {
        crate::cose_sign1_with_signature_algorithm(algorithm, b"payload", &private(), Some(b"k"))
    }
}
fn attached(
    encoded: &[u8],
    algorithm: wire::CoseSignatureAlgorithm,
) -> wire::CoseSign1VerifyRequest {
    wire::CoseSign1VerifyRequest::default()
        .with_cose_sign1(encoded.to_vec())
        .with_public_key(public())
        .with_public_key_algorithm(algorithm)
        .with_expected_kid(b"k".to_vec())
        .with_allowed_algorithms(vec![
            wire::CoseSignatureAlgorithm::Es256.into(),
            wire::CoseSignatureAlgorithm::Esp256.into(),
        ])
}
fn detached(
    encoded: &[u8],
    algorithm: wire::CoseSignatureAlgorithm,
) -> wire::CoseSign1VerifyDetachedRequest {
    wire::CoseSign1VerifyDetachedRequest::default()
        .with_cose_sign1(encoded.to_vec())
        .with_payload(b"payload".to_vec())
        .with_public_key(public())
        .with_public_key_algorithm(algorithm)
        .with_expected_kid(b"k".to_vec())
        .with_allowed_algorithms(vec![
            wire::CoseSignatureAlgorithm::Es256.into(),
            wire::CoseSignatureAlgorithm::Esp256.into(),
        ])
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn every_native_sign1_resolver_name_receives_exact_registration() -> Result<(), CoseError> {
    for algorithm in [Exact::Es256, Exact::Esp256] {
        let attached = encoded(algorithm, false)?;
        let detached = encoded(algorithm, true)?;
        let called = Cell::new(0_u32);
        let resolve = |actual: Exact, kid: &[u8]| {
            called.set(called.get() + 1);
            assert_eq!(actual, algorithm);
            assert_eq!(kid, b"k");
            Some(public())
        };
        crate::cose_verify1(&attached, resolve)?;
        let _ = crate::cose_verify1_with_metadata(&attached, resolve)?;
        let _ = crate::cose_verify1_with_policy(&attached, &broad(), resolve)?;
        let _ =
            crate::cose_verify1_with_policy_and_external_aad(&attached, &[], &broad(), resolve)?;
        let _ = crate::cose_verify1_with_exact_algorithm(&attached, &[], &broad(), resolve)?;
        crate::cose_verify1_detached(&detached, b"payload", resolve)?;
        let _ = crate::cose_verify1_detached_with_metadata(&detached, b"payload", resolve)?;
        let _ = crate::cose_verify1_detached_with_policy(&detached, b"payload", &broad(), resolve)?;
        let _ = crate::cose_verify1_detached_with_policy_and_external_aad(
            &detached,
            b"payload",
            &[],
            &broad(),
            resolve,
        )?;
        let _ = crate::cose_verify1_detached_with_exact_algorithm(
            &detached,
            b"payload",
            &[],
            &broad(),
            resolve,
        )?;
        assert_eq!(called.get(), 10);
        // All entrypoints may consume one owned key, without a repeatable Fn.
        let key = public();
        crate::cose_verify1(&attached, move |actual, kid| {
            (actual == algorithm && kid == b"k").then_some(key)
        })?;
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn shared_p256_key_and_kid_do_not_cross_an_exact_authorization_namespace() -> Result<(), CoseError>
{
    let es256 = encoded(Exact::Es256, false)?;
    let esp256 = encoded(Exact::Esp256, false)?;
    let authorized =
        |algorithm: Exact, kid: &[u8]| (algorithm == Exact::Es256 && kid == b"k").then(public);
    let _ = crate::cose_verify1_with_policy(&es256, &broad(), authorized)?;
    assert_eq!(
        crate::cose_verify1_with_policy(&esp256, &broad(), authorized).err(),
        Some(CoseError::KeyNotResolved)
    );
    let detached = encoded(Exact::Esp256, true)?;
    assert_eq!(
        crate::cose_verify1_detached_with_policy(&detached, b"payload", &broad(), authorized).err(),
        Some(CoseError::KeyNotResolved)
    );
    // Explicit authorization of the other exact identity still interoperates.
    let _ = crate::cose_verify1_with_policy(&esp256, &broad(), |algorithm, kid| {
        (algorithm == Exact::Esp256 && kid == b"k").then(public)
    })?;
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn direct_sign1_key_binding_is_required_and_checked_in_all_transports() -> Result<(), CoseError> {
    for registration in [Exact::Es256, Exact::Esp256] {
        let wire_algorithm = wire::CoseSignatureAlgorithm::from(registration);
        let attached_bytes = encoded(registration, false)?;
        let detached_bytes = encoded(registration, true)?;
        let wrong = if registration == Exact::Es256 {
            wire::CoseSignatureAlgorithm::Esp256
        } else {
            wire::CoseSignatureAlgorithm::Es256
        };
        for (binding, expected) in [
            (
                wire::CoseSignatureAlgorithm::Unspecified.into(),
                Some(wire::CoseErrorReason::CommonInvalidParameter),
            ),
            (
                buffa::EnumValue::from(999_999),
                Some(wire::CoseErrorReason::CommonInvalidParameter),
            ),
            (
                wrong.into(),
                Some(wire::CoseErrorReason::KeyAlgorithmMismatch),
            ),
            (wire_algorithm.into(), None),
        ] {
            let mut attached = attached(&attached_bytes, wire_algorithm);
            attached.public_key_algorithm = binding;
            let mut detached = detached(&detached_bytes, wire_algorithm);
            detached.public_key_algorithm = binding;
            for operation in [
                Operation::Sign1Verify(Box::new(attached)),
                Operation::Sign1VerifyDetached(Box::new(detached)),
            ] {
                let response = codec_parity(operation)?;
                if let Some(expected) = expected {
                    assert_eq!(reason(&response), expected);
                } else {
                    let result = success(response);
                    match &result {
                        Branch::Sign1Verify(value) | Branch::Sign1VerifyDetached(value) => {
                            assert_eq!(value.exact_signature_algorithm, wire_algorithm)
                        }
                        _ => return Err(CoseError::InvalidFormat),
                    }
                }
            }
        }
    }
    Ok(())
}

struct Resolver {
    authorized: wire::CoseSignatureAlgorithm,
    calls: Cell<u32>,
    last: Cell<Option<wire::CoseSignatureAlgorithm>>,
}
impl OperationProviders for Resolver {
    fn resolve_sign1_key(
        &self,
        handle: u64,
        algorithm: wire::CoseSignatureAlgorithm,
        kid: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        self.calls.set(self.calls.get() + 1);
        self.last.set(Some(algorithm));
        (handle == 1 && algorithm == self.authorized && kid == b"k")
            .then(|| Zeroizing::new(public()))
    }
}
fn profile(encoded: &[u8], detached: bool) -> wire::CoseSign1VerifyProfileRequest {
    wire::CoseSign1VerifyProfileRequest {
        request: field(wire::CoseSign1VerifyRequest::default().with_cose_sign1(encoded.to_vec())),
        detached_payload: if detached {
            b"payload".to_vec().into()
        } else {
            Vec::new().into()
        },
        detached,
        capability: capability(1, wire::CoseProviderKind::KeyResolver),
        policy: field(broad().contract().clone()),
        allow_unprotected_x5chain: false,
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn exact_profile_resolvers_bind_keys_without_disabling_multi_algorithm_lookup(
) -> Result<(), CoseError> {
    for detached in [false, true] {
        for registration in [Exact::Es256, Exact::Esp256] {
            let bytes = encoded(registration, detached)?;
            let wire_algorithm = wire::CoseSignatureAlgorithm::from(registration);
            let provider = Resolver {
                authorized: wire_algorithm,
                calls: Cell::new(0),
                last: Cell::new(None),
            };
            let input = profile(&bytes, detached);
            let _ = success(codec_parity_with_providers(
                Operation::Sign1VerifyProfile(Box::new(input.clone())),
                &provider,
            )?);
            assert_eq!(provider.calls.get(), 3);
            assert_eq!(provider.last.get(), Some(wire_algorithm));
            let wrong = Resolver {
                authorized: if registration == Exact::Es256 {
                    wire::CoseSignatureAlgorithm::Esp256
                } else {
                    wire::CoseSignatureAlgorithm::Es256
                },
                calls: Cell::new(0),
                last: Cell::new(None),
            };
            assert_eq!(
                reason(&codec_parity_with_providers(
                    Operation::Sign1VerifyProfile(Box::new(input.clone())),
                    &wrong
                )?),
                wire::CoseErrorReason::Sign1KeyNotResolved
            );
            let mut filtered = input;
            filtered
                .request
                .as_option_mut()
                .ok_or(CoseError::InvalidFormat)?
                .public_key_algorithm = wrong.authorized.into();
            provider.calls.set(0);
            assert_eq!(
                reason(&codec_parity_with_providers(
                    Operation::Sign1VerifyProfile(Box::new(filtered)),
                    &provider
                )?),
                wire::CoseErrorReason::KeyAlgorithmMismatch
            );
            assert_eq!(provider.calls.get(), 0);
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn profile_direct_keys_cannot_omit_the_exact_registration() -> Result<(), CoseError> {
    let bytes = encoded(Exact::Es256, false)?;
    let mut input = profile(&bytes, false);
    input.capability = Default::default();
    input
        .request
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?
        .public_key = public().into();
    assert_eq!(
        reason(&codec_parity(Operation::Sign1VerifyProfile(Box::new(
            input.clone()
        )))?),
        wire::CoseErrorReason::CommonInvalidParameter
    );
    input
        .request
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?
        .public_key_algorithm = wire::CoseSignatureAlgorithm::Es256.into();
    let _ = success(codec_parity(Operation::Sign1VerifyProfile(Box::new(
        input,
    )))?);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn native_certificate_resolver_names_preserve_the_exact_registration() -> Result<(), CoseError> {
    let certificates = vec![vec![0x30, 0x03, 0x02, 0x01, 0x01]];
    for algorithm in [Exact::Es256, Exact::Esp256] {
        let signed = crate::cose_sign1_with_signature_algorithm_and_external_aad(
            algorithm,
            b"payload",
            &private(),
            Some(b"k"),
            &[],
            crate::CoseSign1EncodeOptions::new().with_x5chain_der(certificates.clone()),
        )?;
        let resolver = |actual: Exact, received: &[Vec<u8>]| {
            assert_eq!(actual, algorithm);
            assert_eq!(received, certificates);
            Some(public())
        };
        let _ = crate::cose_verify1_with_x5chain(&signed, &broad(), resolver)?;
        let _ = crate::cose_verify1_with_x5chain_and_exact_algorithm(&signed, &broad(), resolver)?;
        if algorithm == Exact::Esp256 {
            assert_eq!(
                crate::cose_verify1_with_x5chain(&signed, &broad(), |actual, _| (actual
                    == Exact::Es256)
                    .then(public))
                .err(),
                Some(CoseError::KeyNotResolved)
            );
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
#[allow(deprecated)] // The historical protobuf primitive selector denotes ESP256 exactly.
fn direct_binding_compatibility_selector_is_esp256_and_never_es256() -> Result<(), CoseError> {
    for registration in [Exact::Es256, Exact::Esp256] {
        let bytes = encoded(registration, false)?;
        let input = attached(&bytes, wire::CoseSignatureAlgorithm::EcdsaP256Sha256);
        let response = codec_parity(Operation::Sign1Verify(Box::new(input)))?;
        if registration == Exact::Esp256 {
            let _ = success(response);
        } else {
            assert_eq!(
                reason(&response),
                wire::CoseErrorReason::KeyAlgorithmMismatch
            );
        }
    }
    Ok(())
}
