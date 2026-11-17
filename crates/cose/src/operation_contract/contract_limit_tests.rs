// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, reason, success};
use crate::api::contract::{
    __buffa::oneof::cose_operation_request::Operation, CoseByteLimits, CoseErrorReason,
    CoseSign1CreateDetachedRequest, CoseSign1CreateRequest, CoseSign1Options,
    CoseSign1VerifyProfileRequest, CoseSign1VerifyRequest, CoseSignatureAlgorithm,
    CoseVerificationPolicy,
};
use crate::limits::{MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES};
use crate::{Algorithm, CoseError, CosePolicy, CoseSign1EncodeOptions};
use zeroize::Zeroizing;

fn limits(encoded: u64, payload: u64, aad: u64) -> CoseByteLimits {
    CoseByteLimits {
        encoded_bytes: encoded,
        payload_bytes: payload,
        external_aad_bytes: aad,
    }
}

fn policy(limits: CoseByteLimits) -> CoseVerificationPolicy {
    CoseVerificationPolicy::default()
        .with_allow_any_algorithm(true)
        .with_limits(limits)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign1_policy_limits_clamp_builders_and_portable_contracts() -> Result<(), CoseError> {
    let defaults = CosePolicy::default();
    assert_eq!(defaults.max_cose_sign1_bytes(), MAX_COSE_SIGN1_BYTES);
    assert_eq!(
        defaults.max_detached_payload_bytes(),
        MAX_DETACHED_PAYLOAD_BYTES
    );
    assert_eq!(defaults.max_external_aad_bytes(), MAX_COSE_SIGN1_BYTES);
    for value in [0, 1, u64::MAX] {
        let value = CosePolicy::from_contract(policy(limits(value, value, value)))?;
        let expected = if value.contract().limits.encoded_bytes == u64::MAX {
            (
                MAX_COSE_SIGN1_BYTES,
                MAX_DETACHED_PAYLOAD_BYTES,
                MAX_COSE_SIGN1_BYTES,
            )
        } else {
            let n = usize::try_from(value.contract().limits.encoded_bytes)
                .map_err(|_| CoseError::ResourceLimitExceeded)?;
            (n, n, n)
        };
        assert_eq!(value.max_cose_sign1_bytes(), expected.0);
        assert_eq!(value.max_detached_payload_bytes(), expected.1);
        assert_eq!(value.max_external_aad_bytes(), expected.2);
    }
    let built = CosePolicy::default()
        .with_max_cose_sign1_bytes(usize::MAX)
        .with_max_detached_payload_bytes(usize::MAX);
    assert_eq!(built.max_cose_sign1_bytes(), MAX_COSE_SIGN1_BYTES);
    assert_eq!(
        built.max_detached_payload_bytes(),
        MAX_DETACHED_PAYLOAD_BYTES
    );
    let built = built
        .with_max_cose_sign1_bytes(0)
        .with_max_detached_payload_bytes(0);
    assert_eq!(built.max_cose_sign1_bytes(), 0);
    assert_eq!(built.max_detached_payload_bytes(), 0);
    assert_eq!(built.max_external_aad_bytes(), MAX_COSE_SIGN1_BYTES);
    let options = CoseSign1EncodeOptions::new().with_max_cose_sign1_bytes(usize::MAX);
    assert_eq!(options.max_cose_sign1_bytes(), MAX_COSE_SIGN1_BYTES);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign1_verification_limits_reject_before_parsing_or_resolving() -> Result<(), CoseError> {
    let policy = CosePolicy::from_contract(policy(limits(u64::MAX, u64::MAX, u64::MAX)))?;
    let encoded = vec![
        0;
        MAX_COSE_SIGN1_BYTES
            .checked_add(1)
            .ok_or(CoseError::ResourceLimitExceeded)?
    ];
    let payload = vec![
        0;
        MAX_DETACHED_PAYLOAD_BYTES
            .checked_add(1)
            .ok_or(CoseError::ResourceLimitExceeded)?
    ];
    let called = core::cell::Cell::new(false);
    for (encoded, payload, aad) in [
        (encoded.as_slice(), &[][..], &[][..]),
        (&[][..], payload.as_slice(), &[][..]),
        (&[][..], &[][..], encoded.as_slice()),
    ] {
        let rejected = crate::cose_verify1_detached_with_policy_and_external_aad(
            encoded,
            payload,
            aad,
            &policy,
            |_, _| {
                called.set(true);
                None
            },
        );
        assert_eq!(rejected.err(), Some(CoseError::ResourceLimitExceeded));
    }
    assert!(!called.get());
    Ok(())
}

fn keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CoseError> {
    let (public, private) = reallyme_crypto::dispatch::generate_keypair(Algorithm::Ed25519)
        .map_err(|_| CoseError::Crypto)?;
    Ok((public, Zeroizing::new(private.to_vec())))
}

fn sign(
    private: &[u8],
    payload: &[u8],
    aad: &[u8],
    detached: bool,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let options = CoseSign1EncodeOptions::new();
    if detached {
        crate::cose_sign1_detached_with_options_and_external_aad(
            Algorithm::Ed25519,
            payload,
            private,
            None,
            aad,
            options,
        )
    } else {
        crate::cose_sign1_with_options_and_external_aad(
            Algorithm::Ed25519,
            payload,
            private,
            None,
            aad,
            options,
        )
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign1_verification_enforces_independent_zero_and_exact_limits() -> Result<(), CoseError> {
    let (public, private) = keypair()?;
    for detached in [false, true] {
        for (payload, aad, payload_limit, aad_limit, accepted) in [
            (&b"data"[..], &b"ad"[..], 4, 2, true),
            (&b"data"[..], &b"ad"[..], 3, 2, false),
            (&b"data"[..], &b"ad"[..], 0, 2, false),
            (&b"data"[..], &b"ad"[..], 4, 1, false),
            (&b"data"[..], &b"ad"[..], 4, 0, false),
            (&[][..], &b"ad"[..], 0, 2, true),
            (&[][..], &[][..], 0, 0, true),
        ] {
            let encoded = sign(&private, payload, aad, detached)?;
            let encoded_limit =
                u64::try_from(encoded.len()).map_err(|_| CoseError::ResourceLimitExceeded)?;
            let contract = policy(limits(encoded_limit, payload_limit, aad_limit));
            let native = CosePolicy::from_contract(contract.clone())?;
            let resolved = core::cell::Cell::new(false);
            let resolver = |_: Algorithm, _: &[u8]| {
                resolved.set(true);
                Some(public.clone())
            };
            let actual = if detached {
                crate::cose_verify1_detached_with_policy_and_external_aad(
                    &encoded, payload, aad, &native, resolver,
                )
                .map(|_| ())
            } else {
                crate::cose_verify1_with_policy_and_external_aad(&encoded, aad, &native, resolver)
                    .map(|_| ())
            };
            let expected = if accepted {
                Ok(())
            } else {
                Err(CoseError::ResourceLimitExceeded)
            };
            assert_eq!(actual, expected);
            assert_eq!(resolved.get(), accepted);
            let request = CoseSign1VerifyRequest::default()
                .with_cose_sign1(encoded.to_vec())
                .with_public_key(public.clone())
                .with_external_aad(aad.to_vec());
            let mut request = CoseSign1VerifyProfileRequest::default()
                .with_request(request)
                .with_policy(contract)
                .with_detached(detached);
            if detached {
                request.detached_payload = payload.to_vec().into();
            }
            let response = codec_parity(Operation::Sign1VerifyProfile(Box::new(request)))?;
            if accepted {
                success(response);
            } else {
                assert_eq!(
                    reason(&response),
                    CoseErrorReason::CommonResourceLimitExceeded
                );
            }
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign1_signing_preserves_all_canonical_limits_and_zero_presence() -> Result<(), CoseError> {
    let (_, private) = keypair()?;
    for detached in [false, true] {
        for (payload_limit, aad_limit, accepted) in [
            (4, 2, true),
            (3, 2, false),
            (0, 2, false),
            (4, 1, false),
            (4, 0, false),
        ] {
            let options = CoseSign1Options::default()
                .with_max_cose_sign1_bytes(u64::MAX)
                .with_limits(limits(u64::MAX, payload_limit, aad_limit));
            let response = if detached {
                codec_parity(Operation::Sign1CreateDetached(Box::new(
                    CoseSign1CreateDetachedRequest::default()
                        .with_algorithm(CoseSignatureAlgorithm::Ed25519)
                        .with_private_key(private.to_vec())
                        .with_payload(b"data".to_vec())
                        .with_external_aad(b"ad".to_vec())
                        .with_options(options),
                )))?
            } else {
                codec_parity(Operation::Sign1Create(Box::new(
                    CoseSign1CreateRequest::default()
                        .with_algorithm(CoseSignatureAlgorithm::Ed25519)
                        .with_private_key(private.to_vec())
                        .with_payload(b"data".to_vec())
                        .with_external_aad(b"ad".to_vec())
                        .with_options(options),
                )))?
            };
            if accepted {
                success(response);
            } else {
                assert_eq!(
                    reason(&response),
                    CoseErrorReason::CommonResourceLimitExceeded
                );
            }
        }
    }
    // A present all-zero message must reject output; absent limits keep defaults.
    let mut input = CoseSign1CreateRequest::default()
        .with_algorithm(CoseSignatureAlgorithm::Ed25519)
        .with_private_key(private.to_vec());
    input.options = field(CoseSign1Options::default().with_limits(CoseByteLimits::default()));
    let response = codec_parity(Operation::Sign1Create(Box::new(input)))?;
    assert_eq!(
        reason(&response),
        CoseErrorReason::CommonResourceLimitExceeded
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign1_aad_hard_boundary_is_identical_for_signing_and_verification() -> Result<(), CoseError> {
    let (public, private) = keypair()?;
    let mut aad = vec![0x5a; MAX_COSE_SIGN1_BYTES];
    for detached in [false, true] {
        let encoded = sign(&private, b"data", &aad, detached)?;
        let policy = CosePolicy::from_contract(policy(limits(u64::MAX, u64::MAX, u64::MAX)))?;
        let result = if detached {
            crate::cose_verify1_detached_with_policy_and_external_aad(
                &encoded,
                b"data",
                &aad,
                &policy,
                |_, _| Some(public.clone()),
            )
            .map(|_| ())
        } else {
            crate::cose_verify1_with_policy_and_external_aad(&encoded, &aad, &policy, |_, _| {
                Some(public.clone())
            })
            .map(|_| ())
        };
        assert_eq!(result, Ok(()));
    }
    aad.push(0);
    assert_eq!(
        sign(&private, b"data", &aad, false).err(),
        Some(CoseError::ResourceLimitExceeded)
    );
    assert_eq!(
        sign(&private, b"data", &aad, true).err(),
        Some(CoseError::ResourceLimitExceeded)
    );
    let payload = Zeroizing::new(vec![0x42; MAX_DETACHED_PAYLOAD_BYTES]);
    let encoded = sign(&private, &payload, &[], true)?;
    assert!(crate::cose_verify1_detached_with_policy_and_external_aad(
        &encoded,
        &payload,
        &[],
        &CosePolicy::default(),
        |_, _| Some(public.clone()),
    )
    .is_ok());
    Ok(())
}
