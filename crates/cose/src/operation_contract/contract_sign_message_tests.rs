// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, hex, reason, success};
use crate::api::contract::{
    self as contract,
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
    CoseNamedCurve as Curve, CoseSignatureAlgorithm as Alg,
};
use crate::{Algorithm, CoseError};
use buffa::Message;

fn suite(algorithm: Alg, curve: Curve) -> contract::CoseSignatureSuite {
    contract::CoseSignatureSuite {
        registration: algorithm.into(),
        curve: curve.into(),
    }
}
fn headers(protected: &[u8]) -> contract::CoseMessageHeaders {
    contract::CoseMessageHeaders {
        protected: protected.to_vec().into(),
        unprotected: vec![0xa0].into(),
    }
}
fn request(
    encoded: Vec<u8>,
    suites: &[contract::CoseSignatureSuite],
    keys: &[Vec<u8>],
) -> contract::CoseSignVerifyRequest {
    contract::CoseSignVerifyRequest {
        encoded: encoded.into(),
        envelope: contract::CoseEnvelopePolicy::Either.into(),
        keys: suites
            .iter()
            .zip(keys)
            .enumerate()
            .map(|(index, (suite, key))| contract::CoseSignKeyBinding {
                signature_index: u32::try_from(index).unwrap_or(u32::MAX),
                suite: field(suite.clone()),
                public_key: key.clone().into(),
            })
            .collect::<Vec<_>>()
            .into(),
        allowed_suites: suites.to_vec().into(),
        detached_payload: None,
        external_aad: Vec::new().into(),
    }
}
fn verify(
    request: contract::CoseSignVerifyRequest,
) -> Result<contract::CoseOperationResponseV2, CoseError> {
    codec_parity(Operation::SignVerify(Box::new(request)))
}
fn rfc_public() -> Vec<u8> {
    hex("04bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")
}
fn rfc_signature() -> Vec<u8> {
    hex("e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a")
}
fn rfc_message() -> Vec<u8> {
    // RFC 9052 C.1.1, independent P-256 Signature-context vector.
    let mut bytes =
        hex("d8628440a054546869732069732074686520636f6e74656e742e818343a10126a1044231315840");
    bytes.extend_from_slice(&rfc_signature());
    bytes
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign_rfc_single_and_multiple_signatures_verify_exact_bytes() -> Result<(), CoseError> {
    let p256 = suite(Alg::Es256, Curve::P256);
    let result = success(verify(request(
        rfc_message(),
        std::slice::from_ref(&p256),
        &[rfc_public()],
    ))?);
    let Branch::SignVerify(result) = &result else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(
        result.attached_payload.as_deref(),
        Some(b"This is the content.".as_slice())
    );
    assert!(result.body_protected.is_empty());
    assert_eq!(result.signatures[0].protected, hex("a10126"));
    assert_eq!(result.signatures[0].protected_kid, None);
    // RFC 9052 C.1.2 adds a P-521 signer without changing the first signature.
    let mut multi = rfc_message();
    *multi.get_mut(26).ok_or(CoseError::InvalidFormat)? = 0x82;
    multi.extend_from_slice(&hex("8344a1013823a104581e62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65588400a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf482270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297"));
    let p521=hex("040072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475");
    let response = verify(request(
        multi,
        &[p256, suite(Alg::Es512, Curve::P521)],
        &[rfc_public(), p521],
    ))?;
    let result = success(response);
    let Branch::SignVerify(result) = &result else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(result.signatures.len(), 2);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign_rejects_tampering_wrong_binding_critical_duplicates_and_trailing_data(
) -> Result<(), CoseError> {
    let valid = request(
        rfc_message(),
        &[suite(Alg::Es256, Curve::P256)],
        &[rfc_public()],
    );
    for position in [6, 39, 102] {
        let mut changed = valid.clone();
        let mut encoded = changed.encoded.to_vec();
        *encoded.get_mut(position).ok_or(CoseError::InvalidFormat)? ^= 1;
        changed.encoded = encoded.into();
        assert_eq!(
            reason(&verify(changed)?),
            CoseError::InvalidSignature.reason()
        );
    }
    let mut changed = valid.clone();
    changed.external_aad = vec![1].into();
    assert_eq!(
        reason(&verify(changed)?),
        CoseError::InvalidSignature.reason()
    );
    let mut changed = valid.clone();
    changed
        .keys
        .get_mut(0)
        .ok_or(CoseError::InvalidFormat)?
        .signature_index = 1;
    assert_eq!(
        reason(&verify(changed)?),
        CoseError::InvalidKeyMaterial.reason()
    );
    let mut changed = valid.clone();
    changed
        .keys
        .get_mut(0)
        .ok_or(CoseError::InvalidFormat)?
        .suite = field(suite(Alg::Esp256, Curve::P256));
    assert_eq!(
        reason(&verify(changed)?),
        CoseError::UnsupportedAlgorithm.reason()
    );
    let mut changed = valid.clone();
    let mut encoded = changed.encoded.to_vec();
    encoded.push(0);
    changed.encoded = encoded.into();
    assert_eq!(reason(&verify(changed)?), CoseError::Cbor.reason());
    let mut changed = valid.clone();
    changed.allowed_suites.clear();
    assert_eq!(
        reason(&verify(changed)?),
        CoseError::UnsupportedAlgorithm.reason()
    );
    let mut changed = valid;
    changed.detached_payload = Some(Vec::new().into());
    assert_eq!(reason(&verify(changed)?), CoseError::InvalidFormat.reason());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign_create_attached_detached_and_shared_body_algorithm() -> Result<(), CoseError> {
    let (public, private) = reallyme_crypto::dispatch::generate_keypair(Algorithm::Ed25519)
        .map_err(|_| CoseError::Crypto)?;
    for mode in [
        contract::CoseContentMode::Attached,
        contract::CoseContentMode::Detached,
    ] {
        for shared in [true, false] {
            // Unsorted protected labels and present-empty protected kid survive.
            let protected = hex("a204400127");
            let suite = suite(Alg::Eddsa, Curve::Ed25519);
            let mut create = contract::CoseSignCreateRequest {
                headers: field(headers(if shared { &protected } else { &[] })),
                payload: b"payload".to_vec().into(),
                external_aad: b"aad".to_vec().into(),
                content_mode: mode.into(),
                tagged: true,
                signers: vec![contract::CoseSignSigner {
                    headers: field(headers(if shared { &[] } else { &protected })),
                    suite: field(suite.clone()),
                    private_key: private.to_vec().into(),
                }]
                .into(),
                allowed_suites: vec![suite.clone()].into(),
            };
            let result = success(codec_parity(Operation::SignCreate(Box::new(
                create.clone(),
            )))?);
            let Branch::SignCreate(result) = &result else {
                return Err(CoseError::InvalidFormat);
            };
            let mut verify_request = request(
                result.encoded.to_vec(),
                &[suite],
                std::slice::from_ref(&public),
            );
            verify_request.external_aad = b"aad".to_vec().into();
            if mode == contract::CoseContentMode::Detached {
                verify_request.detached_payload = Some(b"payload".to_vec().into());
            }
            let mut reordered = verify_request.clone();
            let mut bytes = reordered.encoded.to_vec();
            let offset = bytes
                .windows(protected.len())
                .position(|part| part == protected)
                .ok_or(CoseError::InvalidFormat)?;
            bytes
                .get_mut(
                    offset
                        ..offset
                            .checked_add(protected.len())
                            .ok_or(CoseError::ResourceLimitExceeded)?,
                )
                .ok_or(CoseError::InvalidFormat)?
                .copy_from_slice(&hex("a201270440"));
            reordered.encoded = bytes.into();
            assert_eq!(
                reason(&verify(reordered)?),
                CoseError::InvalidSignature.reason()
            );
            let result = success(verify(verify_request.clone())?);
            let Branch::SignVerify(result) = &result else {
                return Err(CoseError::InvalidFormat);
            };
            assert_eq!(
                if shared {
                    &result.body_protected
                } else {
                    &result.signatures[0].protected
                },
                &protected
            );
            if !shared {
                assert_eq!(
                    result.signatures[0].protected_kid.as_deref(),
                    Some([].as_slice())
                );
            }
            if mode == contract::CoseContentMode::Detached {
                verify_request.detached_payload = Some(b"wrong".to_vec().into());
                assert_eq!(
                    reason(&verify(verify_request)?),
                    CoseError::InvalidSignature.reason()
                );
            }
            create.clear();
            assert!(create.payload.is_empty());
            assert!(create.signers.is_empty());
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign_all_builtin_suites_keep_exact_registration_and_curve() -> Result<(), CoseError> {
    for (registration, curve, algorithm, protected) in [
        (Alg::Es256, Curve::P256, Algorithm::P256, "a10126"),
        (Alg::Esp256, Curve::P256, Algorithm::P256, "a10128"),
        (Alg::Es384, Curve::P384, Algorithm::P384, "a1013822"),
        (Alg::Esp384, Curve::P384, Algorithm::P384, "a1013832"),
        (Alg::Es512, Curve::P521, Algorithm::P521, "a1013823"),
        (Alg::Esp512, Curve::P521, Algorithm::P521, "a1013833"),
        (Alg::Ed25519, Curve::Ed25519, Algorithm::Ed25519, "a10132"),
        (Alg::Eddsa, Curve::Ed25519, Algorithm::Ed25519, "a10127"),
        (
            Alg::EcdsaSecp256k1Sha256,
            Curve::Secp256k1,
            Algorithm::Secp256k1,
            "a101382e",
        ),
        (
            Alg::MlDsa44,
            Curve::Unspecified,
            Algorithm::MlDsa44,
            "a101382f",
        ),
        (
            Alg::MlDsa65,
            Curve::Unspecified,
            Algorithm::MlDsa65,
            "a1013830",
        ),
        (
            Alg::MlDsa87,
            Curve::Unspecified,
            Algorithm::MlDsa87,
            "a1013831",
        ),
    ] {
        let (public, private) = reallyme_crypto::dispatch::generate_keypair(algorithm)
            .map_err(|_| CoseError::Crypto)?;
        let suite = suite(registration, curve);
        let create = contract::CoseSignCreateRequest {
            headers: field(headers(&[])),
            payload: b"payload".to_vec().into(),
            external_aad: Vec::new().into(),
            content_mode: contract::CoseContentMode::Attached.into(),
            tagged: false,
            signers: vec![contract::CoseSignSigner {
                headers: field(headers(&hex(protected))),
                suite: field(suite.clone()),
                private_key: private.to_vec().into(),
            }]
            .into(),
            allowed_suites: vec![suite.clone()].into(),
        };
        let output = success(codec_parity(Operation::SignCreate(Box::new(create)))?);
        let Branch::SignCreate(output) = &output else {
            return Err(CoseError::InvalidFormat);
        };
        let _ = success(verify(request(
            output.encoded.to_vec(),
            &[suite],
            &[public],
        ))?);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign_header_and_resource_failures_are_fixed() -> Result<(), CoseError> {
    for (protected, unprotected, expected) in [
        ("a201260126", "a0", CoseError::DuplicateMapLabel),
        ("a10126", "a10126", CoseError::DuplicateMapLabel),
        ("a201260281182a", "a0", CoseError::UnsupportedCriticalHeader),
        ("a10126", "a1028101", CoseError::UnsupportedCriticalHeader),
        ("", "a10126", CoseError::UnprotectedHeaderNotAllowed),
        ("a20126048101", "a0", CoseError::Cbor),
    ] {
        let create = contract::CoseSignCreateRequest {
            headers: field(headers(&[])),
            payload: Vec::new().into(),
            external_aad: Vec::new().into(),
            content_mode: contract::CoseContentMode::Attached.into(),
            tagged: false,
            signers: vec![contract::CoseSignSigner {
                headers: field(contract::CoseMessageHeaders {
                    protected: hex(protected).into(),
                    unprotected: hex(unprotected).into(),
                }),
                suite: field(suite(Alg::Es256, Curve::P256)),
                private_key: Vec::new().into(),
            }]
            .into(),
            allowed_suites: vec![suite(Alg::Es256, Curve::P256)].into(),
        };
        assert_eq!(
            reason(&codec_parity(Operation::SignCreate(Box::new(create)))?),
            expected.reason()
        );
    }
    let mut request = request(
        rfc_message(),
        &[suite(Alg::Es256, Curve::P256)],
        &[rfc_public()],
    );
    request.external_aad = vec![0; 65_537].into();
    assert_eq!(
        reason(&verify(request)?),
        CoseError::ResourceLimitExceeded.reason()
    );
    Ok(())
}
