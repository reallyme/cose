// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity_with_providers, field, hex, keys, reason, success, suite};
use crate::api::{
    contract::{
        __buffa::oneof::{
            cose_operation_request::Operation, cose_operation_result::Result as Branch,
            cose_type::Value as TypeValue,
        },
        CoseContainerPolicy, CoseContainerProfile, CoseContainerPurpose, CoseContainerSignRequest,
        CoseContentMode, CoseEnvelopePolicy, CoseErrorReason, CoseSign1CreateProfileRequest,
        CoseSign1CreateRequest, CoseSign1VerifyProfileRequest, CoseSign1VerifyRequest,
        CoseSignatureAlgorithm, CoseSignatureAlgorithm as CoseSignatureRegistration,
        CoseType as Type,
    },
    OperationProviders,
};
use crate::containers::{
    ContainerError, ContainerErrorReason as Reason, ContainerSigner, CryptoVerificationKey,
    SignatureEncoding, SignatureSuite, SigningInput, SigningMode, VerificationKey,
};
use crate::{Algorithm, CoseError, CoseSigner, CoseSignerError};
use zeroize::Zeroizing;

struct Signer {
    private: Zeroizing<Vec<u8>>,
    key: CryptoVerificationKey,
}
impl CoseSigner for Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }
    fn sign(&self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseSignerError> {
        reallyme_crypto::dispatch::sign(Algorithm::Ed25519, &self.private, message)
            .map(Zeroizing::new)
            .map_err(|_| CoseSignerError::Backend)
    }
}
impl ContainerSigner for Signer {
    fn verification_key(&self) -> &dyn VerificationKey {
        &self.key
    }
    fn input_mode(&self) -> SigningMode {
        SigningMode::Message
    }
    fn signature_encoding(&self) -> SignatureEncoding {
        SignatureEncoding::EdDsa
    }
    fn sign(&self, input: SigningInput<'_>) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
        let SigningInput::Message(message) = input else {
            return Err(Reason::SigningInput.into());
        };
        CoseSigner::sign(self, message).map_err(|_| Reason::Backend.into())
    }
}
impl OperationProviders for Signer {
    fn cose_signer(&self, _: u64) -> Result<&dyn CoseSigner, ContainerError> {
        Ok(self)
    }
    fn container_signer(&self, _: u64) -> Result<&dyn ContainerSigner, ContainerError> {
        Ok(self)
    }
    fn resolve_sign1_key(
        &self,
        _: u64,
        registration: CoseSignatureRegistration,
        kid: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        if registration != CoseSignatureRegistration::Ed25519 || kid != b"k" {
            return None;
        }
        Some(Zeroizing::new(self.key.public_key().to_vec()))
    }
}
fn signer() -> Result<Signer, CoseError> {
    let public = keys()?
        .into_iter()
        .find(|k| k.curve == 6)
        .ok_or(CoseError::InvalidFormat)?;
    let private = Zeroizing::new((0u8..32).collect());
    let suite = SignatureSuite::iso(
        crate::iso18013::Iso18013SignatureAlgorithm::EdDsa,
        crate::iso18013::Iso18013SignatureCurve::Ed25519,
    )
    .map_err(|_| CoseError::UnsupportedAlgorithm)?;
    let key = CryptoVerificationKey::new(suite, Zeroizing::new(hex(&public.public)), [0; 32])
        .map_err(|_| CoseError::InvalidKeyMaterial)?;
    Ok(Signer { private, key })
}
fn typ() -> Type {
    Type {
        value: Some(TypeValue::ContentFormat(42)),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_modern_profiles_match_raw_and_nonexporting_borrowed_signatures(
) -> Result<(), CoseError> {
    let signer = signer()?;
    for detached in [false, true] {
        for opaque in [false, true] {
            let input = CoseSign1CreateProfileRequest {
                request: field(CoseSign1CreateRequest {
                    algorithm: CoseSignatureAlgorithm::Ed25519.into(),
                    payload: b"payload".to_vec().into(),
                    private_key: if opaque {
                        Vec::new().into()
                    } else {
                        signer.private.to_vec().into()
                    },
                    kid: Some(b"k".to_vec().into()),
                    options: Default::default(),
                    external_aad: b"aad".to_vec().into(),
                }),
                protected_type: field(typ()),
                capability: super::support::capability(
                    if opaque { 1 } else { 0 },
                    crate::api::contract::CoseProviderKind::Signer,
                ),
            };
            let operation = if detached {
                Operation::Sign1CreateDetachedProfile(Box::new(input))
            } else {
                Operation::Sign1CreateProfile(Box::new(input))
            };
            let encoded = match &mut success(codec_parity_with_providers(operation, &signer)?) {
                Branch::Sign1CreateProfile(v) | Branch::Sign1CreateDetachedProfile(v) => {
                    core::mem::take(&mut v.cose_sign1).into_zeroizing()
                }
                _ => return Err(CoseError::InvalidFormat),
            };
            let options = crate::CoseSign1EncodeOptions::new()
                .with_protected_type(crate::CoseType::ContentFormat(42));
            let native = match (detached, opaque) {
                (false, false) => crate::cose_sign1_with_options_and_external_aad(
                    Algorithm::Ed25519,
                    b"payload",
                    &signer.private,
                    Some(b"k"),
                    b"aad",
                    options,
                ),
                (true, false) => crate::cose_sign1_detached_with_options_and_external_aad(
                    Algorithm::Ed25519,
                    b"payload",
                    &signer.private,
                    Some(b"k"),
                    b"aad",
                    options,
                ),
                (false, true) => {
                    crate::cose_sign1_with_signer(&signer, b"payload", Some(b"k"), b"aad", options)
                }
                (true, true) => crate::cose_sign1_detached_with_signer(
                    &signer,
                    b"payload",
                    Some(b"k"),
                    b"aad",
                    options,
                ),
            }?;
            assert_eq!(encoded.as_slice(), native.as_slice());
            let mut input = CoseSign1VerifyProfileRequest {
                policy: Default::default(),
                request: field(CoseSign1VerifyRequest {
                    cose_sign1: encoded.to_vec().into(),
                    public_key: if opaque {
                        Vec::new().into()
                    } else {
                        signer.key.public_key().to_vec().into()
                    },
                    max_cose_sign1_bytes: 0,
                    max_detached_payload_bytes: 0,
                    require_kid: true,
                    allowed_algorithms: vec![CoseSignatureAlgorithm::Ed25519.into()].into(),
                    external_aad: b"aad".to_vec().into(),
                    expected_kid: b"k".to_vec().into(),
                    require_tagged_sign1: false,
                    expected_type: field(typ()),
                    public_key_algorithm: CoseSignatureAlgorithm::Ed25519.into(),
                }),
                detached_payload: if detached {
                    b"payload".to_vec().into()
                } else {
                    Vec::new().into()
                },
                detached,
                allow_unprotected_x5chain: false,
                capability: super::support::capability(
                    if opaque { 1 } else { 0 },
                    crate::api::contract::CoseProviderKind::KeyResolver,
                ),
            };
            let Branch::Sign1VerifyProfile(value) = &mut success(codec_parity_with_providers(
                Operation::Sign1VerifyProfile(Box::new(input.clone())),
                &signer,
            )?) else {
                return Err(CoseError::InvalidFormat);
            };
            assert_eq!(value.payload, if detached { &[][..] } else { b"payload" });
            assert_eq!(value.protected_type.as_option(), Some(&typ()));
            let nested = input
                .request
                .as_option_mut()
                .ok_or(CoseError::InvalidFormat)?;
            nested.external_aad = vec![1].into();
            assert_eq!(
                reason(&codec_parity_with_providers(
                    Operation::Sign1VerifyProfile(Box::new(input)),
                    &signer
                )?),
                CoseErrorReason::Sign1InvalidSignature
            );
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_nonexporting_container_signer_matches_independent_pure_eddsa_answer(
) -> Result<(), CoseError> {
    let signer = signer()?;
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/signature-suites.json"))
            .map_err(|_| CoseError::Cbor)?;
    let case = vectors
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|cases| {
            cases
                .iter()
                .find(|c| c["algorithm"] == -8 && c["curve"] == 6)
        })
        .ok_or(CoseError::InvalidFormat)?;
    let bytes = |name| {
        case.get(name)
            .and_then(serde_json::Value::as_str)
            .map(hex)
            .ok_or(CoseError::InvalidFormat)
    };
    let request = CoseContainerSignRequest {
        protected_headers: bytes("protected")?.into(),
        unprotected_headers: vec![0xa0].into(),
        payload: bytes("payload")?.into(),
        content_mode: CoseContentMode::Detached.into(),
        external_aad: Vec::new().into(),
        policy: field(CoseContainerPolicy {
            profile: CoseContainerProfile::IsoEdition2Dis.into(),
            purpose: CoseContainerPurpose::ReaderAuthentication.into(),
            envelope: CoseEnvelopePolicy::Untagged.into(),
        }),
        allowed_suites: vec![suite(-8, 6)?].into(),
        capability: super::support::capability(1, crate::api::contract::CoseProviderKind::Signer),
        limits: Default::default(),
    };
    let Branch::ContainerSign(value) = &mut success(codec_parity_with_providers(
        Operation::ContainerSign(Box::new(request)),
        &signer,
    )?) else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(value.encoded, bytes("encoded")?);
    Ok(())
}

struct ChainResolver {
    public: Zeroizing<Vec<u8>>,
    calls: core::cell::Cell<usize>,
}
impl OperationProviders for ChainResolver {
    fn resolve_x5chain_key(
        &self,
        handle: u64,
        registration: CoseSignatureRegistration,
        chain: &[Vec<u8>],
    ) -> Option<Zeroizing<Vec<u8>>> {
        self.calls.set(self.calls.get() + 1);
        if handle != 1 || registration != CoseSignatureRegistration::Es256 || chain.is_empty() {
            return None;
        }
        Some(Zeroizing::new(self.public.to_vec()))
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_chain_callback_preserves_placement_and_rejects_before_resolution(
) -> Result<(), CoseError> {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/containers.json"))
            .map_err(|_| CoseError::Cbor)?;
    let case = vectors
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|cases| cases.iter().find(|case| case["id"] == "issuer-2021"))
        .ok_or(CoseError::InvalidFormat)?;
    let bytes = |name| {
        case.get(name)
            .and_then(serde_json::Value::as_str)
            .map(hex)
            .ok_or(CoseError::InvalidFormat)
    };
    let ports = ChainResolver {
        public: Zeroizing::new(bytes("public_key")?),
        calls: core::cell::Cell::new(0),
    };
    let mut request = CoseSign1VerifyProfileRequest {
        policy: Default::default(),
        request: field(CoseSign1VerifyRequest {
            cose_sign1: bytes("encoded")?.into(),
            public_key: Vec::new().into(),
            max_cose_sign1_bytes: 0,
            max_detached_payload_bytes: 0,
            require_kid: false,
            allowed_algorithms: vec![CoseSignatureAlgorithm::Es256.into()].into(),
            external_aad: Vec::new().into(),
            expected_kid: Vec::new().into(),
            require_tagged_sign1: false,
            expected_type: Default::default(),
            public_key_algorithm: CoseSignatureAlgorithm::Es256.into(),
        }),
        detached_payload: Vec::new().into(),
        detached: false,
        allow_unprotected_x5chain: false,
        capability: super::support::capability(
            1,
            crate::api::contract::CoseProviderKind::KeyResolver,
        ),
    };
    assert_eq!(
        reason(&codec_parity_with_providers(
            Operation::Sign1VerifyX5chain(Box::new(request.clone())),
            &ports
        )?),
        CoseErrorReason::Sign1UnprotectedHeaderNotAllowed
    );
    assert_eq!(ports.calls.get(), 0);
    request.allow_unprotected_x5chain = true;
    let Branch::Sign1VerifyX5chain(value) = &mut success(codec_parity_with_providers(
        Operation::Sign1VerifyX5chain(Box::new(request)),
        &ports,
    )?) else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(
        value.placement.as_known(),
        Some(crate::wire::CoseX5ChainHeaderPlacement::Unprotected)
    );
    assert_eq!(
        value
            .verified
            .as_option()
            .ok_or(CoseError::InvalidFormat)?
            .payload,
        bytes("payload")?
    );
    let certificates = &value
        .x5chain
        .as_option()
        .ok_or(CoseError::InvalidFormat)?
        .certificates_der;
    assert_eq!(certificates.len(), 1);
    assert_eq!(
        certificates[0],
        vectors
            .get("certificate_a")
            .and_then(serde_json::Value::as_str)
            .map(hex)
            .ok_or(CoseError::InvalidFormat)?
    );
    Ok(())
}
