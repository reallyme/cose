// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{field, hex, keys, suite};
use crate::api::{contract as wire, ProviderTransport};
use crate::containers::{
    AgreementKeyProvider, CryptoVerificationKey, PeerKeyValidator, SignatureSuite, VerificationKey,
};
use crate::{Algorithm, CoseError, CoseSignatureAlgorithm};
use buffa::Message;
use core::cell::Cell;
use wire::{
    cose_provider_call_request::Call, cose_provider_call_response::Outcome,
    cose_provider_call_result::Result as Branch, cose_signing_input::Input,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Default)]
pub(super) enum Fault {
    #[default]
    None,
    WrongResult,
    UnknownResponse,
    Unavailable,
    CorruptSignature,
    DoubleHash,
    WrongHash,
    WrongEncoding,
    OversizedKey,
    VerifierContext,
    VerifierPublicKey,
    VerifierSuite,
}
pub(super) struct Port {
    pub registry: wire::CoseProviderRegistry,
    pub fault: Fault,
    pub prehash: bool,
    pub external_verifier: bool,
    pub selected_certificate: Vec<u8>,
    pub calls: Cell<usize>,
    pub signatures: Cell<usize>,
    pub verifications: Cell<usize>,
    key: CryptoVerificationKey,
    private: Zeroizing<Vec<u8>>,
    mac: crate::CoseMacKey,
}
impl Port {
    pub fn new(identifier: i64) -> Result<Self, CoseError> {
        let algorithm = CoseSignatureAlgorithm::from_identifier(identifier)?;
        let curve = if identifier == -7 || identifier == -9 {
            1
        } else {
            6
        };
        let point = keys()?
            .into_iter()
            .find(|key| key.curve == curve)
            .ok_or(CoseError::InvalidKeyMaterial)?;
        let curve = crate::iso18013::Iso18013SignatureCurve::from_identifier(curve)?;
        let selected = if algorithm.is_iso() {
            SignatureSuite::iso(algorithm, curve)?
        } else {
            SignatureSuite::modern(algorithm)?
        };
        let private = if identifier == -7 || identifier == -9 {
            let mut value = vec![0; 32];
            value[31] = 1;
            value
        } else {
            (0u8..32).collect()
        };
        let kinds = [
            wire::CoseProviderKind::Signer,
            wire::CoseProviderKind::VerificationKey,
            wire::CoseProviderKind::CertificateValidator,
            wire::CoseProviderKind::KeyResolver,
            wire::CoseProviderKind::MacVerifier,
            wire::CoseProviderKind::PeerKeyValidator,
            wire::CoseProviderKind::AgreementKeyNormalizer,
        ];
        let registry = wire::CoseProviderRegistry {
            capabilities: kinds
                .into_iter()
                .map(|kind| wire::CoseProviderCapability {
                    handle: 1,
                    kind: kind.into(),
                })
                .collect(),
        };
        let mac = crate::CoseMacKey::new(
            crate::CoseMacAlgorithm::Hmac256_256,
            Zeroizing::new(hex(
                "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188",
            )),
        )?;
        Ok(Self {
            registry,
            fault: Fault::None,
            prehash: false,
            external_verifier: true,
            selected_certificate: Vec::new(),
            calls: Cell::new(0),
            signatures: Cell::new(0),
            verifications: Cell::new(0),
            key: CryptoVerificationKey::new(
                selected,
                Zeroizing::new(hex(&point.public)),
                [0x42; 32],
            )?,
            private: Zeroizing::new(private),
            mac,
        })
    }
    fn working_key(&self) -> wire::CoseWorkingKey {
        wire::CoseWorkingKey {
            suite: field(wire::CoseSignatureSuite::from(self.key.suite())),
            public_key: self.key.public_key().to_vec().into(),
            context_id: self.key.context_id().to_vec().into(),
        }
    }
    fn execute(&self, mut request: wire::CoseProviderCallRequest) -> Result<Branch, CoseError> {
        self.calls.set(self.calls.get() + 1);
        if matches!(self.fault, Fault::Unavailable) {
            return Err(CoseError::ProviderUnavailable);
        }
        if matches!(self.fault, Fault::WrongResult) {
            return Ok(Branch::Verify(Box::default()));
        }
        let kind = request
            .capability
            .as_option()
            .ok_or(CoseError::InvalidFormat)?
            .kind;
        match request.call.as_mut().ok_or(CoseError::InvalidFormat)? {
            Call::Describe(_) => {
                let mut description = wire::CoseProviderDescription::default();
                let mut signer = wire::CoseProviderSignerDescription::default();
                if kind == wire::CoseProviderKind::MacVerifier {
                    description.description =
                        Some(wire::cose_provider_description::Description::MacAlgorithm(
                            wire::CoseMacAlgorithm::Hmac256256.into(),
                        ));
                } else {
                    let mut key = self.working_key();
                    if matches!(self.fault, Fault::OversizedKey) {
                        key.public_key = vec![0; crate::limits::MAX_COSE_KEY_BYTES + 1].into();
                    }
                    if kind == wire::CoseProviderKind::VerificationKey {
                        match self.fault {
                            Fault::VerifierContext => key.context_id[0] ^= 1,
                            Fault::VerifierPublicKey => key.public_key[0] ^= 1,
                            Fault::VerifierSuite => {
                                key.suite
                                    .as_option_mut()
                                    .ok_or(CoseError::InvalidFormat)?
                                    .registration = wire::CoseSignatureAlgorithm::Ed25519.into();
                            }
                            _ => {}
                        }
                        description.description = Some(
                            wire::cose_provider_description::Description::VerificationKey(
                                Box::new(key),
                            ),
                        );
                    } else {
                        signer.key = field(key);
                    }
                    signer.signing_mode = if self.prehash {
                        wire::CoseSigningMode::EcdsaPrehash
                    } else {
                        wire::CoseSigningMode::Message
                    }
                    .into();
                    signer.prehash = if matches!(self.fault, Fault::WrongHash) {
                        wire::CoseHashAlgorithm::Sha384
                    } else if self.prehash {
                        wire::CoseHashAlgorithm::Sha256
                    } else {
                        wire::CoseHashAlgorithm::Unspecified
                    }
                    .into();
                    signer.signature_encoding = if matches!(self.fault, Fault::WrongEncoding) {
                        wire::CoseSignatureEncoding::CoseEcdsa
                    } else if self.key.suite().curve().coordinate_length().is_some() {
                        wire::CoseSignatureEncoding::EcdsaDer
                    } else {
                        wire::CoseSignatureEncoding::Eddsa
                    }
                    .into();
                }
                if kind == wire::CoseProviderKind::Signer {
                    if self.external_verifier && self.key.suite().registration().is_iso() {
                        signer.verifier =
                            super::support::capability(1, wire::CoseProviderKind::VerificationKey);
                    }
                    description.description = Some(
                        wire::cose_provider_description::Description::Signer(Box::new(signer)),
                    );
                }
                Ok(Branch::Describe(Box::new(description)))
            }
            Call::Sign(input) => {
                self.signatures.set(self.signatures.get() + 1);
                let primitive = if self.key.suite().curve().coordinate_length().is_some() {
                    Algorithm::P256
                } else {
                    Algorithm::Ed25519
                };
                let mut signature = match input.input.as_mut().ok_or(CoseError::InvalidFormat)? {
                    Input::Message(value) => {
                        reallyme_crypto::dispatch::sign(primitive, &self.private, &value.encoded)
                            .map_err(|_| CoseError::Crypto)?
                    }
                    Input::EcdsaPrehash(value) => {
                        if value.hash != wire::CoseHashAlgorithm::Sha256 || value.digest.len() != 32
                        {
                            return Err(CoseError::InvalidFormat);
                        }
                        if matches!(self.fault, Fault::DoubleHash) {
                            reallyme_crypto::dispatch::sign(primitive, &self.private, &value.digest)
                                .map_err(|_| CoseError::Crypto)?
                        } else {
                            use p256::ecdsa::signature::hazmat::PrehashSigner;
                            let key = p256::ecdsa::SigningKey::from_slice(&self.private)
                                .map_err(|_| CoseError::InvalidKeyMaterial)?;
                            let signature: p256::ecdsa::Signature = key
                                .sign_prehash(&value.digest)
                                .map_err(|_| CoseError::Crypto)?;
                            signature.to_der().as_bytes().to_vec()
                        }
                    }
                };
                if matches!(self.fault, Fault::CorruptSignature) {
                    *signature.last_mut().ok_or(CoseError::InvalidSignature)? ^= 1;
                }
                Ok(Branch::Sign(Box::new(wire::CoseOpaqueBytes {
                    encoded: signature.into(),
                })))
            }
            Call::Verify(value) => {
                self.verifications.set(self.verifications.get() + 1);
                if value.key.as_option() != Some(&self.working_key()) {
                    return Err(CoseError::InvalidKeyMaterial);
                }
                self.key.verify(&value.message, &value.signature)?;
                Ok(Branch::Verify(Box::default()))
            }
            Call::ResolveKey(value) => {
                if value.algorithm
                    != wire::CoseSignatureAlgorithm::from(self.key.suite().registration())
                {
                    return Err(wire::CoseErrorReason::KeyAlgorithmMismatch.into());
                }
                Ok(Branch::ResolveKey(Box::new(wire::CoseOpaqueBytes {
                    encoded: self.key.public_key().to_vec().into(),
                })))
            }
            Call::ResolveCertificate(_) => Ok(Branch::ResolveCertificate(Box::new(
                wire::CoseProviderCertificateResult {
                    key: field(self.working_key()),
                    end_entity_der: self.selected_certificate.clone().into(),
                },
            ))),
            Call::VerifyMac(value) => {
                crate::mac0::CoseMacVerifier::verify(&self.mac, &value.message, &value.tag)?;
                Ok(Branch::VerifyMac(Box::default()))
            }
            Call::NormalizeAgreement(value) => {
                let point = crate::containers::CryptoAgreementKeyProvider.normalize_public_key(
                    crate::containers::PeerCurve::try_from(value.curve)?,
                    &value.public_key,
                )?;
                Ok(Branch::NormalizeAgreement(Box::new(
                    wire::CoseOpaqueBytes {
                        encoded: point.to_vec().into(),
                    },
                )))
            }
            Call::ValidatePeer(value) => {
                let usage = if value.purpose == wire::CosePeerKeyPurpose::Agreement {
                    crate::containers::PeerKeyUsage::Agreement
                } else {
                    return Err(CoseError::InvalidFormat);
                };
                crate::containers::CryptoPeerKeyValidator.validate(
                    crate::containers::PeerCurve::try_from(value.curve)?,
                    usage,
                    &value.public_key,
                )?;
                Ok(Branch::ValidatePeer(Box::default()))
            }
        }
    }
}
impl ProviderTransport for Port {
    fn registry(&self) -> &wire::CoseProviderRegistry {
        &self.registry
    }
    fn call(&self, request: wire::CoseProviderCallRequest) -> wire::CoseProviderCallResponse {
        // Serialize both directions: the provider only consumes the schema's
        // messages, including mode/encoding and fixed error envelopes.
        let decoded =
            crate::wire::decode_protobuf::<wire::CoseProviderCallRequest>(&request.encode_to_vec())
                .map_err(|_| CoseError::Cbor);
        let result = decoded.and_then(|request| self.execute(request));
        let response = wire::CoseProviderCallResponse {
            outcome: Some(match result {
                Ok(result) => Outcome::Result(Box::new(wire::CoseProviderCallResult {
                    result: Some(result),
                })),
                Err(error) => Outcome::Error(Box::new(crate::wire::cose_error(
                    crate::wire::CoseWireError::from_reason(error.reason()),
                ))),
            }),
        };
        let mut bytes = response.encode_to_vec();
        if matches!(self.fault, Fault::UnknownResponse) {
            bytes.extend_from_slice(&[0xa0, 0x06, 1]);
        }
        crate::wire::decode_protobuf::<wire::CoseProviderCallResponse>(&bytes).unwrap_or_else(
            |error| wire::CoseProviderCallResponse {
                outcome: Some(Outcome::Error(Box::new(crate::wire::cose_error(error)))),
            },
        )
    }
}

pub(super) fn fixture(algorithm: i64) -> Result<serde_json::Value, CoseError> {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/signature-suites.json"))
            .map_err(|_| CoseError::Cbor)?;
    value
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case["algorithm"] == algorithm
                    && case["curve"]
                        == if algorithm == -8 || algorithm == -19 {
                            6
                        } else {
                            1
                        }
            })
        })
        .cloned()
        .ok_or(CoseError::InvalidFormat)
}
pub(super) fn bytes(value: &serde_json::Value, name: &str) -> Result<Vec<u8>, CoseError> {
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(hex)
        .ok_or(CoseError::InvalidFormat)
}
pub(super) fn sign_request(algorithm: i64) -> Result<wire::CoseContainerSignRequest, CoseError> {
    let value = fixture(algorithm)?;
    Ok(wire::CoseContainerSignRequest {
        protected_headers: bytes(&value, "protected")?.into(),
        unprotected_headers: vec![0xa0].into(),
        payload: bytes(&value, "payload")?.into(),
        content_mode: wire::CoseContentMode::Detached.into(),
        external_aad: Vec::new().into(),
        policy: field(wire::CoseContainerPolicy {
            profile: wire::CoseContainerProfile::IsoEdition2Dis.into(),
            purpose: wire::CoseContainerPurpose::ReaderAuthentication.into(),
            envelope: wire::CoseEnvelopePolicy::Untagged.into(),
        }),
        allowed_suites: vec![suite(algorithm, if algorithm == -8 { 6 } else { 1 })?].into(),
        capability: super::support::capability(1, wire::CoseProviderKind::Signer),
        limits: Default::default(),
    })
}
