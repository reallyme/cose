// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity_with_providers, field, hex, reason, request, success};
use crate::api::{self, contract as wire, ProviderTransport};
use crate::{Algorithm, CoseError};
use buffa::Message;
use core::cell::Cell;
use serde::Deserialize;
use wire::{
    cose_operation_request::Operation, cose_operation_result::Result as ResultBranch,
    cose_provider_call_request::Call, cose_provider_call_response::Outcome,
    cose_provider_call_result::Result as Branch, cose_provider_description::Description,
    cose_signing_input::Input,
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Case {
    id: String,
    public_key_hex: String,
    private_key_seed_hex: String,
    kid_hex: String,
    payload_hex: String,
    cose_sign1_hex: String,
}

struct Port {
    registry: wire::CoseProviderRegistry,
    public: Vec<u8>,
    private: Zeroizing<Vec<u8>>,
    encoding: wire::CoseSignatureEncoding,
    corrupt: bool,
    replacement_signature: Option<Zeroizing<Vec<u8>>>,
    signatures: Cell<usize>,
}
impl Port {
    fn execute(&self, input: &wire::CoseProviderCallRequest) -> Result<Branch, CoseError> {
        match input.call.as_ref() {
            Some(Call::Describe(_)) => {
                Ok(Branch::Describe(Box::new(wire::CoseProviderDescription {
                    description: Some(Description::Signer(Box::new(
                        wire::CoseProviderSignerDescription {
                            key: field(wire::CoseWorkingKey {
                                suite: field(wire::CoseSignatureSuite {
                                    registration:
                                        wire::CoseSignatureAlgorithm::EcdsaSecp256k1Sha256.into(),
                                    curve: wire::CoseNamedCurve::Secp256k1.into(),
                                }),
                                public_key: self.public.clone().into(),
                                context_id: vec![0x42; 32].into(),
                            }),
                            signing_mode: wire::CoseSigningMode::Message.into(),
                            prehash: Default::default(),
                            signature_encoding: self.encoding.into(),
                            verifier: Default::default(),
                        },
                    ))),
                })))
            }
            Some(Call::Sign(value)) => {
                let Some(Input::Message(message)) = value.input.as_ref() else {
                    return Err(CoseError::InvalidFormat);
                };
                self.signatures.set(
                    self.signatures
                        .get()
                        .checked_add(1)
                        .ok_or(CoseError::ResourceLimitExceeded)?,
                );
                let mut signature = Zeroizing::new(
                    reallyme_crypto::dispatch::sign(
                        Algorithm::Secp256k1,
                        &self.private,
                        &message.encoded,
                    )
                    .map_err(|_| CoseError::Crypto)?,
                );
                assert_eq!(signature.len(), 64);
                if self.corrupt {
                    *signature.first_mut().ok_or(CoseError::InvalidFormat)? ^= 1;
                }
                if let Some(replacement) = &self.replacement_signature {
                    signature = Zeroizing::new(replacement.to_vec());
                }
                Ok(Branch::Sign(Box::new(wire::CoseOpaqueBytes {
                    encoded: core::mem::take(&mut *signature).into(),
                })))
            }
            _ => Err(CoseError::InvalidFormat),
        }
    }
}
impl ProviderTransport for Port {
    fn registry(&self) -> &wire::CoseProviderRegistry {
        &self.registry
    }
    fn call(&self, request: wire::CoseProviderCallRequest) -> wire::CoseProviderCallResponse {
        let result = wire::CoseProviderCallRequest::decode_from_slice(&request.encode_to_vec())
            .map_err(|_| CoseError::Cbor)
            .and_then(|request| self.execute(&request));
        wire::CoseProviderCallResponse {
            outcome: Some(match result {
                Ok(result) => Outcome::Result(Box::new(wire::CoseProviderCallResult {
                    result: Some(result),
                })),
                Err(error) => Outcome::Error(Box::new(crate::wire::cose_error(
                    crate::wire::CoseWireError::from_reason(error.reason()),
                ))),
            }),
        }
    }
}

fn fixture(detached: bool) -> Result<(Case, Port), CoseError> {
    let cases: super::support::Cases<Case> =
        serde_json::from_str(include_str!("../../../../vectors/cose-sign1.json"))
            .map_err(|_| CoseError::Cbor)?;
    let id = if detached {
        "cose-sign1-es256k-detached"
    } else {
        "cose-sign1-es256k-attached"
    };
    let case = cases
        .cases
        .into_iter()
        .find(|case| case.id == id)
        .ok_or(CoseError::InvalidFormat)?;
    let port = Port {
        registry: wire::CoseProviderRegistry {
            capabilities: vec![wire::CoseProviderCapability {
                handle: 1,
                kind: wire::CoseProviderKind::Signer.into(),
            }]
            .into(),
        },
        public: hex(&case.public_key_hex),
        private: Zeroizing::new(hex(&case.private_key_seed_hex)),
        encoding: wire::CoseSignatureEncoding::CoseEcdsa,
        corrupt: false,
        replacement_signature: None,
        signatures: Cell::new(0),
    };
    Ok((case, port))
}

fn input(case: &Case, detached: bool) -> wire::CoseOperationRequest {
    let value = Box::new(wire::CoseSign1CreateProfileRequest {
        request: field(
            wire::CoseSign1CreateRequest::default()
                .with_algorithm(wire::CoseSignatureAlgorithm::EcdsaSecp256k1Sha256)
                .with_payload(hex(&case.payload_hex))
                .with_kid(hex(&case.kid_hex)),
        ),
        capability: super::support::capability(1, wire::CoseProviderKind::Signer),
        protected_type: Default::default(),
    });
    request(if detached {
        Operation::Sign1CreateDetachedProfile(value)
    } else {
        Operation::Sign1CreateProfile(value)
    })
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn secp256k1_provider_raw_signatures_match_portable_attached_and_detached_vectors(
) -> Result<(), CoseError> {
    for detached in [false, true] {
        let (case, port) = fixture(detached)?;
        let input = input(&case, detached);
        let binary = Zeroizing::new(input.encode_to_vec());
        let json =
            Zeroizing::new(serde_json::to_string(&input).map_err(|_| CoseError::InvalidFormat)?);
        for input in [
            input,
            wire::CoseOperationRequest::decode_from_slice(&binary).map_err(|_| CoseError::Cbor)?,
            serde_json::from_str(&json).map_err(|_| CoseError::Cbor)?,
        ] {
            let output = success(api::execute_with_provider_transport(input, &port));
            let encoded = match &output {
                ResultBranch::Sign1CreateProfile(value)
                | ResultBranch::Sign1CreateDetachedProfile(value) => &value.cose_sign1,
                _ => return Err(CoseError::InvalidFormat),
            };
            assert_eq!(encoded.as_slice(), hex(&case.cose_sign1_hex));
            if detached {
                crate::cose_verify1_detached(encoded, &hex(&case.payload_hex), |_, _| {
                    Some(port.public.clone())
                })?;
            } else {
                crate::cose_verify1(encoded, |_, _| Some(port.public.clone()))?;
            }
        }
        assert_eq!(port.signatures.get(), 3);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn secp256k1_provider_rejects_declared_der_before_signing_and_tampered_raw_output(
) -> Result<(), CoseError> {
    for detached in [false, true] {
        for encoding in [
            wire::CoseSignatureEncoding::EcdsaDer,
            wire::CoseSignatureEncoding::CoseNative,
        ] {
            let (case, mut port) = fixture(detached)?;
            port.encoding = encoding;
            assert_eq!(
                reason(&api::execute_with_provider_transport(
                    input(&case, detached),
                    &port
                )),
                CoseError::InvalidSignatureEncoding.reason()
            );
            assert_eq!(port.signatures.get(), 0);
        }
        let (case, mut port) = fixture(detached)?;
        port.corrupt = true;
        assert_eq!(
            reason(&api::execute_with_provider_transport(
                input(&case, detached),
                &port
            )),
            CoseError::InvalidSignature.reason()
        );
        assert_eq!(port.signatures.get(), 1);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn secp256k1_provider_rejects_malformed_raw_output_in_every_transport() -> Result<(), CoseError> {
    for detached in [false, true] {
        // A description declaring raw COSE ECDSA does not authorize arbitrary
        // output. Cover wrong lengths, invalid scalars and DER bytes presented
        // as raw; the returned signature is checked before an envelope exists.
        for replacement in [
            Vec::new(),
            vec![0; 63],
            vec![0; 65],
            vec![0; 64],
            hex("3006020101020101"),
        ] {
            let (case, mut port) = fixture(detached)?;
            port.replacement_signature = Some(Zeroizing::new(replacement));
            let session = crate::operation_contract::provider_transport::Session::new(&port);
            let operation = input(&case, detached)
                .operation
                .take()
                .ok_or(CoseError::InvalidFormat)?;
            assert_eq!(
                reason(&codec_parity_with_providers(operation, &session)?),
                CoseError::InvalidSignature.reason()
            );
            assert_eq!(session.take_failure(), None);
            assert_eq!(port.signatures.get(), 3);
        }
    }
    Ok(())
}
