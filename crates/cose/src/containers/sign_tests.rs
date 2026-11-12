// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{assert_error, fixtures, hex, policy, request, suite};
use crate::containers::{
    sign_container, verify_container, ContainerError, ContainerErrorReason as Reason,
    ContainerLimits, ContainerSignRequest, ContainerSigner, CryptoVerificationKey,
    SignatureEncoding, SigningContent, SigningInput, SigningMode, VerificationKey,
    VerificationSource,
};
use crate::iso18013::Iso18013EcdsaHash;
use p256::ecdsa::signature::{hazmat::PrehashSigner, Signer, Verifier};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
enum Fault {
    None,
    Provider,
    WrongKey,
    AlterMessage,
    DoubleHash,
    WrongEncoding,
}

struct OpaqueSigner {
    handle: p256::ecdsa::SigningKey,
    key: CryptoVerificationKey,
    mode: SigningMode,
    encoding: SignatureEncoding,
    fault: Fault,
}
impl ContainerSigner for OpaqueSigner {
    fn verification_key(&self) -> &dyn VerificationKey {
        &self.key
    }
    fn input_mode(&self) -> SigningMode {
        self.mode
    }
    fn signature_encoding(&self) -> SignatureEncoding {
        self.encoding
    }
    fn sign(&self, input: SigningInput<'_>) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
        if matches!(self.fault, Fault::Provider) {
            return Err(Reason::Provider.into());
        }
        let signature: p256::ecdsa::Signature = match input {
            SigningInput::Message(message) => {
                let mut received = message.to_vec();
                assert!(received.starts_with(b"\x84\x6aSignature1"));
                if matches!(self.fault, Fault::AlterMessage) {
                    received[1] ^= 1;
                }
                if matches!(self.fault, Fault::WrongKey) {
                    let mut private = [0; 32];
                    private[31] = 2;
                    let wrong =
                        p256::ecdsa::SigningKey::from_slice(&private).map_err(|_| Reason::Key)?;
                    wrong.sign(&received)
                } else {
                    self.handle.sign(&received)
                }
            }
            SigningInput::EcdsaPrehash { hash, digest } => {
                assert_eq!(hash, Iso18013EcdsaHash::Sha256);
                assert_eq!(digest.len(), 32);
                if matches!(self.fault, Fault::DoubleHash) {
                    self.handle.sign(digest)
                } else {
                    self.handle
                        .sign_prehash(digest)
                        .map_err(|_| Reason::Backend)?
                }
            }
        };
        let der = self.encoding == SignatureEncoding::EcdsaDer;
        if der != matches!(self.fault, Fault::WrongEncoding) {
            Ok(Zeroizing::new(signature.to_der().as_bytes().to_vec()))
        } else {
            Ok(Zeroizing::new(signature.to_bytes().to_vec()))
        }
    }
}

fn signer(
    mode: SigningMode,
    encoding: SignatureEncoding,
    fault: Fault,
) -> Result<OpaqueSigner, ContainerError> {
    let case = &fixtures().cases[6];
    let mut private = [0; 32];
    private[31] = 1;
    let handle = p256::ecdsa::SigningKey::from_slice(&private).map_err(|_| Reason::Key)?;
    let key = CryptoVerificationKey::new(
        suite(case)?,
        Zeroizing::new(hex(&case.public_key)),
        [0x42; 32],
    )?;
    Ok(OpaqueSigner {
        handle,
        key,
        mode,
        encoding,
        fault,
    })
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn nonexporting_message_and_prehash_signers_independently_verify_exact_finalized_structure(
) -> Result<(), ContainerError> {
    let vectors = fixtures();
    let case = &vectors.cases[6];
    let protected = hex(&case.protected);
    let unprotected = hex(&case.unprotected);
    let payload = hex(&case.payload);
    let suites = [suite(case)?];
    for mode in [
        SigningMode::Message,
        SigningMode::EcdsaPrehash(Iso18013EcdsaHash::Sha256),
    ] {
        for encoding in [SignatureEncoding::EcdsaDer, SignatureEncoding::EcdsaFixed] {
            let signer = signer(mode, encoding, Fault::None)?;
            let signed = sign_container(
                ContainerSignRequest {
                    protected_headers: &protected,
                    unprotected_headers: &unprotected,
                    content: SigningContent::Detached(&payload),
                    external_aad: &[],
                    policy: policy(case),
                    allowed_suites: &suites,
                    limits: ContainerLimits::default(),
                },
                &signer,
            )?;
            let verified = verify_container(
                request(signed.encoded(), &payload, policy(case), &suites),
                VerificationSource::Key(&signer.key),
            )?;
            assert_eq!(verified.protected_headers(), protected);
            assert_eq!(verified.payload(), payload);
            let parsed = crate::containers::decode::decode(signed.encoded())?;
            let signature = p256::ecdsa::Signature::from_slice(parsed.signature)
                .map_err(|_| Reason::SignatureEncoding)?;
            signer
                .handle
                .verifying_key()
                .verify(&hex(&case.structure), &signature)
                .map_err(|_| Reason::Authentication)?;
            let mut changed = payload.clone();
            changed[0] ^= 1;
            assert_error(
                verify_container(
                    request(signed.encoded(), &changed, policy(case), &suites),
                    VerificationSource::Key(&signer.key),
                ),
                Reason::Authentication,
            );
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn provider_wrong_key_changed_finalized_input_double_hash_and_encoding_confusion_fail(
) -> Result<(), ContainerError> {
    let vectors = fixtures();
    let case = &vectors.cases[6];
    let protected = hex(&case.protected);
    let unprotected = hex(&case.unprotected);
    let payload = hex(&case.payload);
    let suites = [suite(case)?];
    for (mode, fault, reason) in [
        (SigningMode::Message, Fault::Provider, Reason::Provider),
        (
            SigningMode::Message,
            Fault::WrongKey,
            Reason::Authentication,
        ),
        (
            SigningMode::Message,
            Fault::AlterMessage,
            Reason::Authentication,
        ),
        (
            SigningMode::Message,
            Fault::WrongEncoding,
            Reason::SignatureEncoding,
        ),
        (
            SigningMode::EcdsaPrehash(Iso18013EcdsaHash::Sha256),
            Fault::DoubleHash,
            Reason::Authentication,
        ),
        (
            SigningMode::EcdsaPrehash(Iso18013EcdsaHash::Sha384),
            Fault::None,
            Reason::SigningInput,
        ),
    ] {
        let signer = signer(mode, SignatureEncoding::EcdsaDer, fault)?;
        assert_error(
            sign_container(
                ContainerSignRequest {
                    protected_headers: &protected,
                    unprotected_headers: &unprotected,
                    content: SigningContent::Detached(&payload),
                    external_aad: &[],
                    policy: policy(case),
                    allowed_suites: &suites,
                    limits: ContainerLimits::default(),
                },
                &signer,
            ),
            reason,
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn maximum_detached_content_and_tightened_output_limits_are_enforced() -> Result<(), ContainerError>
{
    let vectors = fixtures();
    let case = &vectors.cases[6];
    let protected = hex(&case.protected);
    let unprotected = hex(&case.unprotected);
    let suites = [suite(case)?];
    let signer = signer(
        SigningMode::EcdsaPrehash(Iso18013EcdsaHash::Sha256),
        SignatureEncoding::EcdsaFixed,
        Fault::None,
    )?;
    let payload = vec![0x42; crate::limits::MAX_DETACHED_PAYLOAD_BYTES];
    let signed = sign_container(
        ContainerSignRequest {
            protected_headers: &protected,
            unprotected_headers: &unprotected,
            content: SigningContent::Detached(&payload),
            external_aad: &[],
            policy: policy(case),
            allowed_suites: &suites,
            limits: ContainerLimits::default(),
        },
        &signer,
    )?;
    assert_eq!(
        verify_container(
            request(signed.encoded(), &payload, policy(case), &suites),
            VerificationSource::Key(&signer.key)
        )?
        .payload(),
        payload
    );
    let too_large = vec![0x42; crate::limits::MAX_DETACHED_PAYLOAD_BYTES + 1];
    assert_error(
        verify_container(
            request(signed.encoded(), &too_large, policy(case), &suites),
            VerificationSource::Key(&signer.key),
        ),
        Reason::Limit,
    );
    let limits = ContainerLimits {
        encoded_bytes: signed.encoded().len() - 1,
        ..ContainerLimits::default()
    };
    assert_error(
        sign_container(
            ContainerSignRequest {
                protected_headers: &protected,
                unprotected_headers: &unprotected,
                content: SigningContent::Detached(&payload),
                external_aad: &[],
                policy: policy(case),
                allowed_suites: &suites,
                limits,
            },
            &signer,
        ),
        Reason::Limit,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn explicit_aad_unknown_preferred_float_headers_and_tagged_generic_envelopes_authenticate_exactly(
) -> Result<(), ContainerError> {
    use crate::containers::{
        ContainerContent, ContainerPolicy, ContainerProfile, ContainerPurpose,
        ContainerVerifyRequest, EnvelopePolicy, SignatureSuite,
    };
    let vectors = fixtures();
    let case = &vectors.cases[9];
    let suite = SignatureSuite::modern(crate::CoseSignatureAlgorithm::Esp256)?;
    let mut signer = signer(
        SigningMode::Message,
        SignatureEncoding::EcdsaDer,
        Fault::None,
    )?;
    signer.key =
        CryptoVerificationKey::new(suite, Zeroizing::new(hex(&case.public_key)), [0x42; 32])?;
    let protected = hex("a21863f93e000128");
    let unprotected = hex("a0");
    let payload = b"exact detached content";
    let aad = b"exact external context";
    let suites = [suite];
    let policy = ContainerPolicy {
        profile: ContainerProfile::Rfc9360,
        purpose: ContainerPurpose::Generic,
        envelope: EnvelopePolicy::Tagged,
    };
    let signed = sign_container(
        ContainerSignRequest {
            protected_headers: &protected,
            unprotected_headers: &unprotected,
            content: SigningContent::Detached(payload),
            external_aad: aad,
            policy,
            allowed_suites: &suites,
            limits: ContainerLimits::default(),
        },
        &signer,
    )?;
    let req = |encoded, aad| ContainerVerifyRequest {
        encoded,
        content: ContainerContent::Detached(payload),
        external_aad: aad,
        policy,
        allowed_suites: &suites,
        limits: ContainerLimits::default(),
    };
    assert_eq!(
        verify_container(
            req(signed.encoded(), aad),
            VerificationSource::Key(&signer.key)
        )?
        .protected_headers(),
        protected
    );
    assert_error(
        verify_container(
            req(signed.encoded(), b"changed context"),
            VerificationSource::Key(&signer.key),
        ),
        Reason::Authentication,
    );
    let parsed = crate::containers::decode::decode(signed.encoded())?;
    let mut altered = protected.clone();
    altered[5] = 0x01;
    let mut changed = vec![0xd2];
    changed.extend_from_slice(&super::support::envelope(
        &altered,
        &unprotected,
        None,
        parsed.signature,
    ));
    assert_error(
        verify_container(req(&changed, aad), VerificationSource::Key(&signer.key)),
        Reason::Authentication,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn pure_eddsa_rejects_an_ecdsa_prehash_contract_before_calling_provider(
) -> Result<(), ContainerError> {
    use crate::containers::{
        ContainerPolicy, ContainerProfile, ContainerPurpose, EnvelopePolicy, SignatureSuite,
    };
    use crate::iso18013::{Iso18013SignatureAlgorithm as Alg, Iso18013SignatureCurve as Curve};
    let values: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/peer-keys.json"))
            .map_err(|_| Reason::Malformed)?;
    let cases = values
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or(Reason::Malformed)?;
    let case = cases
        .iter()
        .find(|case| case.get("curve").and_then(serde_json::Value::as_i64) == Some(6))
        .ok_or(Reason::Key)?;
    let public = case
        .get("public")
        .and_then(serde_json::Value::as_str)
        .ok_or(Reason::Key)?;
    let suite = SignatureSuite::iso(Alg::EdDsa, Curve::Ed25519)?;
    let mut signer = signer(
        SigningMode::EcdsaPrehash(Iso18013EcdsaHash::Sha256),
        SignatureEncoding::EdDsa,
        Fault::Provider,
    )?;
    signer.key = CryptoVerificationKey::new(suite, Zeroizing::new(hex(public)), [0; 32])?;
    let protected = hex("a10127");
    assert_error(
        sign_container(
            ContainerSignRequest {
                protected_headers: &protected,
                unprotected_headers: &[0xa0],
                content: SigningContent::Detached(b"opaque"),
                external_aad: &[],
                policy: ContainerPolicy {
                    profile: ContainerProfile::IsoEdition2Dis,
                    purpose: ContainerPurpose::ReaderAuthentication,
                    envelope: EnvelopePolicy::Untagged,
                },
                allowed_suites: &[suite],
                limits: ContainerLimits::default(),
            },
            &signer,
        ),
        Reason::SigningInput,
    );
    Ok(())
}
