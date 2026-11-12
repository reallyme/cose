// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::hex;
use crate::containers::{
    sign_container, ContainerError, ContainerErrorReason as Reason, ContainerLimits,
    ContainerPolicy, ContainerProfile, ContainerPurpose, ContainerSignRequest, ContainerSigner,
    CryptoVerificationKey, EnvelopePolicy, SignatureEncoding, SignatureSuite, SigningContent,
    SigningInput, SigningMode, VerificationKey,
};
use crate::iso18013::{Iso18013SignatureAlgorithm as Alg, Iso18013SignatureCurve as Curve};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

struct EdSigner {
    key: CryptoVerificationKey,
    handle: SecretBox<[u8; 32]>,
}
impl ContainerSigner for EdSigner {
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
        reallyme_crypto::dispatch::sign(
            crate::Algorithm::Ed25519,
            self.handle.expose_secret(),
            message,
        )
        .map(Zeroizing::new)
        .map_err(|_| Reason::Backend.into())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn opaque_pure_eddsa_signer_matches_independent_deterministic_answer() -> Result<(), ContainerError>
{
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/signature-suites.json"))
            .map_err(|_| Reason::Malformed)?;
    let cases = vectors
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or(Reason::Malformed)?;
    let vector = cases
        .iter()
        .find(|v| {
            v.get("algorithm").and_then(serde_json::Value::as_i64) == Some(-8)
                && v.get("curve").and_then(serde_json::Value::as_i64) == Some(6)
        })
        .ok_or(Reason::Key)?;
    let field = |name| {
        vector
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(hex)
            .ok_or(Reason::Malformed)
    };
    let suite = SignatureSuite::iso(Alg::EdDsa, Curve::Ed25519)?;
    let key = CryptoVerificationKey::new(suite, Zeroizing::new(field("public")?), [0; 32])?;
    let mut private = Zeroizing::new([0u8; 32]);
    for (index, byte) in private.iter_mut().enumerate() {
        *byte = u8::try_from(index).map_err(|_| Reason::Limit)?;
    }
    let signer = EdSigner {
        key,
        handle: SecretBox::new(Box::new(*private)),
    };
    let protected = field("protected")?;
    let payload = field("payload")?;
    let signed = sign_container(
        ContainerSignRequest {
            protected_headers: &protected,
            unprotected_headers: &[0xa0],
            content: SigningContent::Detached(&payload),
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
    )?;
    assert_eq!(signed.encoded(), field("encoded")?);
    assert_eq!(
        crate::containers::decode::decode(signed.encoded())?.signature,
        field("signature")?
    );
    Ok(())
}
