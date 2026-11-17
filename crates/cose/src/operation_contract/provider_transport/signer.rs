// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    key::Key,
    transport::{self, ProviderTransport},
};
use crate::api::contract::{
    self, cose_provider_call_request::Call, cose_provider_call_result::Result as Branch,
    cose_signing_input::Input,
};
use crate::containers::{
    ContainerSigner, SignatureEncoding, SigningInput, SigningMode, VerificationKey,
};
use crate::iso18013::Iso18013EcdsaHash;
use crate::{CoseError, CoseSignatureAlgorithm};
use reallyme_crypto::core::Algorithm;
use zeroize::Zeroizing;

pub(super) struct Signer<'a> {
    signer_handle: Zeroizing<u64>,
    key: Key<'a>,
    mode: SigningMode,
    encoding: SignatureEncoding,
}
impl<'a> Signer<'a> {
    pub(super) fn load(
        transport: &'a dyn ProviderTransport,
        handle: u64,
    ) -> Result<Self, CoseError> {
        let kind = contract::CoseProviderKind::Signer;
        let mut description = transport::describe(transport, handle, kind)?;
        let Some(contract::cose_provider_description::Description::Signer(value)) =
            description.description.as_mut()
        else {
            return Err(crate::error::CoseErrorReason::CommonInvalidParameter.into());
        };
        let key = Key::for_signer(
            transport,
            handle,
            value.key.take().ok_or(CoseError::InvalidKeyMaterial)?,
            value.verifier.as_option(),
        )?;
        let mode = SigningMode::try_from(&**value)?;
        if let SigningMode::EcdsaPrehash(hash) = mode {
            if key.suite.primitive_suite()?.algorithm().ecdsa_hash() != Some(hash) {
                return Err(crate::error::CoseErrorReason::ContainerSigningInput.into());
            }
        }
        let encoding = SignatureEncoding::try_from(value.signature_encoding)?;
        encoding.validate_family(key.suite.curve())?;
        Ok(Self {
            signer_handle: Zeroizing::new(handle),
            key,
            mode,
            encoding,
        })
    }
    fn produce(&self, input: SigningInput<'_>) -> Result<Zeroizing<Vec<u8>>, CoseError> {
        let input = match (self.mode, input) {
            (SigningMode::Message, SigningInput::Message(message)) => {
                Input::Message(Box::new(contract::CoseOpaqueBytes {
                    encoded: transport::bytes(message)?,
                }))
            }
            (SigningMode::EcdsaPrehash(expected), SigningInput::EcdsaPrehash { hash, digest })
                if expected == hash =>
            {
                let size = match hash {
                    Iso18013EcdsaHash::Sha256 => 32,
                    Iso18013EcdsaHash::Sha384 => 48,
                    Iso18013EcdsaHash::Sha512 => 64,
                };
                if digest.len() != size {
                    return Err(crate::error::CoseErrorReason::ContainerSigningInput.into());
                }
                Input::EcdsaPrehash(Box::new(contract::CoseEcdsaPrehash {
                    hash: contract::CoseHashAlgorithm::from(hash).into(),
                    digest: transport::bytes(digest)?,
                }))
            }
            _ => return Err(crate::error::CoseErrorReason::ContainerSigningInput.into()),
        };
        let mut result = transport::invoke(
            self.key.transport,
            *self.signer_handle,
            contract::CoseProviderKind::Signer,
            Call::Sign(Box::new(contract::CoseSigningInput { input: Some(input) })),
        )?;
        match &mut result {
            Branch::Sign(output) => {
                if output.encoded.len() > crate::limits::MAX_COSE_KEY_BYTES {
                    return Err(CoseError::ResourceLimitExceeded);
                }
                // Validation uses the declared encoding and curve, never length inference.
                crate::containers::signature_to_cose(
                    self.key.suite.curve(),
                    self.encoding,
                    &output.encoded,
                )?;
                Ok(core::mem::take(&mut output.encoded).into_zeroizing())
            }
            _ => Err(CoseError::Crypto),
        }
    }
}
impl ContainerSigner for Signer<'_> {
    fn verification_key(&self) -> &dyn VerificationKey {
        &self.key
    }
    fn input_mode(&self) -> SigningMode {
        self.mode
    }
    fn signature_encoding(&self) -> SignatureEncoding {
        self.encoding
    }
    fn sign(&self, input: SigningInput<'_>) -> Result<Zeroizing<Vec<u8>>, CoseError> {
        self.produce(input)
    }
}
// The generated description also covers post-quantum Sign1 providers. A PQ
// parameter set has no elliptic-curve identity and must leave crv unspecified.
pub(super) struct ModernSigner<'a> {
    transport: &'a dyn ProviderTransport,
    handle: zeroize::Zeroizing<u64>,
    algorithm: CoseSignatureAlgorithm,
    primitive: Algorithm,
    public: Zeroizing<Vec<u8>>,
}
impl<'a> ModernSigner<'a> {
    pub(super) fn load(
        transport: &'a dyn ProviderTransport,
        handle: u64,
    ) -> Result<Self, CoseError> {
        let mut description =
            transport::describe(transport, handle, contract::CoseProviderKind::Signer)?;
        let Some(contract::cose_provider_description::Description::Signer(value)) =
            description.description.as_mut()
        else {
            return Err(crate::error::CoseErrorReason::CommonInvalidParameter.into());
        };
        if value.verifier.as_option().is_some() {
            return Err(crate::error::CoseErrorReason::CommonInvalidParameter.into());
        }
        if value.signing_mode != contract::CoseSigningMode::Message
            || value.prehash != contract::CoseHashAlgorithm::Unspecified
        {
            return Err(crate::error::CoseErrorReason::ContainerSigningInput.into());
        }
        let mut key = value.key.take().ok_or(CoseError::InvalidKeyMaterial)?;
        if key.context_id.len() != super::super::profile_input::VERIFICATION_CONTEXT_BYTES
            || key.public_key.len() > crate::limits::MAX_COSE_KEY_BYTES
        {
            return Err(CoseError::InvalidKeyMaterial);
        }
        let suite = key.suite.as_option().ok_or(CoseError::InvalidKeyMaterial)?;
        let algorithm = CoseSignatureAlgorithm::try_from(suite.registration)?;
        let primitive = algorithm.crypto_algorithm()?;
        let (expected_curve, expected_encoding) = match primitive {
            Algorithm::P256 => (
                contract::CoseNamedCurve::P256,
                contract::CoseSignatureEncoding::EcdsaDer,
            ),
            Algorithm::P384 => (
                contract::CoseNamedCurve::P384,
                contract::CoseSignatureEncoding::EcdsaDer,
            ),
            Algorithm::P521 => (
                contract::CoseNamedCurve::P521,
                contract::CoseSignatureEncoding::EcdsaDer,
            ),
            Algorithm::Secp256k1 => (
                contract::CoseNamedCurve::Secp256k1,
                contract::CoseSignatureEncoding::EcdsaDer,
            ),
            Algorithm::Ed25519 => (
                contract::CoseNamedCurve::Ed25519,
                contract::CoseSignatureEncoding::Eddsa,
            ),
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => (
                contract::CoseNamedCurve::Unspecified,
                contract::CoseSignatureEncoding::CoseNative,
            ),
            _ => return Err(CoseError::UnsupportedAlgorithm),
        };
        if suite.curve != expected_curve || value.signature_encoding != expected_encoding {
            return Err(CoseError::InvalidSignatureEncoding);
        }
        crate::key::validate_public_key(primitive, &key.public_key)?;
        Ok(Self {
            transport,
            handle: zeroize::Zeroizing::new(handle),
            algorithm,
            primitive,
            public: core::mem::take(&mut key.public_key).into_zeroizing(),
        })
    }
}
impl crate::sign1::CoseSigner for ModernSigner<'_> {
    fn algorithm(&self) -> Algorithm {
        self.primitive
    }
    fn cose_algorithm(&self) -> Result<CoseSignatureAlgorithm, CoseError> {
        Ok(self.algorithm)
    }
    fn sign(&self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseError> {
        let input = Input::Message(Box::new(contract::CoseOpaqueBytes {
            encoded: transport::bytes(message)?,
        }));
        match &mut transport::invoke(
            self.transport,
            *self.handle,
            contract::CoseProviderKind::Signer,
            Call::Sign(Box::new(contract::CoseSigningInput { input: Some(input) })),
        )? {
            Branch::Sign(value) => {
                let signature = core::mem::take(&mut value.encoded).into_zeroizing();
                if signature.len() > crate::limits::MAX_COSE_KEY_BYTES {
                    return Err(CoseError::ResourceLimitExceeded);
                }
                // The compatibility signer has historically returned DER for EC.
                reallyme_crypto::dispatch::verify(
                    self.primitive,
                    &self.public,
                    message,
                    &signature,
                )
                .map_err(crate::error::signature_error_from_algorithm_error)?;
                Ok(signature)
            }
            _ => Err(CoseError::Crypto),
        }
    }
}
