// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::transport::{self, ProviderTransport};
use crate::api::contract::{
    self, cose_provider_call_request::Call, cose_provider_call_result::Result as Branch,
};
use crate::containers::{SignatureSuite, VerificationKey};
use crate::iso18013::{Iso18013SignatureSuite, Iso18013Verifier};
use crate::CoseError;
use zeroize::{ZeroizeOnDrop, Zeroizing};

pub(super) struct Key<'a> {
    pub(super) transport: &'a dyn ProviderTransport,
    pub(super) handle: zeroize::Zeroizing<u64>,
    pub(super) kind: contract::CoseProviderKind,
    pub(super) suite: SignatureSuite,
    public: Zeroizing<Vec<u8>>,
    context: Zeroizing<[u8; 32]>,
    builtin: Option<crate::containers::CryptoVerificationKey>,
}
impl<'a> Key<'a> {
    pub(super) fn from_message(
        transport: &'a dyn ProviderTransport,
        handle: u64,
        kind: contract::CoseProviderKind,
        mut value: contract::CoseWorkingKey,
    ) -> Result<Self, CoseError> {
        if value.public_key.len() > crate::limits::MAX_COSE_KEY_BYTES {
            return Err(CoseError::ResourceLimitExceeded);
        }
        if !super::super::profile_response::working_key(&value) {
            return Err(CoseError::InvalidKeyMaterial);
        }
        let suite = super::super::profile_input::suite(
            value
                .suite
                .as_option()
                .ok_or(CoseError::InvalidKeyMaterial)?,
        )?;
        let context = <&[u8; 32]>::try_from(value.context_id.as_slice())
            .map_err(|_| CoseError::InvalidKeyMaterial)?;
        Ok(Self {
            transport,
            handle: zeroize::Zeroizing::new(handle),
            kind,
            suite,
            context: Zeroizing::new(*context),
            builtin: None,
            public: core::mem::take(&mut value.public_key).into_zeroizing(),
        })
    }
    pub(super) fn load(
        transport: &'a dyn ProviderTransport,
        handle: u64,
        kind: contract::CoseProviderKind,
    ) -> Result<Self, CoseError> {
        let mut description = transport::describe(transport, handle, kind)?;
        let Some(contract::cose_provider_description::Description::VerificationKey(value)) =
            description.description.as_mut()
        else {
            return Err(crate::error::CoseErrorReason::CommonInvalidParameter.into());
        };
        Self::from_message(transport, handle, kind, core::mem::take(&mut **value))
    }
    pub(super) fn for_signer(
        transport: &'a dyn ProviderTransport,
        handle: u64,
        value: contract::CoseWorkingKey,
        verifier: Option<&contract::CoseProviderCapability>,
    ) -> Result<Self, CoseError> {
        let mut signing =
            Self::from_message(transport, handle, contract::CoseProviderKind::Signer, value)?;
        if let Some(verifier) = verifier {
            if verifier.handle == 0 || verifier.kind != contract::CoseProviderKind::VerificationKey
            {
                return Err(crate::error::CoseErrorReason::CommonInvalidParameter.into());
            }
            let selected = Self::load(
                transport,
                verifier.handle,
                contract::CoseProviderKind::VerificationKey,
            )?;
            if selected.suite != signing.suite
                || !reallyme_crypto::operations::constant_time::equal(
                    &selected.public,
                    &signing.public,
                )
                || !reallyme_crypto::operations::constant_time::equal(
                    &*selected.context,
                    &*signing.context,
                )
            {
                return Err(crate::error::CoseErrorReason::KeyAlgorithmMismatch.into());
            }
            Ok(selected)
        } else {
            signing.builtin = Some(crate::containers::CryptoVerificationKey::new(
                signing.suite,
                super::super::profile_input::copy(&signing.public)?,
                *signing.context,
            )?);
            Ok(signing)
        }
    }
    fn authenticate(&self, message: &[u8], signature: &[u8]) -> Result<(), CoseError> {
        crate::containers::validate_cose_signature(self.suite.curve(), signature)?;
        if let Some(builtin) = &self.builtin {
            return builtin.verify(message, signature);
        }
        let mut key = contract::CoseWorkingKey::default();
        key.suite =
            buffa::MessageField::some(super::super::profile_input::suite_message(self.suite)?);
        key.public_key = transport::bytes(&self.public)?;
        key.context_id = transport::bytes(&*self.context)?;
        let mut request = contract::CoseProviderVerifyRequest::default();
        request.key = buffa::MessageField::some(key);
        request.message = transport::bytes(message)?;
        request.signature = transport::bytes(signature)?;
        let result = transport::invoke(
            self.transport,
            *self.handle,
            self.kind,
            Call::Verify(Box::new(request)),
        )?;
        match result {
            Branch::Verify(_) => Ok(()),
            _ => Err(CoseError::Crypto),
        }
    }
}
impl VerificationKey for Key<'_> {
    fn suite(&self) -> SignatureSuite {
        self.suite
    }
    fn public_key(&self) -> &[u8] {
        &self.public
    }
    fn context_id(&self) -> &[u8; 32] {
        &self.context
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CoseError> {
        self.authenticate(message, signature)
    }
}
impl Iso18013Verifier for Key<'_> {
    fn suite(&self) -> Iso18013SignatureSuite {
        self.suite
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CoseError> {
        self.authenticate(message, signature)
    }
}
impl ZeroizeOnDrop for Key<'_> {}
