// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::transport::{self, ProviderTransport};
use crate::api::contract::{
    self, cose_provider_call_request::Call, cose_provider_call_result::Result as Branch,
};
use crate::containers::{AgreementKeyProvider, PeerCurve, PeerKeyUsage, PeerKeyValidator};
use crate::CoseError;
use zeroize::Zeroizing;

pub(super) struct Point<'a> {
    pub(super) transport: &'a dyn ProviderTransport,
    pub(super) handle: zeroize::Zeroizing<u64>,
}
impl PeerKeyValidator for Point<'_> {
    fn validate(
        &self,
        curve: PeerCurve,
        usage: PeerKeyUsage,
        public_material: &[u8],
    ) -> Result<(), CoseError> {
        let purpose = match usage {
            PeerKeyUsage::Signature(_) => contract::CosePeerKeyPurpose::Signature,
            PeerKeyUsage::Agreement => contract::CosePeerKeyPurpose::Agreement,
            PeerKeyUsage::HpkeRecipient => contract::CosePeerKeyPurpose::HpkeRecipient,
        };
        let request = contract::CoseProviderPointRequest {
            signature_suite: match usage {
                PeerKeyUsage::Signature(suite) => {
                    buffa::MessageField::some(super::super::profile_input::suite_message(suite)?)
                }
                _ => buffa::MessageField::none(),
            },
            curve: contract::CoseNamedCurve::from(curve).into(),
            purpose: purpose.into(),
            public_key: transport::bytes(public_material)?,
        };
        match &mut transport::invoke(
            self.transport,
            *self.handle,
            contract::CoseProviderKind::PeerKeyValidator,
            Call::ValidatePeer(Box::new(request)),
        )? {
            Branch::ValidatePeer(_) => Ok(()),
            _ => Err(CoseError::Crypto),
        }
    }
}
impl AgreementKeyProvider for Point<'_> {
    fn normalize_public_key(
        &self,
        curve: PeerCurve,
        public_material: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoseError> {
        let request = contract::CoseProviderPointRequest {
            signature_suite: buffa::MessageField::none(),
            curve: contract::CoseNamedCurve::from(curve).into(),
            purpose: contract::CosePeerKeyPurpose::Agreement.into(),
            public_key: transport::bytes(public_material)?,
        };
        match &mut transport::invoke(
            self.transport,
            *self.handle,
            contract::CoseProviderKind::AgreementKeyNormalizer,
            Call::NormalizeAgreement(Box::new(request)),
        )? {
            Branch::NormalizeAgreement(value) => {
                if value.encoded.len() > crate::limits::MAX_COSE_KEY_BYTES {
                    return Err(CoseError::ResourceLimitExceeded);
                }
                Ok(core::mem::take(&mut value.encoded).into_zeroizing())
            }
            _ => Err(CoseError::Crypto),
        }
    }
}
