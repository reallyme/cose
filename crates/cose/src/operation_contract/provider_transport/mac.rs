// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::transport::{self, ProviderTransport};
use crate::api::contract::{
    self, cose_provider_call_request::Call, cose_provider_call_result::Result as Branch,
};
use crate::mac0::{CoseMacAlgorithm, CoseMacVerifier};
use crate::CoseError;

pub(super) struct Mac<'a> {
    transport: &'a dyn ProviderTransport,
    handle: zeroize::Zeroizing<u64>,
    algorithm: CoseMacAlgorithm,
}
impl<'a> Mac<'a> {
    pub(super) fn load(
        transport: &'a dyn ProviderTransport,
        handle: u64,
    ) -> Result<Self, CoseError> {
        let mut value =
            transport::describe(transport, handle, contract::CoseProviderKind::MacVerifier)?;
        let Some(contract::cose_provider_description::Description::MacAlgorithm(algorithm)) =
            value.description.take()
        else {
            return Err(crate::error::CoseErrorReason::CommonInvalidParameter.into());
        };
        Ok(Self {
            transport,
            handle: zeroize::Zeroizing::new(handle),
            algorithm: CoseMacAlgorithm::try_from(algorithm)?,
        })
    }
}
impl CoseMacVerifier for Mac<'_> {
    fn algorithm(&self) -> CoseMacAlgorithm {
        self.algorithm
    }
    fn verify(&self, message: &[u8], tag: &[u8]) -> Result<(), CoseError> {
        let mut request = contract::CoseProviderMacRequest::default();
        request.algorithm = contract::CoseMacAlgorithm::from(self.algorithm).into();
        request.message = transport::bytes(message)?;
        request.tag = transport::bytes(tag)?;
        match &mut transport::invoke(
            self.transport,
            *self.handle,
            contract::CoseProviderKind::MacVerifier,
            Call::VerifyMac(Box::new(request)),
        )? {
            Branch::VerifyMac(_) => Ok(()),
            _ => Err(CoseError::Crypto),
        }
    }
}
