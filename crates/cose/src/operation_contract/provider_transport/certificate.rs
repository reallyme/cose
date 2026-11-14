// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    key::Key,
    transport::{self, ProviderTransport},
};
use crate::api::contract::{
    self, cose_provider_call_request::Call, cose_provider_call_result::Result as Branch,
};
use crate::containers::{CertificateHeaders, CertificateSelection, CertificateValidator};
use crate::{CoseError, CoseSignatureAlgorithm};
use buffa::MessageField;
use std::cell::OnceCell;
use zeroize::Zeroizing;

struct Selected<'a> {
    key: Key<'a>,
    der: Zeroizing<Vec<u8>>,
}
pub(super) struct Certificate<'a> {
    transport: &'a dyn ProviderTransport,
    handle: zeroize::Zeroizing<u64>,
    selected: OnceCell<Selected<'a>>,
}
impl<'a> Certificate<'a> {
    pub(super) fn new(transport: &'a dyn ProviderTransport, handle: u64) -> Self {
        Self {
            transport,
            handle: zeroize::Zeroizing::new(handle),
            selected: OnceCell::new(),
        }
    }
}
impl CertificateValidator for Certificate<'_> {
    fn resolve(
        &self,
        headers: &CertificateHeaders<'_>,
        algorithm: i64,
    ) -> Result<CertificateSelection<'_>, CoseError> {
        // A session executes one operation; retaining one selected owner makes
        // borrowed trust-boundary lifetimes explicit without cloning DER trees.
        if self.selected.get().is_some() {
            return Err(CoseError::Crypto);
        }
        let mut certificates = Zeroizing::new(Vec::new());
        certificates
            .try_reserve_exact(headers.certificates().len())
            .map_err(|_| CoseError::ResourceLimitExceeded)?;
        for certificate in headers.certificates() {
            certificates.push(transport::bytes(certificate)?);
        }
        let request = contract::CoseProviderCertificateRequest {
            algorithm: contract::CoseSignatureAlgorithm::from(
                CoseSignatureAlgorithm::from_identifier(algorithm)?,
            )
            .into(),
            chain: MessageField::some(contract::CoseX5Chain {
                certificates_der: core::mem::take(&mut *certificates).into(),
            }),
            placement: headers
                .placement()
                .map(contract::CoseX5ChainHeaderPlacement::from)
                .unwrap_or_default()
                .into(),
            sha256_thumbprint: transport::bytes(
                headers
                    .sha256_thumbprint()
                    .map_or(&[][..], |digest| &digest[..]),
            )?,
        };
        let kind = contract::CoseProviderKind::CertificateValidator;
        let mut result = transport::invoke(
            self.transport,
            *self.handle,
            kind,
            Call::ResolveCertificate(Box::new(request)),
        )?;
        let Branch::ResolveCertificate(value) = &mut result else {
            return Err(CoseError::Crypto);
        };
        if value.end_entity_der.is_empty()
            || value.end_entity_der.len() > crate::limits::MAX_COSE_X5CHAIN_CERTIFICATE_BYTES
        {
            return Err(CoseError::InvalidKeyMaterial);
        }
        let key = Key::from_message(
            self.transport,
            *self.handle,
            kind,
            value.key.take().ok_or(CoseError::InvalidKeyMaterial)?,
        )?;
        let selected = Selected {
            key,
            der: core::mem::take(&mut value.end_entity_der).into_zeroizing(),
        };
        self.selected.set(selected).map_err(|_| CoseError::Crypto)?;
        let selected = self.selected.get().ok_or(CoseError::Crypto)?;
        Ok(CertificateSelection {
            key: &selected.key,
            end_entity_der: &selected.der,
        })
    }
}
