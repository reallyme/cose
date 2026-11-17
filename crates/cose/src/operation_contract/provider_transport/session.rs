// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::super::providers::OperationProviders;
use super::{
    certificate::Certificate,
    key::Key,
    mac::Mac,
    point::Point,
    signer::{ModernSigner, Signer},
    transport::{self, ProviderTransport},
};
use crate::api::contract::{
    self, cose_provider_call_request::Call, cose_provider_call_result::Result as Branch,
};
use crate::containers::{
    AgreementKeyProvider, CertificateValidator, ContainerSigner, PeerKeyValidator, VerificationKey,
};
use crate::iso18013::Iso18013Verifier;
use crate::mac0::CoseMacVerifier;
use crate::{sign1::CoseSigner, CoseError};
use std::cell::{Cell, OnceCell};
use zeroize::Zeroizing;

pub(crate) struct Session<'a> {
    transport: &'a dyn ProviderTransport,
    failure: Cell<Option<CoseError>>,
    key: OnceCell<Key<'a>>,
    certificate: OnceCell<Certificate<'a>>,
    signer: OnceCell<Signer<'a>>,
    modern: OnceCell<ModernSigner<'a>>,
    mac: OnceCell<Mac<'a>>,
    point: OnceCell<Point<'a>>,
}
impl<'a> Session<'a> {
    pub(crate) fn new(transport: &'a dyn ProviderTransport) -> Self {
        Self {
            transport,
            failure: Cell::new(None),
            key: OnceCell::new(),
            certificate: OnceCell::new(),
            signer: OnceCell::new(),
            modern: OnceCell::new(),
            mac: OnceCell::new(),
            point: OnceCell::new(),
        }
    }
    pub(crate) fn take_failure(&self) -> Option<CoseError> {
        self.failure.take()
    }
    fn retain<T>(&self, result: Result<T, CoseError>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.failure.set(Some(error));
                None
            }
        }
    }
    fn point(&self, handle: u64) -> Result<&Point<'a>, CoseError> {
        if handle == 0 {
            return Err(CoseError::ProviderUnavailable);
        }
        transport::initialize(&self.point, || {
            Ok(Point {
                transport: self.transport,
                handle: Zeroizing::new(handle),
            })
        })
    }
}
impl OperationProviders for Session<'_> {
    fn resolve_sign1_key(
        &self,
        handle: u64,
        algorithm: contract::CoseSignatureAlgorithm,
        kid: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        // The borrowed legacy callback uses Option. The authoritative provider
        // contract retains fixed failures; this compatibility route maps a
        // failed lookup to the historical unresolved-key outcome.
        let request = contract::CoseProviderResolveKeyRequest {
            algorithm: algorithm.into(),
            kid: self.retain(transport::bytes(kid))?,
        };
        match &mut self.retain(transport::invoke(
            self.transport,
            handle,
            contract::CoseProviderKind::KeyResolver,
            Call::ResolveKey(Box::new(request)),
        ))? {
            Branch::ResolveKey(value)
                if value.encoded.len() <= crate::limits::MAX_COSE_KEY_BYTES =>
            {
                Some(core::mem::take(&mut value.encoded).into_zeroizing())
            }
            _ => {
                self.failure.set(Some(CoseError::InvalidKeyMaterial));
                None
            }
        }
    }
    fn resolve_x5chain_key(
        &self,
        handle: u64,
        algorithm: contract::CoseSignatureAlgorithm,
        placement: contract::CoseX5ChainHeaderPlacement,
        certificates: &[Vec<u8>],
    ) -> Result<contract::CoseProviderCertificateResult, CoseError> {
        let mut chain = Zeroizing::new(Vec::new());
        chain
            .try_reserve_exact(certificates.len())
            .map_err(|_| CoseError::ResourceLimitExceeded)?;
        for certificate in certificates {
            chain.push(transport::bytes(certificate)?);
        }
        let request = contract::CoseProviderCertificateRequest {
            algorithm: algorithm.into(),
            placement: placement.into(),
            sha256_thumbprint: Default::default(),
            chain: buffa::MessageField::some(contract::CoseX5Chain {
                certificates_der: core::mem::take(&mut *chain).into(),
            }),
        };
        match &mut transport::invoke(
            self.transport,
            handle,
            contract::CoseProviderKind::KeyResolver,
            Call::ResolveCertificate(Box::new(request)),
        )? {
            // Keep the complete generated owner. The shared Sign1 semantic
            // boundary checks leaf DER and suite before exposing key bytes.
            Branch::ResolveCertificate(value) => Ok(core::mem::take(&mut **value)),
            _ => Err(CoseError::InvalidKeyMaterial),
        }
    }
    fn iso_verifier(&self, handle: u64) -> Result<&dyn Iso18013Verifier, CoseError> {
        Ok(transport::initialize(&self.key, || {
            Key::load(
                self.transport,
                handle,
                contract::CoseProviderKind::VerificationKey,
            )
        })?)
    }
    fn verification_key(&self, handle: u64) -> Result<&dyn VerificationKey, CoseError> {
        Ok(transport::initialize(&self.key, || {
            Key::load(
                self.transport,
                handle,
                contract::CoseProviderKind::VerificationKey,
            )
        })?)
    }
    fn certificate_validator(&self, handle: u64) -> Result<&dyn CertificateValidator, CoseError> {
        if handle == 0 {
            return Err(CoseError::ProviderUnavailable);
        }
        Ok(transport::initialize(&self.certificate, || {
            Ok(Certificate::new(self.transport, handle))
        })?)
    }
    fn container_signer(&self, handle: u64) -> Result<&dyn ContainerSigner, CoseError> {
        Ok(transport::initialize(&self.signer, || {
            Signer::load(self.transport, handle)
        })?)
    }
    fn cose_signer(&self, handle: u64) -> Result<&dyn CoseSigner, CoseError> {
        Ok(transport::initialize(&self.modern, || {
            ModernSigner::load(self.transport, handle)
        })?)
    }
    fn mac_verifier(&self, handle: u64) -> Result<&dyn CoseMacVerifier, CoseError> {
        Ok(transport::initialize(&self.mac, || {
            Mac::load(self.transport, handle)
        })?)
    }
    fn peer_key_validator(&self, handle: u64) -> Result<&dyn PeerKeyValidator, CoseError> {
        Ok(self.point(handle)?)
    }
    fn agreement_key_provider(&self, handle: u64) -> Result<&dyn AgreementKeyProvider, CoseError> {
        Ok(self.point(handle)?)
    }
}
