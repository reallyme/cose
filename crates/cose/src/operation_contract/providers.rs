// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local capability ports behind schema-defined handles; no serialized secrets.

use crate::containers::{
    AgreementKeyProvider, CertificateValidator, ContainerError, ContainerErrorReason,
    ContainerSigner, PeerKeyValidator, VerificationKey,
};
use crate::iso18013::Iso18013Verifier;
use crate::mac0::CoseMacKey;
use crate::sign1::CoseSigner;
use crate::wire::CoseSignatureRegistration;
use zeroize::Zeroizing;

/// Injected application capabilities for generated operations.
///
/// Each nonzero handle must resolve only within the caller's authorization
/// context. Implementations must keep returned capabilities stable for a call.
/// No default method exports key material or silently selects another provider.
pub trait OperationProviders {
    /// Resolve a modern verification key for an exact protected registration/kid.
    /// Returning none preserves the borrowed callback's key-not-resolved failure.
    fn resolve_sign1_key(
        &self,
        _handle: u64,
        _algorithm: CoseSignatureRegistration,
        _kid: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
    /// Resolve an exact-registration verification key through an external
    /// certificate callback. Discovery certificates are untrusted input.
    fn resolve_x5chain_key(
        &self,
        _handle: u64,
        _algorithm: CoseSignatureRegistration,
        _certificates: &[Vec<u8>],
    ) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
    /// Resolve a protected MAC key.
    /// # Errors
    /// Returns a fixed provider/key failure, never the handle or backend text.
    fn mac_key(&self, _handle: u64) -> Result<&CoseMacKey, ContainerError> {
        Err(ContainerErrorReason::Provider.into())
    }
    /// Resolve the schema-defined non-exporting MAC verification port.
    ///
    /// # Errors
    /// Returns a fixed failure if the capability is unavailable or invalid.
    fn mac_verifier(
        &self,
        handle: u64,
    ) -> Result<&dyn crate::mac0::CoseMacVerifier, ContainerError> {
        Ok(self.mac_key(handle)?)
    }
    /// Resolve an exact-suite ISO verifier.
    /// # Errors
    /// Returns a fixed provider/key failure.
    fn iso_verifier(&self, _handle: u64) -> Result<&dyn Iso18013Verifier, ContainerError> {
        Err(ContainerErrorReason::Provider.into())
    }
    /// Resolve a validated working-key capability.
    /// # Errors
    /// Returns a fixed provider/key failure.
    fn verification_key(&self, _handle: u64) -> Result<&dyn VerificationKey, ContainerError> {
        Err(ContainerErrorReason::Provider.into())
    }
    /// Resolve a caller-owned certificate trust-policy capability.
    /// # Errors
    /// Returns a fixed provider/certificate failure.
    fn certificate_validator(
        &self,
        _handle: u64,
    ) -> Result<&dyn CertificateValidator, ContainerError> {
        Err(ContainerErrorReason::Provider.into())
    }
    /// Resolve a non-exporting container signer with bound key/mode/encoding.
    /// # Errors
    /// Returns a fixed provider/key failure.
    fn container_signer(&self, _handle: u64) -> Result<&dyn ContainerSigner, ContainerError> {
        Err(ContainerErrorReason::Provider.into())
    }
    /// Resolve a non-exporting modern Sign1 signer.
    /// # Errors
    /// Returns a fixed provider/key failure.
    fn cose_signer(&self, _handle: u64) -> Result<&dyn CoseSigner, ContainerError> {
        Err(ContainerErrorReason::Provider.into())
    }
    /// Resolve a named-point validation capability.
    /// # Errors
    /// Returns a fixed provider/key failure.
    fn peer_key_validator(&self, _handle: u64) -> Result<&dyn PeerKeyValidator, ContainerError> {
        Err(ContainerErrorReason::Provider.into())
    }
    /// Resolve a crypto-owned agreement validation/normalization capability.
    /// # Errors
    /// Returns a fixed provider/key failure.
    fn agreement_key_provider(
        &self,
        _handle: u64,
    ) -> Result<&dyn AgreementKeyProvider, ContainerError> {
        Err(ContainerErrorReason::Provider.into())
    }
}

/// No application-local handles are enabled by this built-in-only context.
pub struct BuiltinProviders;
impl OperationProviders for BuiltinProviders {}

/// Validate one generated, kind-bound capability before invoking any provider.
pub(crate) fn capability_handle(
    value: Option<&crate::api::contract::CoseProviderCapability>,
    expected: crate::api::contract::CoseProviderKind,
) -> crate::wire::CoseWireResult<u64> {
    match value {
        None => Ok(0),
        Some(value) if value.handle != 0 && value.kind == expected => Ok(value.handle),
        _ => Err(crate::wire::CoseWireError::primitive_internal(
            crate::wire::CoseErrorReason::CommonInvalidParameter,
        )),
    }
}
