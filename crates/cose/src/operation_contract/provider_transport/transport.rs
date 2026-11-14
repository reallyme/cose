// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::super::profile_input::copy;
use crate::api::contract::{
    self, cose_provider_call_request::Call, cose_provider_call_response::Outcome,
    cose_provider_call_result::Result as Branch,
};
use crate::{error::CoseErrorReason as Reason, CoseError};
use buffa::MessageField;
use std::cell::OnceCell;

/// Process-local transport for the complete generated provider callback contract.
/// Implementations may dispatch the same messages across a language boundary.
/// Responses are untrusted and validated before use; no secret-key export exists.
pub trait ProviderTransport {
    /// Explicit capabilities authorized in this caller context.
    fn registry(&self) -> &contract::CoseProviderRegistry;
    /// Execute exactly one capability-scoped generated callback.
    /// Serialized implementations must bound and validate the original reply
    /// with `DecodeOptions::reject_unknown_fields()` before returning it here.
    /// Unknown storage is disabled: a default decoder can discard evidence
    /// that no later check of this typed value could recover.
    fn call(
        &self,
        request: contract::CoseProviderCallRequest,
    ) -> contract::CoseProviderCallResponse;
}

pub(super) fn initialize<T>(
    cell: &OnceCell<T>,
    build: impl FnOnce() -> Result<T, CoseError>,
) -> Result<&T, CoseError> {
    if cell.get().is_none() {
        cell.set(build()?).map_err(|_| CoseError::Crypto)?;
    }
    cell.get().ok_or(CoseError::Crypto)
}

pub(super) fn invoke(
    transport: &dyn ProviderTransport,
    handle: u64,
    kind: contract::CoseProviderKind,
    call: Call,
) -> Result<Branch, CoseError> {
    const MAX_PROVIDER_CAPABILITIES: usize = 32;
    let registry = transport.registry();
    if registry.capabilities.len() > MAX_PROVIDER_CAPABILITIES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    for (index, capability) in registry.capabilities.iter().enumerate() {
        if capability.handle == 0
            || capability.kind.as_known().is_none()
            || capability.kind == contract::CoseProviderKind::Unspecified
            || registry.capabilities[..index]
                .iter()
                .any(|prior| prior.handle == capability.handle && prior.kind == capability.kind)
        {
            return Err(Reason::CommonInvalidParameter.into());
        }
    }
    if !registry
        .capabilities
        .iter()
        .any(|capability| capability.handle == handle && capability.kind == kind)
    {
        return Err(CoseError::ProviderUnavailable);
    }
    if handle == 0 {
        return Err(CoseError::ProviderUnavailable);
    }
    let expected = match &call {
        Call::Describe(_) => 100,
        Call::Sign(_) => 101,
        Call::Verify(_) => 102,
        Call::ResolveKey(_) => 103,
        Call::ResolveCertificate(_) => 104,
        Call::ValidatePeer(_) => 105,
        Call::NormalizeAgreement(_) => 106,
        Call::VerifyMac(_) => 107,
    };
    let request = contract::CoseProviderCallRequest {
        capability: MessageField::some(contract::CoseProviderCapability {
            handle,
            kind: kind.into(),
        }),
        call: Some(call),
    };
    let mut response = transport.call(request);
    let result = match response.outcome.as_mut() {
        Some(Outcome::Result(result)) => result.result.take().ok_or(CoseError::Crypto)?,
        Some(Outcome::Error(error)) => {
            crate::wire::validate_cose_error_proto_wire(error).map_err(|_| CoseError::Crypto)?;
            let reason = match error.error.as_ref() {
                Some(contract::cose_error::Error::Primitive(e)) => e.reason,
                Some(contract::cose_error::Error::Provider(e)) => e.reason,
                Some(contract::cose_error::Error::Backend(e)) => e.reason,
                None => return Err(CoseError::Crypto),
            };
            return Err(reason.as_known().ok_or(CoseError::Crypto)?.into());
        }
        None => return Err(CoseError::Crypto),
    };
    let actual = match &result {
        Branch::Describe(_) => 100,
        Branch::Sign(_) => 101,
        Branch::Verify(_) => 102,
        Branch::ResolveKey(_) => 103,
        Branch::ResolveCertificate(_) => 104,
        Branch::ValidatePeer(_) => 105,
        Branch::NormalizeAgreement(_) => 106,
        Branch::VerifyMac(_) => 107,
    };
    if actual != expected {
        return Err(Reason::BackendInternal.into());
    }
    Ok(result)
}

pub(super) fn bytes(value: &[u8]) -> Result<reallyme_cose_proto::SecretBytes, CoseError> {
    let mut owned = copy(value)?;
    Ok(core::mem::take(&mut *owned).into())
}

pub(super) fn describe(
    transport: &dyn ProviderTransport,
    handle: u64,
    kind: contract::CoseProviderKind,
) -> Result<contract::CoseProviderDescription, CoseError> {
    match &mut invoke(transport, handle, kind, Call::Describe(Box::default()))? {
        Branch::Describe(value) => Ok(core::mem::take(&mut **value)),
        _ => Err(CoseError::Crypto),
    }
}
