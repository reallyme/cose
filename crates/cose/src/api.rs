// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authoritative Buffa-generated COSE operation contract and typed execution.
//!
//! Requests, results, policy selectors and failure codes come from protobuf.
//! Borrowed Rust entrypoints are compatibility adapters to the same semantics.

pub use crate::operation_contract::providers::{BuiltinProviders, OperationProviders};
/// Schema-generated request/result types and operation discriminants.
pub use reallyme_cose_proto::generated::proto::reallyme::cose::v1 as contract;

/// Execute a generated request with only the built-in crypto capabilities.
/// Failures are returned through the generated error outcome without diagnostics.
#[must_use]
pub fn execute(request: contract::CoseOperationRequest) -> contract::CoseOperationResponseV2 {
    execute_with_providers(request, &BuiltinProviders)
}

/// Execute a generated request with explicitly injected non-exporting capabilities.
/// Handles are application-local; COSE never allocates a global handle registry.
#[must_use]
pub fn execute_with_providers(
    request: contract::CoseOperationRequest,
    providers: &dyn OperationProviders,
) -> contract::CoseOperationResponseV2 {
    crate::operation_contract::execute::execute_typed(request, providers)
}

/// Execute bounded protobuf bytes with caller-owned capabilities.
#[must_use]
pub fn execute_protobuf_with_providers(
    bytes: &[u8],
    providers: &dyn OperationProviders,
) -> zeroize::Zeroizing<Vec<u8>> {
    crate::operation_contract::execute::execute_proto_with_providers(bytes, providers)
}

/// Execute strict generated ProtoJSON with caller-owned capabilities.
#[must_use]
pub fn execute_json_with_providers(
    json: &str,
    providers: &dyn OperationProviders,
) -> zeroize::Zeroizing<Vec<u8>> {
    crate::operation_contract::execute::execute_json_with_providers(json, providers)
}

/// Schema-defined callback transport for provider implementations in any language.
pub use crate::operation_contract::provider_transport::ProviderTransport;

/// Execute with generated provider callbacks scoped to this one operation.
#[must_use]
pub fn execute_with_provider_transport(
    request: contract::CoseOperationRequest,
    transport: &dyn ProviderTransport,
) -> contract::CoseOperationResponseV2 {
    let session = crate::operation_contract::provider_transport::Session::new(transport);
    let response = execute_with_providers(request, &session);
    match session.take_failure() {
        Some(error) => crate::operation_contract::response_v2::from_error(
            crate::wire::CoseWireError::from_reason(error.reason()),
        ),
        None => response,
    }
}
