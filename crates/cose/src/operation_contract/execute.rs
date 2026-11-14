// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Executable binary protobuf and generated ProtoJSON operation boundary.

use super::providers::{BuiltinProviders, OperationProviders};
use buffa::Message;
use zeroize::Zeroizing;

use crate::wire::{
    cose_operation_request, decode_json, decode_protobuf, CoseErrorReason, CoseOperationRequest,
    CoseOperationResult, CoseWireError, CoseWireResult,
};

pub(crate) fn execute_proto(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let response = super::response_v2::from_result(
        decode_protobuf(request_bytes)
            .and_then(|request| dispatch_operation(request, &BuiltinProviders)),
    );
    super::response_v2::encode_or_error(&response)
}

pub(crate) fn execute_proto_json(request_json: &str) -> Zeroizing<Vec<u8>> {
    let response = super::response_v2::from_result(
        decode_json(request_json.as_bytes())
            .and_then(|request| dispatch_operation(request, &BuiltinProviders)),
    );
    super::response_v2::encode_or_error(&response)
}

fn dispatch_operation(
    mut request: CoseOperationRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    // Transfer the selected request while keeping the cleanup owner live.
    // Unknown fields are rejected at wire admission and have no typed storage.
    let Some(mut operation) = request.operation.take() else {
        return Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        ));
    };

    match &mut operation {
        cose_operation_request::Operation::Sign1CreateProfile(request) => {
            super::sign1::profile::create(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::Sign1CreateDetachedProfile(request) => {
            super::sign1::profile::create_detached(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::Sign1VerifyProfile(request) => {
            super::sign1::profile::verify(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::Sign1VerifyX5chain(request) => {
            super::sign1::profile::x5chain(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::AgreementKeyCreate(request) => {
            super::agreement::create(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::AgreementKeyParse(request) => {
            super::agreement::parse(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::Mac0VerifyDetached(request) => {
            super::mac0::verify(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::IsoSign1Verify(request) => {
            super::iso_verify::verify(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::ContainerVerify(request) => {
            super::container_verify::verify(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::ContainerSign(request) => {
            super::container_sign::sign(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::PeerKeyInspect(request) => {
            super::peer_key::inspect(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::PeerKeyValidate(request) => {
            super::peer_key::validate(core::mem::take(&mut **request), providers)
        }
        cose_operation_request::Operation::SignatureToCose(request) => {
            super::signature::to_cose(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::SignatureToDer(request) => {
            super::signature::to_der(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::SignatureValidate(request) => {
            super::signature::validate(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::SignatureSuiteInfo(request) => {
            super::suite::info(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::VerificationKeyImport(request) => {
            super::suite::import(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::ContractInfo(_) => super::suite::contract_info(),
        cose_operation_request::Operation::PreferredCborValidate(request) => {
            super::signature::preferred_cbor(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::Sign1Create(request) => {
            super::sign1::create::attached_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::Sign1CreateDetached(request) => {
            super::sign1::create::detached_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::Sign1Verify(request) => {
            super::sign1::verify::attached_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::Sign1VerifyDetached(request) => {
            super::sign1::verify::detached_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::KeyFromPublicBytes(request) => {
            super::key::convert::from_public_bytes_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::KeyFromPrivateBytes(request) => {
            super::key::convert::from_private_bytes_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::KeyParse(request) => {
            super::key::parse::result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::KeyToPublicBytes(request) => {
            super::key::convert::to_public_bytes_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::KeyToPrivateBytes(request) => {
            super::key::convert::to_private_bytes_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::KeyDerivePublicKid(request) => {
            super::key::convert::derive_public_kid_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::KeyToMultikey(request) => {
            super::key::convert::to_multikey_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::MultikeyToCoseKey(request) => {
            super::key::convert::multikey_to_key_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::MlKemEncryptDirect(request) => {
            super::encrypt::create::direct_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::MlKemEncryptKeyWrap(request) => {
            super::encrypt::create::key_wrap_result(core::mem::take(&mut **request))
        }
        cose_operation_request::Operation::MlKemDecrypt(request) => {
            super::encrypt::decrypt::result(core::mem::take(&mut **request))
        }
    }
}

pub(crate) fn execute_typed(
    request: CoseOperationRequest,
    providers: &dyn OperationProviders,
) -> crate::wire::CoseOperationResponseV2 {
    let maximum = match u32::try_from(crate::wire::MAX_COSE_PROTO_MESSAGE_BYTES) {
        Ok(maximum) => maximum,
        Err(_) => {
            return super::response_v2::from_error(CoseWireError::backend_internal(
                CoseErrorReason::BackendInternal,
            ))
        }
    };
    let result = match request.try_encoded_len() {
        Ok(length) if length <= maximum => dispatch_operation(request, providers),
        _ => Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonResourceLimitExceeded,
        )),
    };
    super::response_v2::from_result(result)
}

pub(crate) fn execute_proto_with_providers(
    bytes: &[u8],
    providers: &dyn OperationProviders,
) -> Zeroizing<Vec<u8>> {
    let result = decode_protobuf(bytes).and_then(|request| dispatch_operation(request, providers));
    super::response_v2::encode_or_error(&super::response_v2::from_result(result))
}

pub(crate) fn execute_json_with_providers(
    json: &str,
    providers: &dyn OperationProviders,
) -> Zeroizing<Vec<u8>> {
    let result =
        decode_json(json.as_bytes()).and_then(|request| dispatch_operation(request, providers));
    super::response_v2::encode_or_error(&super::response_v2::from_result(result))
}
