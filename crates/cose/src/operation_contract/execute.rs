// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Executable binary protobuf and generated ProtoJSON operation boundary.

use zeroize::Zeroizing;

use crate::wire::{
    cose_operation_request, decode_json, decode_protobuf, CoseErrorReason, CoseOperationRequest,
    CoseOperationResult, CoseWireError, CoseWireResult,
};

pub(crate) fn execute_proto(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let response = super::response_v2::from_result(
        decode_protobuf(request_bytes).and_then(dispatch_operation),
    );
    super::response_v2::encode_or_error(&response)
}

pub(crate) fn execute_proto_json(request_json: &str) -> Zeroizing<Vec<u8>> {
    let response = super::response_v2::from_result(
        decode_json(request_json.as_bytes()).and_then(dispatch_operation),
    );
    super::response_v2::encode_or_error(&response)
}

fn dispatch_operation(mut request: CoseOperationRequest) -> CoseWireResult<CoseOperationResult> {
    // The generated owner implements Drop so retained unknown fields are
    // recursively wiped. Taking the oneof preserves that owner for its Drop
    // path while transferring the selected request into typed dispatch.
    let Some(operation) = request.operation.take() else {
        return Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        ));
    };

    match operation {
        cose_operation_request::Operation::Sign1Create(request) => {
            super::sign1::create::attached_result(*request)
        }
        cose_operation_request::Operation::Sign1CreateDetached(request) => {
            super::sign1::create::detached_result(*request)
        }
        cose_operation_request::Operation::Sign1Verify(request) => {
            super::sign1::verify::attached_result(*request)
        }
        cose_operation_request::Operation::Sign1VerifyDetached(request) => {
            super::sign1::verify::detached_result(*request)
        }
        cose_operation_request::Operation::KeyFromPublicBytes(request) => {
            super::key::convert::from_public_bytes_result(*request)
        }
        cose_operation_request::Operation::KeyFromPrivateBytes(request) => {
            super::key::convert::from_private_bytes_result(*request)
        }
        cose_operation_request::Operation::KeyParse(request) => super::key::parse::result(*request),
        cose_operation_request::Operation::KeyToPublicBytes(request) => {
            super::key::convert::to_public_bytes_result(*request)
        }
        cose_operation_request::Operation::KeyToPrivateBytes(request) => {
            super::key::convert::to_private_bytes_result(*request)
        }
        cose_operation_request::Operation::KeyDerivePublicKid(request) => {
            super::key::convert::derive_public_kid_result(*request)
        }
        cose_operation_request::Operation::KeyToMultikey(request) => {
            super::key::convert::to_multikey_result(*request)
        }
        cose_operation_request::Operation::MultikeyToCoseKey(request) => {
            super::key::convert::multikey_to_key_result(*request)
        }
        cose_operation_request::Operation::MlKemEncryptDirect(request) => {
            super::encrypt::create::direct_result(*request)
        }
        cose_operation_request::Operation::MlKemEncryptKeyWrap(request) => {
            super::encrypt::create::key_wrap_result(*request)
        }
        cose_operation_request::Operation::MlKemDecrypt(request) => {
            super::encrypt::decrypt::result(*request)
        }
    }
}
