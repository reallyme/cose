// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated-contract adapters for remaining COSE_Key and Multikey operations.

use zeroize::{Zeroize, Zeroizing};

use crate::key::convert::{
    construct_cose_key_from_private, construct_cose_key_from_public, extract_cose_key_private,
    extract_cose_key_public, CoseKeyFromPrivateBytesInput, CoseKeyFromPublicBytesInput,
    CoseKeyRefInput,
};
use crate::key::derive_kid::derive_cose_key_public_kid;
use crate::key::{parse_cose_key, CoseKeyParseInput, CoseKeyParseOutput};
use crate::multikey::convert::{
    convert_cose_key_to_multikey, convert_multikey_to_cose_key, MultikeyInput,
};
use crate::operation_contract::input::algorithm_identifier_from_proto;
use crate::operation_contract::key::result;
use crate::operation_contract::map_failure::boundary_error_from_failure;
use crate::wire::{
    CoseKeyBytesRequest, CoseKeyFromPrivateBytesRequest, CoseKeyFromPublicBytesRequest,
    CoseMultikeyToCoseKeyRequest, CoseOperationResult, CoseWireResult,
};

pub(crate) fn from_public_bytes_result(
    mut request: CoseKeyFromPublicBytesRequest,
) -> CoseWireResult<CoseOperationResult> {
    let algorithm = algorithm_identifier_from_proto(request.algorithm.as_option())?;
    let public_key = Zeroizing::new(core::mem::take(&mut request.public_key));
    let output =
        construct_cose_key_from_public(CoseKeyFromPublicBytesInput::new(algorithm, &public_key))
            .map_err(boundary_error_from_failure)?;
    result::from_public_key(output)
}

pub(crate) fn from_private_bytes_result(
    mut request: CoseKeyFromPrivateBytesRequest,
) -> CoseWireResult<CoseOperationResult> {
    let algorithm = match algorithm_identifier_from_proto(request.algorithm.as_option()) {
        Ok(algorithm) => algorithm,
        Err(error) => {
            request.private_key.zeroize();
            request.public_key.zeroize();
            return Err(error);
        }
    };
    let private_key = Zeroizing::new(core::mem::take(&mut request.private_key));
    let public_key = Zeroizing::new(core::mem::take(&mut request.public_key));
    let public_key = request.has_public_key.then_some(public_key.as_slice());
    let output = construct_cose_key_from_private(CoseKeyFromPrivateBytesInput::new(
        algorithm,
        &private_key,
        public_key,
    ))
    .map_err(boundary_error_from_failure)?;
    result::from_private_key(output)
}

pub(crate) fn to_public_bytes_result(
    request: CoseKeyBytesRequest,
) -> CoseWireResult<CoseOperationResult> {
    let key = parse_request_key(request)?;
    let output =
        extract_cose_key_public(CoseKeyRefInput::new(&key)).map_err(boundary_error_from_failure)?;
    Ok(result::public_key_bytes(output))
}

pub(crate) fn to_private_bytes_result(
    request: CoseKeyBytesRequest,
) -> CoseWireResult<CoseOperationResult> {
    let key = parse_request_key(request)?;
    let output = extract_cose_key_private(CoseKeyRefInput::new(&key))
        .map_err(boundary_error_from_failure)?;
    Ok(result::private_key_bytes(output))
}

pub(crate) fn derive_public_kid_result(
    request: CoseKeyBytesRequest,
) -> CoseWireResult<CoseOperationResult> {
    let key = parse_request_key(request)?;
    let output = derive_cose_key_public_kid(CoseKeyRefInput::new(&key))
        .map_err(boundary_error_from_failure)?;
    Ok(result::key_identifier(output))
}

pub(crate) fn to_multikey_result(
    request: CoseKeyBytesRequest,
) -> CoseWireResult<CoseOperationResult> {
    let key = parse_request_key(request)?;
    let output = convert_cose_key_to_multikey(CoseKeyRefInput::new(&key))
        .map_err(boundary_error_from_failure)?;
    Ok(result::multikey(output))
}

pub(crate) fn multikey_to_key_result(
    mut request: CoseMultikeyToCoseKeyRequest,
) -> CoseWireResult<CoseOperationResult> {
    let multikey = Zeroizing::new(core::mem::take(&mut request.multikey));
    let output = convert_multikey_to_cose_key(MultikeyInput::new(&multikey))
        .map_err(boundary_error_from_failure)?;
    result::from_multikey_key(output)
}

fn parse_request_key(mut request: CoseKeyBytesRequest) -> CoseWireResult<crate::CoseKey> {
    let encoded_key = Zeroizing::new(core::mem::take(&mut request.cose_key));
    parse_cose_key(CoseKeyParseInput::new(&encoded_key))
        .map(CoseKeyParseOutput::into_key)
        .map_err(boundary_error_from_failure)
}
