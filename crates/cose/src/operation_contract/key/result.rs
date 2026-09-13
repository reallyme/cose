// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated-result conversion for COSE_Key and Multikey operations.

use buffa::EnumValue;
use zeroize::Zeroizing;

use crate::algorithm::CoseSignatureAlgorithm;
use crate::key::convert::{
    encode_cose_key, CoseKeyBytesOutput, CoseKeyOwnerOutput, CoseKeyRefInput,
};
use crate::key::derive_kid::CoseKeyKidOutput;
use crate::key::CoseKeyParseOutput;
use crate::multikey::convert::CoseMultikeyOutput;
use crate::operation_contract::map_failure::boundary_error_from_failure;
use crate::wire::{
    cose_operation_result::Result as OperationResultBranch, CoseKeyBytesResult, CoseMultikeyResult,
    CoseOperationResult, CoseWireResult,
};

pub(crate) fn from_public_key(output: CoseKeyOwnerOutput) -> CoseWireResult<CoseOperationResult> {
    let message = encode_key(output.into_key())?;
    Ok(operation_result(OperationResultBranch::KeyFromPublicBytes(
        Box::new(message),
    )))
}

pub(crate) fn from_private_key(output: CoseKeyOwnerOutput) -> CoseWireResult<CoseOperationResult> {
    let message = encode_key(output.into_key())?;
    Ok(operation_result(
        OperationResultBranch::KeyFromPrivateBytes(Box::new(message)),
    ))
}

pub(crate) fn parsed_key(output: CoseKeyParseOutput) -> CoseWireResult<CoseOperationResult> {
    let message = encode_key(output.into_key())?;
    Ok(operation_result(OperationResultBranch::KeyParse(Box::new(
        message,
    ))))
}

pub(crate) fn public_key_bytes(output: CoseKeyBytesOutput) -> CoseWireResult<CoseOperationResult> {
    let (bytes, algorithm) = output.into_parts();
    Ok(operation_result(OperationResultBranch::KeyToPublicBytes(
        Box::new(key_bytes_message_with_algorithm(bytes, algorithm)?),
    )))
}

pub(crate) fn private_key_bytes(output: CoseKeyBytesOutput) -> CoseWireResult<CoseOperationResult> {
    let (bytes, algorithm) = output.into_parts();
    Ok(operation_result(OperationResultBranch::KeyToPrivateBytes(
        Box::new(key_bytes_message_with_algorithm(bytes, algorithm)?),
    )))
}

pub(crate) fn key_identifier(output: CoseKeyKidOutput) -> CoseWireResult<CoseOperationResult> {
    let (kid, algorithm) = output.into_parts();
    Ok(operation_result(OperationResultBranch::KeyDerivePublicKid(
        Box::new(key_bytes_message_with_algorithm(kid, algorithm)?),
    )))
}

pub(crate) fn multikey(output: CoseMultikeyOutput) -> CoseOperationResult {
    let mut value = output.into_zeroizing();
    operation_result(OperationResultBranch::KeyToMultikey(Box::new(
        CoseMultikeyResult {
            multikey: core::mem::take(&mut *value),
            __buffa_unknown_fields: Default::default(),
        },
    )))
}

pub(crate) fn from_multikey_key(output: CoseKeyOwnerOutput) -> CoseWireResult<CoseOperationResult> {
    let message = encode_key(output.into_key())?;
    Ok(operation_result(OperationResultBranch::MultikeyToCoseKey(
        Box::new(message),
    )))
}

fn encode_key(key: crate::CoseKey) -> CoseWireResult<CoseKeyBytesResult> {
    let output =
        encode_cose_key(CoseKeyRefInput::new(&key)).map_err(boundary_error_from_failure)?;
    let (bytes, signature_algorithm) = output.into_parts();
    key_bytes_message_with_algorithm(bytes, signature_algorithm)
}

fn key_bytes_message(mut bytes: Zeroizing<Vec<u8>>) -> CoseKeyBytesResult {
    CoseKeyBytesResult {
        key_bytes: core::mem::take(&mut *bytes),
        signature_algorithm: EnumValue::from(0),
        has_signature_algorithm: false,
        __buffa_unknown_fields: Default::default(),
    }
}

fn key_bytes_message_with_algorithm(
    bytes: Zeroizing<Vec<u8>>,
    algorithm: Option<CoseSignatureAlgorithm>,
) -> CoseWireResult<CoseKeyBytesResult> {
    let Some(algorithm) = algorithm else {
        return Ok(key_bytes_message(bytes));
    };
    let mut message = key_bytes_message(bytes);
    message.signature_algorithm = EnumValue::from(
        crate::operation_contract::sign1::result::signature_algorithm_to_proto(algorithm)?,
    );
    message.has_signature_algorithm = true;
    Ok(message)
}

fn operation_result(result: OperationResultBranch) -> CoseOperationResult {
    CoseOperationResult {
        result: Some(result),
        __buffa_unknown_fields: Default::default(),
    }
}
