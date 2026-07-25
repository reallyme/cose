// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated-result conversion for ML-KEM COSE_Encrypt operations.

use buffa::EnumValue;

use crate::encrypt::create::CoseMlKemEncryptOutput;
use crate::encrypt::types::{
    CoseContentEncryptionAlgorithm as NativeContentAlgorithm, CoseMlKemAlgorithm as NativeKem,
    CoseMlKemMode as NativeMode, DecryptedCoseEncrypt,
};
use crate::wire::{
    cose_operation_result::Result as OperationResultBranch, CoseContentEncryptionAlgorithm,
    CoseKemAlgorithm, CoseMlKemDecryptResult, CoseMlKemEncryptResult, CoseMlKemMode,
    CoseOperationResult,
};

pub(crate) fn encrypted_direct(output: CoseMlKemEncryptOutput) -> CoseOperationResult {
    operation_result(OperationResultBranch::MlKemEncryptDirect(Box::new(
        encrypt_message(output),
    )))
}

pub(crate) fn encrypted_key_wrap(output: CoseMlKemEncryptOutput) -> CoseOperationResult {
    operation_result(OperationResultBranch::MlKemEncryptKeyWrap(Box::new(
        encrypt_message(output),
    )))
}

pub(crate) fn decrypted(output: DecryptedCoseEncrypt) -> CoseOperationResult {
    let mut plaintext = output.plaintext;
    let mut recipient_kid = output.kid;
    operation_result(OperationResultBranch::MlKemDecrypt(Box::new(
        CoseMlKemDecryptResult {
            plaintext: core::mem::take(&mut *plaintext),
            content_algorithm: EnumValue::from(content_algorithm_to_proto(
                output.content_algorithm,
            )),
            kem_algorithm: EnumValue::from(kem_algorithm_to_proto(output.kem_algorithm)),
            mode: EnumValue::from(mode_to_proto(output.mode)),
            recipient_kid: core::mem::take(&mut *recipient_kid),
            __buffa_unknown_fields: Default::default(),
        },
    )))
}

fn encrypt_message(output: CoseMlKemEncryptOutput) -> CoseMlKemEncryptResult {
    let mut cose_encrypt = output.into_zeroizing();
    CoseMlKemEncryptResult {
        cose_encrypt: core::mem::take(&mut *cose_encrypt),
        __buffa_unknown_fields: Default::default(),
    }
}

fn operation_result(result: OperationResultBranch) -> CoseOperationResult {
    CoseOperationResult {
        result: Some(result),
        __buffa_unknown_fields: Default::default(),
    }
}

const fn kem_algorithm_to_proto(algorithm: NativeKem) -> CoseKemAlgorithm {
    match algorithm {
        NativeKem::MlKem512 => CoseKemAlgorithm::MlKem512,
        NativeKem::MlKem768 => CoseKemAlgorithm::MlKem768,
        NativeKem::MlKem1024 => CoseKemAlgorithm::MlKem1024,
    }
}

const fn content_algorithm_to_proto(
    algorithm: NativeContentAlgorithm,
) -> CoseContentEncryptionAlgorithm {
    match algorithm {
        NativeContentAlgorithm::Aes128Gcm => CoseContentEncryptionAlgorithm::Aes128Gcm,
        NativeContentAlgorithm::Aes192Gcm => CoseContentEncryptionAlgorithm::Aes192Gcm,
        NativeContentAlgorithm::Aes256Gcm => CoseContentEncryptionAlgorithm::Aes256Gcm,
    }
}

const fn mode_to_proto(mode: NativeMode) -> CoseMlKemMode {
    match mode {
        NativeMode::Direct => CoseMlKemMode::Direct,
        NativeMode::KeyWrap => CoseMlKemMode::KeyWrap,
    }
}
