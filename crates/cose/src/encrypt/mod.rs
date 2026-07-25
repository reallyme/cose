// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ReallyMe ML-KEM profiles for `COSE_Encrypt` and `COSE_Recipient`.

mod codec;
pub(crate) mod create;
pub(crate) mod decrypt;
mod kdf;
mod profile;
pub(crate) mod types;

pub use crate::algorithm::{
    REALLYME_COSE_ALG_ML_KEM_1024, REALLYME_COSE_ALG_ML_KEM_1024_A256KW,
    REALLYME_COSE_ALG_ML_KEM_512, REALLYME_COSE_ALG_ML_KEM_512_A128KW,
    REALLYME_COSE_ALG_ML_KEM_768, REALLYME_COSE_ALG_ML_KEM_768_A192KW, REALLYME_COSE_HEADER_EK,
};
pub use create::{
    cose_encrypt_ml_kem_direct, cose_encrypt_ml_kem_direct_with_external_aad,
    cose_encrypt_ml_kem_key_wrap, cose_encrypt_ml_kem_key_wrap_with_external_aad,
};
pub use decrypt::{cose_decrypt_ml_kem, cose_decrypt_ml_kem_with_external_aad};
pub use types::{
    CoseContentEncryptionAlgorithm, CoseMlKemAlgorithm, CoseMlKemDecryptRequest,
    CoseMlKemEncryptRequest, CoseMlKemMode, CoseMlKemProfile, DecryptedCoseEncrypt,
};
