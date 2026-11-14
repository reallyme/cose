// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! COSE algorithm mapping helpers.

mod ml_kem;
mod signature;

pub use ml_kem::{
    REALLYME_COSE_ALG_ML_KEM_1024, REALLYME_COSE_ALG_ML_KEM_1024_A256KW,
    REALLYME_COSE_ALG_ML_KEM_512, REALLYME_COSE_ALG_ML_KEM_512_A128KW,
    REALLYME_COSE_ALG_ML_KEM_768, REALLYME_COSE_ALG_ML_KEM_768_A192KW, REALLYME_COSE_HEADER_EK,
};
pub use signature::CoseSignatureAlgorithm;
