// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! COSE algorithm mapping helpers.

#[cfg(feature = "cose-crypto")]
mod map_from_cose;
mod ml_kem;

#[cfg(feature = "cose-crypto")]
pub(crate) use map_from_cose::algorithm_from_cose_alg;
pub use ml_kem::{
    REALLYME_COSE_ALG_ML_KEM_1024, REALLYME_COSE_ALG_ML_KEM_1024_A256KW,
    REALLYME_COSE_ALG_ML_KEM_512, REALLYME_COSE_ALG_ML_KEM_512_A128KW,
    REALLYME_COSE_ALG_ML_KEM_768, REALLYME_COSE_ALG_ML_KEM_768_A192KW, REALLYME_COSE_HEADER_EK,
};
