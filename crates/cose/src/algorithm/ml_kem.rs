// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// ReallyMe private-use COSE algorithm identifier for direct ML-KEM-512.
pub const REALLYME_COSE_ALG_ML_KEM_512: i64 = -65_537;
/// ReallyMe private-use COSE algorithm identifier for direct ML-KEM-768.
pub const REALLYME_COSE_ALG_ML_KEM_768: i64 = -65_538;
/// ReallyMe private-use COSE algorithm identifier for direct ML-KEM-1024.
pub const REALLYME_COSE_ALG_ML_KEM_1024: i64 = -65_539;
/// ReallyMe private-use COSE algorithm identifier for ML-KEM-512+A128KW.
pub const REALLYME_COSE_ALG_ML_KEM_512_A128KW: i64 = -65_540;
/// ReallyMe private-use COSE algorithm identifier for ML-KEM-768+A192KW.
pub const REALLYME_COSE_ALG_ML_KEM_768_A192KW: i64 = -65_541;
/// ReallyMe private-use COSE algorithm identifier for ML-KEM-1024+A256KW.
pub const REALLYME_COSE_ALG_ML_KEM_1024_A256KW: i64 = -65_542;

/// ReallyMe private-use COSE header label carrying the ML-KEM ciphertext.
///
/// The active COSE-HPKE draft assumes `-4` for `ek`, but that allocation is
/// not final. ReallyMe uses a private-use label so emitted objects cannot be
/// silently reinterpreted if the final IANA assignment differs.
pub const REALLYME_COSE_HEADER_EK: i64 = -65_543;
