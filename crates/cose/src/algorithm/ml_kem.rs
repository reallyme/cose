// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

/// ReallyMe private-use COSE algorithm identifier for direct ML-KEM-1024.
pub use crate::generated_contract::values::REALLYME_COSE_ALG_ML_KEM_1024;
/// ReallyMe private-use COSE algorithm identifier for ML-KEM-1024+A256KW.
pub use crate::generated_contract::values::REALLYME_COSE_ALG_ML_KEM_1024_A256KW;
/// ReallyMe private-use COSE algorithm identifier for direct ML-KEM-512.
pub use crate::generated_contract::values::REALLYME_COSE_ALG_ML_KEM_512;
/// ReallyMe private-use COSE algorithm identifier for ML-KEM-512+A128KW.
pub use crate::generated_contract::values::REALLYME_COSE_ALG_ML_KEM_512_A128KW;
/// ReallyMe private-use COSE algorithm identifier for direct ML-KEM-768.
pub use crate::generated_contract::values::REALLYME_COSE_ALG_ML_KEM_768;
/// ReallyMe private-use COSE algorithm identifier for ML-KEM-768+A192KW.
pub use crate::generated_contract::values::REALLYME_COSE_ALG_ML_KEM_768_A192KW;

/// ReallyMe private-use COSE header label carrying the ML-KEM ciphertext.
///
/// The active COSE-HPKE draft assumes `-4` for `ek`, but that allocation is
/// not final. ReallyMe uses a private-use label so emitted objects cannot be
/// silently reinterpreted if the final IANA assignment differs.
pub use crate::generated_contract::values::REALLYME_COSE_HEADER_EK;
