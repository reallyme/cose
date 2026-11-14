// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

#[cfg(feature = "wire")]
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseImplementationConstant as Wire;

#[cfg(feature = "wire")]
pub const CONSTANTS: &[(Wire, i64)] = &[
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_REALLYME_COSE_ALG_ML_KEM_512,
        -65537,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_REALLYME_COSE_ALG_ML_KEM_768,
        -65538,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_REALLYME_COSE_ALG_ML_KEM_1024,
        -65539,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_REALLYME_COSE_ALG_ML_KEM_512_A128KW,
        -65540,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_REALLYME_COSE_ALG_ML_KEM_768_A192KW,
        -65541,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_REALLYME_COSE_ALG_ML_KEM_1024_A256KW,
        -65542,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_REALLYME_COSE_HEADER_EK,
        -65543,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_X5T_SHA256_IDENTIFIER,
        -16,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_COSE_TYPE_TEXT_BYTES,
        256,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_COSE_SIGN1_BYTES,
        65536,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_COSE_MAC0_BYTES,
        65536,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_MAC0_EXTERNAL_AAD_BYTES,
        65536,
    ),
    (Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_COSE_KEY_BYTES, 16384),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_COSE_ENCRYPT_BYTES,
        1114112,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_DETACHED_PAYLOAD_BYTES,
        1048576,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_COSE_X5CHAIN_CERTIFICATES,
        8,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_COSE_X5CHAIN_CERTIFICATE_BYTES,
        16384,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_COSE_X5CHAIN_TOTAL_BYTES,
        65536,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_COSE_PROTO_MESSAGE_BYTES,
        2097152,
    ),
    (
        Wire::COSE_IMPLEMENTATION_CONSTANT_MAX_COSE_PROTO_JSON_BYTES,
        3145728,
    ),
];

pub mod values {
    /// Public contract constant.
    pub const REALLYME_COSE_ALG_ML_KEM_512: i64 = -65537;
    /// Public contract constant.
    pub const REALLYME_COSE_ALG_ML_KEM_768: i64 = -65538;
    /// Public contract constant.
    pub const REALLYME_COSE_ALG_ML_KEM_1024: i64 = -65539;
    /// Public contract constant.
    pub const REALLYME_COSE_ALG_ML_KEM_512_A128KW: i64 = -65540;
    /// Public contract constant.
    pub const REALLYME_COSE_ALG_ML_KEM_768_A192KW: i64 = -65541;
    /// Public contract constant.
    pub const REALLYME_COSE_ALG_ML_KEM_1024_A256KW: i64 = -65542;
    /// Public contract constant.
    pub const REALLYME_COSE_HEADER_EK: i64 = -65543;
    /// Public contract constant.
    #[cfg(feature = "cose-crypto")]
    pub const X5T_SHA256_IDENTIFIER: i64 = -16;
    /// Public contract constant.
    pub const MAX_COSE_TYPE_TEXT_BYTES: usize = 256;
    /// Public contract constant.
    pub const MAX_COSE_SIGN1_BYTES: usize = 65536;
    /// Public contract constant.
    pub const MAX_COSE_MAC0_BYTES: usize = 65536;
    /// Public contract constant.
    pub const MAX_MAC0_EXTERNAL_AAD_BYTES: usize = 65536;
    /// Public contract constant.
    pub const MAX_COSE_KEY_BYTES: usize = 16384;
    /// Public contract constant.
    pub const MAX_COSE_ENCRYPT_BYTES: usize = 1114112;
    /// Public contract constant.
    pub const MAX_DETACHED_PAYLOAD_BYTES: usize = 1048576;
    /// Public contract constant.
    pub const MAX_COSE_X5CHAIN_CERTIFICATES: usize = 8;
    /// Public contract constant.
    pub const MAX_COSE_X5CHAIN_CERTIFICATE_BYTES: usize = 16384;
    /// Public contract constant.
    pub const MAX_COSE_X5CHAIN_TOTAL_BYTES: usize = 65536;
    /// Public contract constant.
    #[cfg(feature = "wire")]
    pub const MAX_COSE_PROTO_MESSAGE_BYTES: usize = 2097152;
    /// Public contract constant.
    #[cfg(feature = "wire")]
    pub const MAX_COSE_PROTO_JSON_BYTES: usize = 3145728;
    #[cfg(feature = "cose-crypto")]
    pub(crate) const MAX_ALLOWLIST_ENTRIES: usize = 32;
    #[cfg(feature = "cose-crypto")]
    pub(crate) const MAX_AGREEMENT_CURVES: usize = 9;
}
