// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Resource limits shared by COSE byte-boundary APIs.

mod profile;
mod validate;

#[cfg(test)]
mod validate_tests;

pub use profile::{
    MAX_COSE_ENCRYPT_BYTES, MAX_COSE_KEY_BYTES, MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES,
};

pub(crate) use profile::validate_cose_key_bytes;

#[cfg(feature = "cose-crypto")]
pub(crate) use profile::{
    validate_cose_encrypt_bytes, validate_cose_sign1_bytes_with_limit, validate_detached_payload,
    validate_detached_payload_with_limit, validate_protected_header_bytes,
};
