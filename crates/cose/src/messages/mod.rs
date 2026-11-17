// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantics for the generated general COSE message operations.

pub(crate) mod attach_counter_signature;
mod bounded;
pub(crate) mod counter_signature;
pub(crate) mod counter_signature0;
mod counter_structure;
mod counter_target;
mod create_recipients;
pub(crate) mod encrypt0;
pub(crate) mod key_set;
pub(crate) mod mac;
mod open_recipient;
mod read_headers;
mod read_message;
mod recipient;
mod rsa;
mod rsa_public;
pub(crate) mod rsa_sign1;
pub(crate) mod sign;
mod signature_crypto;
mod validate_key_map;
mod wrap_key;
