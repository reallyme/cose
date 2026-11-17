// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantics for the generated general COSE message operations.

mod bounded;
mod create_recipients;
pub(crate) mod encrypt0;
pub(crate) mod key_set;
pub(crate) mod mac;
mod open_recipient;
mod read_headers;
mod read_message;
mod recipient;
pub(crate) mod sign;
mod signature_crypto;
mod validate_key_map;
mod wrap_key;
