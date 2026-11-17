// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantics for the generated general COSE message operations.

mod bounded;
pub(crate) mod encrypt0;
pub(crate) mod key_set;
mod read_headers;
mod read_message;
pub(crate) mod sign;
mod signature_crypto;
mod validate_key_map;
