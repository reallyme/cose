// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! COSE_Key and Multikey conversion helpers.

pub(crate) mod convert;

pub use convert::{cose_key_to_multikey, multikey_to_cose_key};
