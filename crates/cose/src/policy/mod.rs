// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! COSE semantic policy enforcement.

mod validate;

#[cfg(feature = "cose-crypto")]
pub(crate) use validate::validate_cose_sign1_policy;
pub use validate::CosePolicy;
