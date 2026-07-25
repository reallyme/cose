// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! COSE semantic policy enforcement.

mod validate;

#[cfg(feature = "cose-crypto")]
pub(crate) use validate::validate_cose_sign1_policy;
pub use validate::CosePolicy;
