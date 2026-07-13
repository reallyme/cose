// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! COSE_Sign1 signing and verification.

#[cfg(feature = "cose-crypto")]
mod build_sig_structure;
#[cfg(feature = "cose-crypto")]
mod convert_ecdsa_signature;
#[cfg(feature = "cose-crypto")]
mod sign;
#[cfg(feature = "cose-crypto")]
mod verify;

#[cfg(feature = "cose-crypto")]
pub use sign::{
    cose_sign1, cose_sign1_detached, cose_sign1_detached_tagged, cose_sign1_detached_with_options,
    cose_sign1_tagged, cose_sign1_with_options, CoseSign1EncodeOptions,
};
#[cfg(feature = "cose-crypto")]
pub use verify::{
    cose_verify1, cose_verify1_detached, cose_verify1_detached_with_metadata,
    cose_verify1_detached_with_policy, cose_verify1_with_metadata, cose_verify1_with_policy,
    VerifiedCoseSign1, VerifiedDetachedCoseSign1,
};
