// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! COSE_Key encoding, extraction, and key identifier derivation.

pub(crate) mod convert;
mod derive_kid;
#[cfg(feature = "cose-crypto")]
pub(crate) mod map_algorithm;

pub use convert::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_from_slice,
    cose_key_to_private_bytes, cose_key_to_public_bytes, cose_key_to_vec,
};
pub use derive_kid::derive_kid_from_cose_key_public;
