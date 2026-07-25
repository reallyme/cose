// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! COSE_Key encoding, extraction, and key identifier derivation.

mod akp;
pub(crate) mod convert;
pub(crate) mod derive_kid;
pub(crate) mod ec;
#[cfg(feature = "cose-crypto")]
pub(crate) mod map_algorithm;
mod owned;
mod parse;
pub(crate) mod profile;
#[cfg(feature = "cose-crypto")]
mod reject_weak_public_key;
mod validate_material;

pub use convert::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_to_private_bytes,
    cose_key_to_public_bytes, cose_key_to_vec,
};
pub use derive_kid::derive_kid_from_cose_key_public;
#[cfg(feature = "cose-crypto")]
pub(crate) use derive_kid::derive_kid_from_ml_kem_public_key;
pub use owned::CoseKey;
pub use parse::cose_key_from_slice;
#[cfg(feature = "wire")]
pub(crate) use parse::{parse_cose_key, CoseKeyParseInput, CoseKeyParseOutput};

#[cfg(all(test, feature = "cose-crypto"))]
mod parse_differential_tests;
#[cfg(test)]
mod parse_tests;
