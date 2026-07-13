// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! COSE helpers for ReallyMe identity software.
//!
//! The initial public surface is intentionally limited to COSE_Sign1 and
//! COSE_Key helpers. Unsupported COSE message families are documented in the
//! crate README and fail closed instead of being partially interpreted.
//!
//! # Example
//!
//! ```
//! use reallyme_cose::{cose_sign1, cose_verify1_with_policy, Algorithm, CoseError, CosePolicy};
//! use reallyme_crypto::dispatch::generate_keypair;
//!
//! fn sign_and_verify() -> Result<(), CoseError> {
//!     let (public_key, private_key) = generate_keypair(Algorithm::Ed25519)?;
//!     let kid = b"example-key";
//!
//!     let cose_bytes = cose_sign1(Algorithm::Ed25519, b"payload", &private_key, Some(kid))?;
//!     let policy = CosePolicy {
//!         require_kid: true,
//!         allowed_algs: vec![Algorithm::Ed25519],
//!         ..Default::default()
//!     };
//!
//!     let verified = cose_verify1_with_policy(&cose_bytes, &policy, |requested_kid| {
//!         (requested_kid == kid).then(|| public_key.clone())
//!     })?;
//!     assert_eq!(verified.payload, b"payload");
//!     assert_eq!(verified.alg, Algorithm::Ed25519);
//!     assert_eq!(verified.kid, kid);
//!     Ok(())
//! }
//! # sign_and_verify().unwrap();
//! ```

/// Crypto algorithm selector used by the COSE public API.
///
/// Consumers should import this re-export instead of depending directly on
/// `reallyme-crypto`; that keeps the algorithm type identical to the one used
/// by `reallyme-cose`.
pub use reallyme_crypto::core::Algorithm;

/// COSE algorithm mapping helpers.
pub mod algorithm;
/// Typed COSE errors.
pub mod error;
pub use error::CoseError;

/// Resource limits shared by COSE byte-boundary APIs.
pub mod limits;

// --- COSE_Sign1 ---
pub mod sign1;
#[cfg(feature = "cose-crypto")]
pub use sign1::{
    cose_sign1, cose_sign1_detached, cose_sign1_detached_tagged, cose_sign1_detached_with_options,
    cose_sign1_tagged, cose_sign1_with_options, cose_verify1, cose_verify1_detached,
    cose_verify1_detached_with_metadata, cose_verify1_detached_with_policy,
    cose_verify1_with_metadata, cose_verify1_with_policy, CoseSign1EncodeOptions,
    VerifiedCoseSign1, VerifiedDetachedCoseSign1,
};

/// COSE semantic policy enforcement.
pub mod policy;
pub use policy::{validate_cose_sign1_policy, CosePolicy};

// --- COSE_Key ---
pub mod key;
pub use key::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_from_slice,
    cose_key_to_private_bytes, cose_key_to_public_bytes, cose_key_to_vec,
    derive_kid_from_cose_key_public,
};

/// COSE_Key and Multikey conversion helpers.
pub mod multikey;
pub use multikey::{cose_key_to_multikey, multikey_to_cose_key};
