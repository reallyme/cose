// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::failure::CoseFailure;
#[cfg(feature = "cose-crypto")]
use crate::key::convert::canonical_ml_kem_public_key_bytes;
use crate::key::convert::{
    construct_cose_key_from_public, encode_cose_key, extract_cose_key_public,
    CoseKeyFromPublicBytesInput, CoseKeyRefInput,
};
use crate::key::profile::algorithm_for_cose_key;
use crate::{CoseError, CoseKey};
use reallyme_codec::cbor::sha2_256_content_hash;
#[cfg(feature = "cose-crypto")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

#[must_use]
pub(crate) struct CoseKeyKidOutput {
    kid: Zeroizing<Vec<u8>>,
}

impl CoseKeyKidOutput {
    pub(crate) fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.kid
    }
}

pub(crate) fn derive_cose_key_public_kid(
    input: CoseKeyRefInput<'_>,
) -> Result<CoseKeyKidOutput, CoseFailure> {
    let algorithm = algorithm_for_cose_key(input.key()).map_err(CoseFailure::from)?;
    let public_bytes = extract_cose_key_public(input)?.into_zeroizing();
    let public_key =
        construct_cose_key_from_public(CoseKeyFromPublicBytesInput::new(algorithm, &public_bytes))?
            .into_key();
    let canonical = encode_cose_key(CoseKeyRefInput::new(&public_key))?.into_zeroizing();
    Ok(CoseKeyKidOutput {
        kid: Zeroizing::new(sha2_256_content_hash(&canonical).to_vec()),
    })
}

/// Derive `kid = SHA-256(canonical public COSE_Key)`.
///
/// The public key is validated and normalized before encoding, so compressed,
/// raw-coordinate, and uncompressed SEC1 inputs for the same EC point produce
/// one identifier. The canonical public key includes its algorithm binding;
/// the same bytes under a different COSE algorithm therefore cannot collide.
///
/// # Errors
///
/// Returns [`CoseError`] when the key profile, public material, algorithm
/// binding, point encoding, or canonical CBOR encoding is invalid.
pub fn derive_kid_from_cose_key_public(key: &CoseKey) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    derive_cose_key_public_kid(CoseKeyRefInput::new(key))
        .map(CoseKeyKidOutput::into_zeroizing)
        .map_err(CoseFailure::into_native_error)
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn derive_kid_from_ml_kem_public_key(
    algorithm: reallyme_crypto::core::Algorithm,
    public_key: &[u8],
) -> Result<[u8; 32], CoseError> {
    let mut canonical = canonical_ml_kem_public_key_bytes(algorithm, public_key)?;
    let kid = sha2_256_content_hash(&canonical);
    canonical.zeroize();
    Ok(kid)
}
