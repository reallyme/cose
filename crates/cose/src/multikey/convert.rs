// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_crypto::core::Algorithm;

use reallyme_codec::multikey::{encode_multikey, parse_multikey};
use zeroize::Zeroizing;

use crate::failure::CoseFailure;
use crate::key::convert::{
    construct_cose_key_from_public, extract_cose_key_public, CoseKeyFromPublicBytesInput,
    CoseKeyOwnerOutput, CoseKeyRefInput,
};
use crate::key::profile::algorithm_for_cose_key;
use crate::{CoseError, CoseKey};

pub(crate) struct MultikeyInput<'a> {
    multikey: &'a str,
}

impl<'a> MultikeyInput<'a> {
    pub(crate) const fn new(multikey: &'a str) -> Self {
        Self { multikey }
    }
}

#[must_use]
pub(crate) struct CoseMultikeyOutput {
    multikey: Zeroizing<String>,
}

impl CoseMultikeyOutput {
    pub(crate) fn into_zeroizing(self) -> Zeroizing<String> {
        self.multikey
    }
}

pub(crate) fn convert_cose_key_to_multikey(
    input: CoseKeyRefInput<'_>,
) -> Result<CoseMultikeyOutput, CoseFailure> {
    let algorithm = algorithm_for_cose_key(input.key()).map_err(CoseFailure::from)?;
    let public_key = extract_cose_key_public(input)?.into_zeroizing();
    let codec_name = codec_name_for_algorithm(algorithm).map_err(CoseFailure::from)?;
    encode_multikey(codec_name, &public_key)
        .map(Zeroizing::new)
        .map(|multikey| CoseMultikeyOutput { multikey })
        .map_err(|_| CoseFailure::from(CoseError::InvalidMultikey))
}

pub(crate) fn convert_multikey_to_cose_key(
    input: MultikeyInput<'_>,
) -> Result<CoseKeyOwnerOutput, CoseFailure> {
    let mut parsed = parse_multikey(input.multikey)
        .map_err(|_| CoseFailure::from(CoseError::InvalidMultikey))?;
    let algorithm = algorithm_for_codec_name(parsed.codec_name).map_err(CoseFailure::from)?;
    let public_key = Zeroizing::new(core::mem::take(&mut parsed.public_key));
    construct_cose_key_from_public(CoseKeyFromPublicBytesInput::new(algorithm, &public_key))
}

/// Convert COSE_Key (public) → multikey string.
///
/// # Errors
///
/// Returns [`CoseError`] when the COSE_Key profile or public material is
/// invalid, the algorithm has no supported multikey mapping, or encoding fails.
pub fn cose_key_to_multikey(key: &CoseKey) -> Result<Zeroizing<String>, CoseError> {
    convert_cose_key_to_multikey(CoseKeyRefInput::new(key))
        .map(CoseMultikeyOutput::into_zeroizing)
        .map_err(CoseFailure::into_native_error)
}

fn codec_name_for_algorithm(algorithm: Algorithm) -> Result<&'static str, CoseError> {
    let codec_name = match algorithm {
        Algorithm::Ed25519 => "ed25519-pub",
        Algorithm::X25519 => "x25519-pub",
        Algorithm::P256 => "p256-pub",
        Algorithm::P384 => "p384-pub",
        Algorithm::P521 => "p521-pub",
        Algorithm::Secp256k1 => "secp256k1-pub",
        Algorithm::MlDsa44 => "mldsa-44-pub",
        Algorithm::MlDsa65 => "mldsa-65-pub",
        Algorithm::MlDsa87 => "mldsa-87-pub",
        Algorithm::MlKem512 => "mlkem-512-pub",
        Algorithm::MlKem768 => "mlkem-768-pub",
        Algorithm::MlKem1024 => "mlkem-1024-pub",
        Algorithm::SlhDsaSha2_128s | Algorithm::XWing768 => {
            return Err(CoseError::UnsupportedAlgorithm);
        }
    };
    Ok(codec_name)
}

/// Convert multikey string → COSE_Key (public only).
///
/// # Errors
///
/// Returns [`CoseError`] when the multikey is malformed, its codec has no
/// supported COSE_Key mapping, or its public key material is invalid.
pub fn multikey_to_cose_key(multikey: &str) -> Result<CoseKey, CoseError> {
    convert_multikey_to_cose_key(MultikeyInput::new(multikey))
        .map(CoseKeyOwnerOutput::into_key)
        .map_err(CoseFailure::into_native_error)
}

fn algorithm_for_codec_name(codec_name: &str) -> Result<Algorithm, CoseError> {
    let algorithm = match codec_name {
        "ed25519-pub" => Algorithm::Ed25519,
        "x25519-pub" => Algorithm::X25519,
        "p256-pub" => Algorithm::P256,
        "p384-pub" => Algorithm::P384,
        "p521-pub" => Algorithm::P521,
        "secp256k1-pub" => Algorithm::Secp256k1,
        "mldsa-44-pub" => Algorithm::MlDsa44,
        "mldsa-65-pub" => Algorithm::MlDsa65,
        "mldsa-87-pub" => Algorithm::MlDsa87,
        "mlkem-512-pub" => Algorithm::MlKem512,
        "mlkem-768-pub" => Algorithm::MlKem768,
        "mlkem-1024-pub" => Algorithm::MlKem1024,
        // The multikey codec is valid, but this bridge does not currently map
        // it into a deliberate COSE_Key representation.
        _ => return Err(CoseError::UnsupportedAlgorithm),
    };
    Ok(algorithm)
}
