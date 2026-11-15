// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use coset::iana;
use reallyme_codec::cbor::sha2_256_content_hash;
use zeroize::Zeroizing;

use super::super::profile::{get_param_bytes, ED25519_PUBLIC_KEY_BYTES};
use crate::CoseError;

// RFC 8949 order for the four COSE_Key labels 1, 3, -1, and -2. The map
// binds kty OKP, alg Ed25519 (-19), crv Ed25519 (6), and x as bstr(32).
const ED25519_PUBLIC_MAP_PREFIX: [u8; 10] =
    [0xa4, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06, 0x21, 0x58, 0x20];
const ED25519_KID_PREIMAGE_BYTES: usize =
    ED25519_PUBLIC_MAP_PREFIX.len() + ED25519_PUBLIC_KEY_BYTES;

// The caller has validated the Ed25519 profile and registration.
pub(super) fn hash_ed25519_kid(key: &coset::CoseKey) -> Result<[u8; 32], CoseError> {
    let public_key = get_param_bytes(key, iana::OkpKeyParameter::X as i64)
        .ok_or(CoseError::MissingKeyMaterial)?;
    let x: &[u8; ED25519_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| CoseError::InvalidKeyMaterial)?;
    let mut preimage = Zeroizing::new([0; ED25519_KID_PREIMAGE_BYTES]);
    let (prefix, public) = preimage.split_at_mut(ED25519_PUBLIC_MAP_PREFIX.len());
    prefix.copy_from_slice(&ED25519_PUBLIC_MAP_PREFIX);
    public.copy_from_slice(x);
    Ok(sha2_256_content_hash(preimage.as_slice()))
}
