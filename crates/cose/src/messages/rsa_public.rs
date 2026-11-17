// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::der::{decode_der, decode_unsigned_integer_pair, DerLimits};
use reallyme_crypto::rsa::{RSA_PUBLIC_KEY_DER_MAX_LEN, RSA_SIGNATURE_MAX_LEN};

use crate::CoseError;

const MIN_COSE_RSA_MODULUS_BITS: usize = 2_048;
const MAX_COSE_RSA_MODULUS_BITS: usize = 8_192;
const KEY_DER_DEPTH: usize = 3;
const KEY_DER_ELEMENTS: usize = 8;
const BITS_PER_BYTE: usize = 8;

pub(super) fn modulus_bytes(spki: &[u8]) -> Result<usize, CoseError> {
    if spki.len() > RSA_PUBLIC_KEY_DER_MAX_LEN {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let limits = DerLimits::new(
        RSA_PUBLIC_KEY_DER_MAX_LEN,
        KEY_DER_DEPTH,
        KEY_DER_ELEMENTS,
        RSA_SIGNATURE_MAX_LEN,
    )
    .map_err(|_| CoseError::ResourceLimitExceeded)?;
    // Codec owns strict DER, exact consumption and minimal INTEGER encoding.
    // Crypto subsequently validates the rsaEncryption OID, exponent and key
    // mathematics. COSE adds RFC 8230's stronger minimum without accepting the
    // crypto primitive's historical 1024-bit document-verification policy.
    let bits = decode_der(spki, limits, |document| {
        document.read_sequence(|sequence| {
            sequence.read_sequence(|algorithm| {
                let _ = algorithm.read_object_identifier()?;
                if !algorithm.is_finished() {
                    algorithm.read_null()?;
                }
                Ok(())
            })?;
            sequence.read_bit_string()
        })
    })
    .map_err(|_| CoseError::InvalidKeyMaterial)?;
    if bits.unused_bits() != 0 {
        return Err(CoseError::InvalidKeyMaterial);
    }
    let pair = decode_unsigned_integer_pair(bits.as_bytes(), limits)
        .map_err(|_| CoseError::InvalidKeyMaterial)?;
    let n = pair.first();
    let first = n.first().ok_or(CoseError::InvalidKeyMaterial)?;
    let leading =
        usize::try_from(first.leading_zeros()).map_err(|_| CoseError::InvalidKeyMaterial)?;
    let bit_length = n
        .len()
        .checked_sub(1)
        .and_then(|bytes| bytes.checked_mul(BITS_PER_BYTE))
        .and_then(|bits| bits.checked_add(BITS_PER_BYTE.checked_sub(leading)?))
        .ok_or(CoseError::InvalidKeyMaterial)?;
    if !(MIN_COSE_RSA_MODULUS_BITS..=MAX_COSE_RSA_MODULUS_BITS).contains(&bit_length) {
        return Err(CoseError::InvalidKeyMaterial);
    }
    let rounding = BITS_PER_BYTE
        .checked_sub(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    bit_length
        .checked_add(rounding)
        .and_then(|bits| bits.checked_div(BITS_PER_BYTE))
        .ok_or(CoseError::ResourceLimitExceeded)
}
