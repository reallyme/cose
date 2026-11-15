// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::cbor::sha2_256_content_hash;
use zeroize::Zeroizing;

use super::super::ec::P256_COORDINATE_BYTES;
use crate::{CoseError, CoseSignatureAlgorithm};

#[cfg(kani)]
#[path = "verify_kid_preimage_proof_tests.rs"]
mod verification;

pub(super) const P256_COMPRESSED_BYTES: usize = 33;
const P256_KID_PREIMAGE_BYTES: usize = 44;
const SEC1_EVEN_Y: u8 = 0x02;
const SEC1_ODD_Y: u8 = 0x03;
const CBOR_FALSE: u8 = 0xf4;
const CBOR_TRUE: u8 = 0xf5;
const CBOR_NEGATIVE_INTEGER: u8 = 0x20;
const CBOR_INLINE_ARGUMENT_LIMIT: u8 = 24;
const ALGORITHM_OFFSET: usize = 4;
const X_OFFSET: usize = 10;
const Y_SIGN_OFFSET: usize = 43;

// Fixed layout of the deterministic public COSE_Key map. The only variable
// fields are the assigned alg, X coordinate, and Y sign. Accepting only a
// validated compressed point keeps private and optional COSE_Key fields out
// of the representation at the hash boundary.
pub(super) fn hash_p256_kid(
    algorithm: CoseSignatureAlgorithm,
    point: &[u8; P256_COMPRESSED_BYTES],
) -> Result<[u8; 32], CoseError> {
    let preimage = encode_p256_kid_preimage(algorithm, point)?;
    Ok(sha2_256_content_hash(preimage.as_slice()))
}

fn encode_p256_kid_preimage(
    algorithm: CoseSignatureAlgorithm,
    point: &[u8; P256_COMPRESSED_BYTES],
) -> Result<Zeroizing<[u8; P256_KID_PREIMAGE_BYTES]>, CoseError> {
    let identifier = match algorithm {
        CoseSignatureAlgorithm::Es256 | CoseSignatureAlgorithm::Esp256 => algorithm.identifier(),
        _ => return Err(CoseError::UnsupportedAlgorithm),
    };
    // CBOR encodes a negative integer n as the unsigned argument -1 - n.
    let argument = (-1_i64)
        .checked_sub(identifier)
        .and_then(|value| u8::try_from(value).ok())
        .filter(|&value| value < CBOR_INLINE_ARGUMENT_LIMIT)
        .ok_or(CoseError::UnsupportedAlgorithm)?;
    let y = match point[0] {
        SEC1_EVEN_Y => CBOR_FALSE,
        SEC1_ODD_Y => CBOR_TRUE,
        _ => return Err(CoseError::InvalidKeyMaterial),
    };

    // CBOR map(5), kty: EC2, alg, crv: P-256, x: bstr(32), y: bool.
    // The labels are already in RFC 8949 deterministic order.
    let mut preimage = Zeroizing::new([0_u8; P256_KID_PREIMAGE_BYTES]);
    preimage[..X_OFFSET]
        .copy_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x00, 0x20, 0x01, 0x21, 0x58, 0x20]);
    preimage[ALGORITHM_OFFSET] = CBOR_NEGATIVE_INTEGER | argument;
    let x_end = X_OFFSET
        .checked_add(P256_COORDINATE_BYTES)
        .ok_or(CoseError::InvalidFormat)?;
    let encoded_x = preimage
        .get_mut(X_OFFSET..x_end)
        .ok_or(CoseError::InvalidFormat)?;
    encoded_x.copy_from_slice(&point[1..]);
    preimage[x_end] = 0x22;
    preimage[Y_SIGN_OFFSET] = y;
    Ok(preimage)
}
