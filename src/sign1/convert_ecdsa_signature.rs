// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ECDSA signature encoding conversion between COSE and backend formats.
//!
//! COSE (RFC 9053 §2.1) encodes ECDSA signatures as the fixed-width
//! concatenation `r || s`, each padded to the curve coordinate width. The
//! `reallyme-crypto` NIST-curve backends produce and consume ASN.1 DER
//! `ECDSA-Sig-Value` encodings, so this module converts strictly between the
//! two forms at the COSE byte boundary and fails closed on malformed input.

use reallyme_crypto::core::Algorithm;

use crate::key::convert::{P256_COORDINATE_BYTES, P384_COORDINATE_BYTES, P521_COORDINATE_BYTES};
use crate::CoseError;

const DER_SEQUENCE_TAG: u8 = 0x30;
const DER_INTEGER_TAG: u8 = 0x02;
const DER_LONG_FORM_LENGTH_ONE_BYTE: u8 = 0x81;
const DER_SHORT_FORM_LENGTH_MAX: usize = 0x7f;
const DER_LONG_FORM_LENGTH_MAX: usize = 0xff;
const SIGN_BIT_MASK: u8 = 0x80;

/// Coordinate width for algorithms whose backend signature encoding is DER.
///
/// Ed25519 and secp256k1 backends already use the raw fixed-width encoding
/// COSE requires, so they are excluded here and pass through unchanged.
fn der_backed_coordinate_len(alg: Algorithm) -> Option<usize> {
    match alg {
        Algorithm::P256 => Some(P256_COORDINATE_BYTES),
        Algorithm::P384 => Some(P384_COORDINATE_BYTES),
        Algorithm::P521 => Some(P521_COORDINATE_BYTES),
        _ => None,
    }
}

/// Convert a backend-produced signature into the COSE wire encoding.
pub(crate) fn cose_signature_from_backend(
    alg: Algorithm,
    signature: Vec<u8>,
) -> Result<Vec<u8>, CoseError> {
    match der_backed_coordinate_len(alg) {
        Some(coordinate_len) => der_to_fixed_width(&signature, coordinate_len),
        None => Ok(signature),
    }
}

/// Convert a COSE wire signature into the backend encoding.
pub(crate) fn backend_signature_from_cose(
    alg: Algorithm,
    signature: &[u8],
) -> Result<Vec<u8>, CoseError> {
    match der_backed_coordinate_len(alg) {
        Some(coordinate_len) => fixed_width_to_der(signature, coordinate_len),
        None => Ok(signature.to_vec()),
    }
}

fn der_to_fixed_width(der: &[u8], coordinate_len: usize) -> Result<Vec<u8>, CoseError> {
    let sequence_tag = *der.first().ok_or(CoseError::InvalidSignature)?;
    if sequence_tag != DER_SEQUENCE_TAG {
        return Err(CoseError::InvalidSignature);
    }

    let (content_len, content_start) = read_der_length(der, 1)?;
    let expected_end = content_start
        .checked_add(content_len)
        .ok_or(CoseError::InvalidSignature)?;
    if expected_end != der.len() {
        return Err(CoseError::InvalidSignature);
    }

    let (r, s_start) = read_der_integer(der, content_start, coordinate_len)?;
    let (s, end) = read_der_integer(der, s_start, coordinate_len)?;
    if end != der.len() {
        return Err(CoseError::InvalidSignature);
    }

    let signature_len = coordinate_len
        .checked_mul(2)
        .ok_or(CoseError::InvalidSignature)?;
    let mut fixed = vec![0_u8; signature_len];
    let r_start = coordinate_len
        .checked_sub(r.len())
        .ok_or(CoseError::InvalidSignature)?;
    let s_pad = coordinate_len
        .checked_sub(s.len())
        .ok_or(CoseError::InvalidSignature)?;
    let s_offset = coordinate_len
        .checked_add(s_pad)
        .ok_or(CoseError::InvalidSignature)?;
    fixed
        .get_mut(r_start..coordinate_len)
        .ok_or(CoseError::InvalidSignature)?
        .copy_from_slice(r);
    fixed
        .get_mut(s_offset..signature_len)
        .ok_or(CoseError::InvalidSignature)?
        .copy_from_slice(s);

    Ok(fixed)
}

fn fixed_width_to_der(signature: &[u8], coordinate_len: usize) -> Result<Vec<u8>, CoseError> {
    let expected_len = coordinate_len
        .checked_mul(2)
        .ok_or(CoseError::InvalidSignature)?;
    if signature.len() != expected_len {
        return Err(CoseError::InvalidSignature);
    }

    let r = trim_leading_zeros(&signature[..coordinate_len]);
    let s = trim_leading_zeros(&signature[coordinate_len..]);
    if r.is_empty() || s.is_empty() {
        // An all-zero r or s can never be a valid ECDSA scalar.
        return Err(CoseError::InvalidSignature);
    }

    let r_encoded_len = der_integer_encoded_len(r)?;
    let s_encoded_len = der_integer_encoded_len(s)?;
    let content_len = r_encoded_len
        .checked_add(s_encoded_len)
        .and_then(|len| len.checked_add(4))
        .ok_or(CoseError::InvalidSignature)?;
    if content_len > DER_LONG_FORM_LENGTH_MAX {
        return Err(CoseError::InvalidSignature);
    }

    let mut der = Vec::with_capacity(
        content_len
            .checked_add(3)
            .ok_or(CoseError::InvalidSignature)?,
    );
    der.push(DER_SEQUENCE_TAG);
    if content_len > DER_SHORT_FORM_LENGTH_MAX {
        der.push(DER_LONG_FORM_LENGTH_ONE_BYTE);
    }
    let content_len_byte = u8::try_from(content_len).map_err(|_| CoseError::InvalidSignature)?;
    der.push(content_len_byte);
    write_der_integer(&mut der, r)?;
    write_der_integer(&mut der, s)?;

    Ok(der)
}

fn read_der_length(bytes: &[u8], offset: usize) -> Result<(usize, usize), CoseError> {
    let first = *bytes.get(offset).ok_or(CoseError::InvalidSignature)?;
    let value_start = offset.checked_add(1).ok_or(CoseError::InvalidSignature)?;

    if first & SIGN_BIT_MASK == 0 {
        return Ok((usize::from(first), value_start));
    }

    if first != DER_LONG_FORM_LENGTH_ONE_BYTE {
        // Supported curve signatures never need more than a one-byte length.
        return Err(CoseError::InvalidSignature);
    }

    let value = *bytes.get(value_start).ok_or(CoseError::InvalidSignature)?;
    if usize::from(value) <= DER_SHORT_FORM_LENGTH_MAX {
        // Non-minimal long-form length.
        return Err(CoseError::InvalidSignature);
    }

    let next = value_start
        .checked_add(1)
        .ok_or(CoseError::InvalidSignature)?;
    Ok((usize::from(value), next))
}

fn read_der_integer(
    bytes: &[u8],
    offset: usize,
    coordinate_len: usize,
) -> Result<(&[u8], usize), CoseError> {
    let tag = *bytes.get(offset).ok_or(CoseError::InvalidSignature)?;
    if tag != DER_INTEGER_TAG {
        return Err(CoseError::InvalidSignature);
    }

    let length_offset = offset.checked_add(1).ok_or(CoseError::InvalidSignature)?;
    let (len, content_start) = read_der_length(bytes, length_offset)?;
    if len == 0 {
        return Err(CoseError::InvalidSignature);
    }

    let content_end = content_start
        .checked_add(len)
        .ok_or(CoseError::InvalidSignature)?;
    let content = bytes
        .get(content_start..content_end)
        .ok_or(CoseError::InvalidSignature)?;

    let leading = content[0];
    if leading & SIGN_BIT_MASK != 0 {
        // Negative integers can never be valid ECDSA scalars.
        return Err(CoseError::InvalidSignature);
    }
    if len > 1 && leading == 0 && content[1] & SIGN_BIT_MASK == 0 {
        // Non-minimal integer encoding.
        return Err(CoseError::InvalidSignature);
    }

    let value = if leading == 0 { &content[1..] } else { content };
    if value.is_empty() || value.len() > coordinate_len {
        return Err(CoseError::InvalidSignature);
    }

    Ok((value, content_end))
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn der_integer_encoded_len(value: &[u8]) -> Result<usize, CoseError> {
    let sign_pad = usize::from(value[0] & SIGN_BIT_MASK != 0);
    value
        .len()
        .checked_add(sign_pad)
        .ok_or(CoseError::InvalidSignature)
}

fn write_der_integer(der: &mut Vec<u8>, value: &[u8]) -> Result<(), CoseError> {
    let encoded_len = der_integer_encoded_len(value)?;
    let encoded_len_byte = u8::try_from(encoded_len).map_err(|_| CoseError::InvalidSignature)?;
    der.push(DER_INTEGER_TAG);
    der.push(encoded_len_byte);
    if value[0] & SIGN_BIT_MASK != 0 {
        der.push(0);
    }
    der.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::{backend_signature_from_cose, cose_signature_from_backend};
    use crate::CoseError;
    use reallyme_crypto::core::Algorithm;

    const P256_SIGNATURE_LEN: usize = 64;
    const P521_SIGNATURE_LEN: usize = 132;

    fn sample_fixed(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from(index % 251).unwrap().wrapping_add(1))
            .collect()
    }

    #[test]
    fn fixed_roundtrips_through_der() {
        for (alg, len) in [
            (Algorithm::P256, P256_SIGNATURE_LEN),
            (Algorithm::P384, 96),
            (Algorithm::P521, P521_SIGNATURE_LEN),
        ] {
            let fixed = sample_fixed(len);
            let der = backend_signature_from_cose(alg, &fixed).unwrap();
            let back = cose_signature_from_backend(alg, der).unwrap();
            assert_eq!(back, fixed);
        }
    }

    #[test]
    fn high_bit_scalars_gain_der_sign_padding_and_roundtrip() {
        let mut fixed = vec![0xff_u8; P256_SIGNATURE_LEN];
        fixed[0] = 0x80;
        fixed[32] = 0x80;
        let der = backend_signature_from_cose(Algorithm::P256, &fixed).unwrap();
        assert_eq!(der[4], 0);
        let back = cose_signature_from_backend(Algorithm::P256, der).unwrap();
        assert_eq!(back, fixed);
    }

    #[test]
    fn short_scalars_left_pad_to_coordinate_width() {
        let mut fixed = vec![0_u8; P256_SIGNATURE_LEN];
        fixed[31] = 0x01;
        fixed[63] = 0x02;
        let der = backend_signature_from_cose(Algorithm::P256, &fixed).unwrap();
        let back = cose_signature_from_backend(Algorithm::P256, der).unwrap();
        assert_eq!(back, fixed);
    }

    #[test]
    fn p521_uses_long_form_der_length() {
        let fixed = sample_fixed(P521_SIGNATURE_LEN);
        let der = backend_signature_from_cose(Algorithm::P521, &fixed).unwrap();
        assert_eq!(der[1], 0x81);
        let back = cose_signature_from_backend(Algorithm::P521, der).unwrap();
        assert_eq!(back, fixed);
    }

    #[test]
    fn wrong_length_fixed_signature_is_rejected() {
        let fixed = sample_fixed(P256_SIGNATURE_LEN - 1);
        let err = backend_signature_from_cose(Algorithm::P256, &fixed).unwrap_err();
        assert_eq!(err, CoseError::InvalidSignature);
    }

    #[test]
    fn zero_scalars_are_rejected() {
        let fixed = vec![0_u8; P256_SIGNATURE_LEN];
        let err = backend_signature_from_cose(Algorithm::P256, &fixed).unwrap_err();
        assert_eq!(err, CoseError::InvalidSignature);
    }

    #[test]
    fn der_with_trailing_bytes_is_rejected() {
        let fixed = sample_fixed(P256_SIGNATURE_LEN);
        let mut der = backend_signature_from_cose(Algorithm::P256, &fixed).unwrap();
        der.push(0);
        let err = cose_signature_from_backend(Algorithm::P256, der).unwrap_err();
        assert_eq!(err, CoseError::InvalidSignature);
    }

    #[test]
    fn negative_der_integer_is_rejected() {
        // SEQUENCE { INTEGER 0x80 (negative), INTEGER 0x01 }
        let der = vec![0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
        let err = cose_signature_from_backend(Algorithm::P256, der).unwrap_err();
        assert_eq!(err, CoseError::InvalidSignature);
    }

    #[test]
    fn non_minimal_der_integer_is_rejected() {
        // SEQUENCE { INTEGER 0x00 0x01 (non-minimal), INTEGER 0x01 }
        let der = vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
        let err = cose_signature_from_backend(Algorithm::P256, der).unwrap_err();
        assert_eq!(err, CoseError::InvalidSignature);
    }

    #[test]
    fn ed25519_and_secp256k1_pass_through_unchanged() {
        let fixed = sample_fixed(64);
        for alg in [Algorithm::Ed25519, Algorithm::Secp256k1] {
            assert_eq!(
                cose_signature_from_backend(alg, fixed.clone()).unwrap(),
                fixed
            );
            assert_eq!(backend_signature_from_cose(alg, &fixed).unwrap(), fixed);
        }
    }
}
