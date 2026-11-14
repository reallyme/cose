// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    AgreementKeyProvider, ContainerError, ContainerErrorReason as Reason, CryptoPeerKeyValidator,
    PeerCurve, PeerKeyUsage, PeerKeyValidator,
};
use reallyme_crypto::operations::key_encoding::{
    decompress_p256_public_key, decompress_p384_public_key, decompress_p521_public_key,
};
use zeroize::Zeroizing;

pub(crate) const SEC1_PREFIX_BYTES: usize = 1;
pub(crate) const SEC1_COMPRESSED_EVEN: u8 = 2;
pub(crate) const SEC1_COMPRESSED_ODD: u8 = 3;
pub(crate) const SEC1_UNCOMPRESSED: u8 = 4;

/// Published reallyme-crypto adapter for P-256/P-384/P-521 and X25519 agreement.
/// Brainpool and X448 fail with `Provider` until crypto exposes these capabilities.
pub struct CryptoAgreementKeyProvider;

impl AgreementKeyProvider for CryptoAgreementKeyProvider {
    fn normalize_public_key(
        &self,
        curve: PeerCurve,
        public_material: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
        check_shape(curve, public_material, false)?;
        CryptoPeerKeyValidator.validate(curve, PeerKeyUsage::Agreement, public_material)?;
        if curve.coordinate_bytes().is_none() || public_material.first() == Some(&SEC1_UNCOMPRESSED)
        {
            return super::own_bytes::copy(public_material);
        }
        let expanded = match curve {
            PeerCurve::P256 => decompress_p256_public_key(public_material),
            PeerCurve::P384 => decompress_p384_public_key(public_material),
            PeerCurve::P521 => decompress_p521_public_key(public_material),
            _ => return Err(Reason::Provider.into()),
        }
        .map_err(|_| Reason::Key)?;
        Ok(Zeroizing::new(expanded))
    }
}

pub(super) fn normalize(
    provider: &dyn AgreementKeyProvider,
    curve: PeerCurve,
    public_material: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
    check_shape(curve, public_material, false)?;
    let normalized = provider.normalize_public_key(curve, public_material)?;
    // Providers own mathematical checks. COSE still enforces the representation
    // contract so a malformed result cannot be serialized under another curve.
    check_shape(curve, &normalized, true)?;
    check_identity(curve, public_material, &normalized)?;
    Ok(normalized)
}

fn check_identity(
    curve: PeerCurve,
    supplied: &[u8],
    normalized: &[u8],
) -> Result<(), ContainerError> {
    use reallyme_crypto::operations::constant_time::equal;
    let same = if let Some(width) = curve.coordinate_bytes() {
        if supplied.first() == Some(&SEC1_UNCOMPRESSED) {
            equal(supplied, normalized)
        } else {
            let y_start = SEC1_PREFIX_BYTES.checked_add(width).ok_or(Reason::Limit)?;
            let x = normalized
                .get(SEC1_PREFIX_BYTES..y_start)
                .ok_or(Reason::Key)?;
            let parity = normalized.last().copied().ok_or(Reason::Key)? & 1;
            let prefix = if parity == 0 {
                SEC1_COMPRESSED_EVEN
            } else {
                SEC1_COMPRESSED_ODD
            };
            supplied.first() == Some(&prefix)
                && equal(supplied.get(SEC1_PREFIX_BYTES..).ok_or(Reason::Key)?, x)
        }
    } else {
        equal(supplied, normalized)
    };
    if !same {
        return Err(Reason::Key.into());
    }
    Ok(())
}

fn check_shape(curve: PeerCurve, material: &[u8], full_only: bool) -> Result<(), ContainerError> {
    if material.len() > crate::limits::MAX_COSE_KEY_BYTES {
        return Err(Reason::Limit.into());
    }
    super::inspect_key::check_usage(curve, PeerKeyUsage::Agreement)?;
    if let Some(width) = curve.coordinate_bytes() {
        let full_len = width
            .checked_mul(2)
            .and_then(|n| n.checked_add(SEC1_PREFIX_BYTES))
            .ok_or(Reason::Limit)?;
        let compressed_len = width.checked_add(SEC1_PREFIX_BYTES).ok_or(Reason::Limit)?;
        if material.len() == full_len && material.first() == Some(&SEC1_UNCOMPRESSED) {
            return Ok(());
        }
        if !full_only
            && material.len() == compressed_len
            && matches!(
                material.first(),
                Some(&SEC1_COMPRESSED_EVEN | &SEC1_COMPRESSED_ODD)
            )
        {
            return Ok(());
        }
    } else if Some(material.len()) == curve.okp_bytes() {
        return Ok(());
    }
    Err(Reason::Key.into())
}
