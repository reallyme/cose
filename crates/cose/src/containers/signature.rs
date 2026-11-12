// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::scalar_order::scalar_order;
use super::{ContainerError, ContainerErrorReason as Reason};
use crate::iso18013::Iso18013SignatureCurve;
use crate::sign1::{der_to_fixed_width, fixed_width_to_der};
use zeroize::Zeroizing;

// A long-form SEQUENCE length plus two INTEGER headers and sign pads. Every
// supported coordinate is at most 66 bytes, so INTEGER lengths stay short-form.
const MAX_ECDSA_DER_OVERHEAD_BYTES: usize = 9;

/// Declared provider encoding, independent of signature byte length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureEncoding {
    /// Strict minimal ASN.1 ECDSA-Sig-Value.
    EcdsaDer,
    /// Exact padded COSE ECDSA r || s.
    EcdsaFixed,
    /// Pure EdDSA compressed R || S encoding.
    EdDsa,
}

impl SignatureEncoding {
    pub(super) fn validate_family(
        self,
        curve: Iso18013SignatureCurve,
    ) -> Result<(), ContainerError> {
        match (curve.coordinate_length().is_some(), self) {
            (true, Self::EcdsaDer | Self::EcdsaFixed) | (false, Self::EdDsa) => Ok(()),
            _ => Err(Reason::SignatureEncoding.into()),
        }
    }
}

/// Validate exact COSE signature width and ECDSA scalars 1 <= r,s < n.
///
/// No blanket low-S policy is applied. Edwards canonicality and subgroup checks
/// remain part of the cryptographic provider's verification responsibility.
///
/// # Errors
/// Returns `SignatureEncoding` for invalid widths or ECDSA scalar values.
pub fn validate_cose_signature(
    curve: Iso18013SignatureCurve,
    signature: &[u8],
) -> Result<(), ContainerError> {
    if signature.len() != curve.signature_length()? {
        return Err(Reason::SignatureEncoding.into());
    }
    if let Some(order) = scalar_order(curve) {
        let (r, s) = signature.split_at(order.len());
        for scalar in [r, s] {
            if scalar.iter().all(|byte| *byte == 0) || scalar >= order {
                return Err(Reason::SignatureEncoding.into());
            }
        }
    }
    Ok(())
}

/// Convert an explicitly declared provider signature to strict COSE form.
///
/// # Errors
/// Returns fixed encoding or allocation failures; never guesses DER by length.
pub fn signature_to_cose(
    curve: Iso18013SignatureCurve,
    encoding: SignatureEncoding,
    signature: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
    let expected = curve.signature_length()?;
    let maximum = expected
        .checked_add(MAX_ECDSA_DER_OVERHEAD_BYTES)
        .ok_or(Reason::Limit)?;
    if signature.len() > maximum
        || (encoding != SignatureEncoding::EcdsaDer && signature.len() != expected)
    {
        return Err(Reason::SignatureEncoding.into());
    }
    let result = match (scalar_order(curve), encoding) {
        (Some(order), SignatureEncoding::EcdsaDer) => {
            Zeroizing::new(der_to_fixed_width(signature, order.len()).map_err(signature_error)?)
        }
        (Some(_), SignatureEncoding::EcdsaFixed) | (None, SignatureEncoding::EdDsa) => {
            super::own_bytes::copy(signature)?
        }
        _ => return Err(Reason::SignatureEncoding.into()),
    };
    validate_cose_signature(curve, &result)?;
    Ok(result)
}

/// Convert strict COSE ECDSA to DER for the explicitly selected named curve.
///
/// # Errors
/// Returns fixed scalar, width, family, DER or allocation failures.
pub fn cose_signature_to_der(
    curve: Iso18013SignatureCurve,
    signature: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
    validate_cose_signature(curve, signature)?;
    let order = scalar_order(curve).ok_or(Reason::SignatureEncoding)?;
    fixed_width_to_der(signature, order.len())
        .map(Zeroizing::new)
        .map_err(signature_error)
}

fn signature_error(error: crate::CoseError) -> ContainerError {
    if error == crate::CoseError::ResourceLimitExceeded {
        Reason::Limit.into()
    } else {
        Reason::SignatureEncoding.into()
    }
}
