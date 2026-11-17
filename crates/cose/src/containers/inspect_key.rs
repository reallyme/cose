// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::read_cbor::Item;
use super::{
    ContainerError, ContainerErrorReason as Reason, InspectedPeerKey, OptionalKeyPolicy, PeerCurve,
    PeerKeyUsage, PeerPointEncoding,
};
use crate::limits::MAX_COSE_KEY_BYTES;
use zeroize::Zeroizing;

const MAX_KEY_PARAMETERS: usize = 32;
const MAX_KEY_OPERATIONS: usize = 16;
const EC2_KEY_TYPE: i64 = 2;
const OKP_KEY_TYPE: i64 = 1;
const SEC1_PREFIX_BYTES: usize = 1;
const SEC1_COMPRESSED_EVEN: u8 = 2;
const SEC1_COMPRESSED_ODD: u8 = 3;
const SEC1_UNCOMPRESSED: u8 = 4;

/// Inspect bounded public COSE_Key bytes without requiring a signing registration.
///
/// Map order and original compressed-point representation are retained. This is
/// not cryptographic point validation: call `InspectedPeerKey::validate` before
/// passing a key to crypto. No private d is accepted or copied. Under `Cose`, a
/// signature key's optional Base IV must be a byte string; it is retained only
/// in the exact original encoding and never contributes to public material.
///
/// # Errors
/// Returns fixed encoding, limit, duplicate, key, usage and algorithm failures.
pub fn inspect_peer_key(
    encoded: &[u8],
    usage: PeerKeyUsage,
    optional: OptionalKeyPolicy,
) -> Result<InspectedPeerKey, ContainerError> {
    inspect_peer_key_operation(encoded, usage, optional)
}

pub(crate) fn inspect_peer_key_operation(
    encoded: &[u8],
    usage: PeerKeyUsage,
    optional: OptionalKeyPolicy,
) -> Result<InspectedPeerKey, ContainerError> {
    if encoded.len() > MAX_COSE_KEY_BYTES {
        return Err(Reason::Limit.into());
    }
    super::validate_preferred_cbor(encoded)?;
    let map = Item::from_validated(encoded)?;
    let count = map.count(5)?;
    if count > MAX_KEY_PARAMETERS {
        return Err(Reason::Limit.into());
    }
    let mut cursor = map.cursor()?;
    let (mut kty, mut curve, mut x, mut y) = (None, None, None, None);
    for _ in 0..count {
        let label = cursor.next()?.integer()?;
        let value = cursor.next()?;
        match label {
            1 => kty = Some(value.integer()?),
            -1 => curve = Some(PeerCurve::from_identifier(value.integer()?)?),
            -2 => x = Some(value.bytes()?),
            -3 => y = Some(value),
            label if label < 0 => return Err(Reason::Key.into()),
            2 => {
                value.bytes()?;
            }
            _ if optional == OptionalKeyPolicy::IsoPeer => {}
            3 => {
                let PeerKeyUsage::Signature(suite) = usage else {
                    return Err(Reason::Key.into());
                };
                if value.integer()? != suite.registration().identifier() {
                    return Err(Reason::Key.into());
                }
            }
            4 => check_operations(value, usage)?,
            5 if matches!(usage, PeerKeyUsage::Signature(_)) => {
                // Base IV has no role in signatures. Validate its CBOR type
                // without copying or interpreting it as cryptographic input.
                value.bytes()?;
            }
            _ => return Err(Reason::Key.into()),
        }
    }
    let curve = curve.ok_or(Reason::Key)?;
    check_usage(curve, usage)?;
    let x = x.ok_or(Reason::Key)?;
    let mut material = Zeroizing::new(Vec::new());
    let encoding = if let Some(width) = curve.coordinate_bytes() {
        if kty != Some(EC2_KEY_TYPE) || x.len() != width {
            return Err(Reason::Key.into());
        }
        let y = y.ok_or(Reason::Key)?;
        let size = width
            .checked_mul(2)
            .and_then(|n| n.checked_add(SEC1_PREFIX_BYTES))
            .ok_or(Reason::Limit)?;
        super::own_bytes::reserve(&mut material, size)?;
        match (y.major, y.argument) {
            (7, Some(20 | 21)) => {
                material.push(if y.argument == Some(20) {
                    SEC1_COMPRESSED_EVEN
                } else {
                    SEC1_COMPRESSED_ODD
                });
                material.extend_from_slice(x);
                PeerPointEncoding::Ec2YSign
            }
            (2, _) => {
                let y = y.bytes()?;
                if y.len() != width {
                    return Err(Reason::Key.into());
                }
                material.push(SEC1_UNCOMPRESSED);
                material.extend_from_slice(x);
                material.extend_from_slice(y);
                PeerPointEncoding::Ec2Coordinates
            }
            _ => return Err(Reason::Key.into()),
        }
    } else {
        if kty != Some(OKP_KEY_TYPE) || y.is_some() || Some(x.len()) != curve.okp_bytes() {
            return Err(Reason::Key.into());
        }
        material = super::own_bytes::copy(x)?;
        PeerPointEncoding::Okp
    };
    Ok(InspectedPeerKey {
        original: super::own_bytes::copy(encoded)?,
        material,
        curve,
        usage,
        encoding,
    })
}

pub(crate) fn check_usage(curve: PeerCurve, usage: PeerKeyUsage) -> Result<(), ContainerError> {
    if curve == PeerCurve::Secp256k1 {
        return Err(Reason::Algorithm.into());
    }
    match usage {
        PeerKeyUsage::Signature(suite) if curve == suite.curve() => Ok(()),
        PeerKeyUsage::Agreement | PeerKeyUsage::HpkeRecipient
            if !matches!(curve, PeerCurve::Ed25519 | PeerCurve::Ed448) =>
        {
            Ok(())
        }
        _ => Err(Reason::Key.into()),
    }
}

fn check_operations(value: Item<'_>, usage: PeerKeyUsage) -> Result<(), ContainerError> {
    let count = value.count(4)?;
    if count == 0 || count > MAX_KEY_OPERATIONS {
        return Err(Reason::Key.into());
    }
    let mut cursor = value.cursor()?;
    let mut seen: u16 = 0;
    let mut permitted = false;
    for _ in 0..count {
        let op = u32::try_from(cursor.next()?.integer()?).map_err(|_| Reason::Key)?;
        let flag = 1u16.checked_shl(op).ok_or(Reason::Key)?;
        if seen & flag != 0 {
            return Err(Reason::Key.into());
        }
        seen |= flag;
        match usage {
            PeerKeyUsage::Signature(_) => {
                if op != 1 && op != 2 {
                    return Err(Reason::Key.into());
                }
                permitted |= op == 2;
            }
            PeerKeyUsage::Agreement | PeerKeyUsage::HpkeRecipient => {
                if op != 7 && op != 8 {
                    return Err(Reason::Key.into());
                }
                permitted = true;
            }
        }
    }
    if !permitted {
        return Err(Reason::Key.into());
    }
    Ok(())
}
