// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::normalize_agreement_key::{normalize, SEC1_PREFIX_BYTES};
use super::own_bytes::{bstr, head, reserve};
use super::{
    inspect_peer_key, AgreementKey, AgreementKeyPolicy, AgreementKeyProvider, ContainerError,
    ContainerErrorReason as Reason, OptionalKeyPolicy, PeerCurve, PeerKeyUsage, PeerPointEncoding,
};
use zeroize::Zeroizing;

const CBOR_UNSIGNED: u8 = 0;
const CBOR_MAP: u8 = 5;
const EC2_KEY_TYPE: u64 = 2;
const OKP_KEY_TYPE: u64 = 1;
const EC2_PARAMETER_COUNT: u64 = 4;
const OKP_PARAMETER_COUNT: u64 = 3;
const KTY_LABEL: u8 = 1;
const CURVE_LABEL: u8 = 0x20;
const X_LABEL: u8 = 0x21;
const Y_LABEL: u8 = 0x22;
const CBOR_FALSE: u8 = 0xf4;
const CBOR_TRUE: u8 = 0xf5;

impl AgreementKey {
    /// Construct a public agreement COSE_Key with an explicit point encoding.
    ///
    /// The input is SEC1 (full or compressed) for EC2 and canonical Montgomery
    /// bytes for OKP. Crypto validates and normalizes before serialization. Only
    /// kty, crv, x and EC2 y are emitted; neither a signature alg nor key_ops is
    /// invented. The map is preferred/deterministically ordered. Reader/device
    /// role selection stays with the caller through `policy.ec2_encoding`.
    ///
    /// # Errors
    /// Returns fixed key, algorithm, profile, limit or provider failures.
    pub fn from_public_key(
        curve: PeerCurve,
        public_material: &[u8],
        encoding: PeerPointEncoding,
        policy: AgreementKeyPolicy<'_>,
        provider: &dyn AgreementKeyProvider,
    ) -> Result<Self, ContainerError> {
        construct_agreement_key(curve, public_material, encoding, policy, provider)
    }
}

pub(crate) fn construct_agreement_key(
    curve: PeerCurve,
    public_material: &[u8],
    encoding: PeerPointEncoding,
    policy: AgreementKeyPolicy<'_>,
    provider: &dyn AgreementKeyProvider,
) -> Result<AgreementKey, ContainerError> {
    policy.validate()?;
    policy.check_curve(curve)?;
    policy.check_encoding(curve, encoding)?;
    let normalized = normalize(provider, curve, public_material)?;
    let encoded = encode(curve, &normalized, encoding)?;
    let received = inspect_peer_key(&encoded, PeerKeyUsage::Agreement, OptionalKeyPolicy::Cose)?;
    Ok(AgreementKey {
        received,
        normalized,
    })
}

fn encode(
    curve: PeerCurve,
    material: &[u8],
    encoding: PeerPointEncoding,
) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
    let mut encoded = Zeroizing::new(Vec::new());
    let width = curve.coordinate_bytes();
    head(
        &mut encoded,
        CBOR_MAP,
        if width.is_some() {
            EC2_PARAMETER_COUNT
        } else {
            OKP_PARAMETER_COUNT
        },
    )?;
    byte(&mut encoded, KTY_LABEL)?;
    head(
        &mut encoded,
        CBOR_UNSIGNED,
        if width.is_some() {
            EC2_KEY_TYPE
        } else {
            OKP_KEY_TYPE
        },
    )?;
    byte(&mut encoded, CURVE_LABEL)?;
    head(
        &mut encoded,
        CBOR_UNSIGNED,
        u64::try_from(curve.identifier()).map_err(|_| Reason::Algorithm)?,
    )?;
    byte(&mut encoded, X_LABEL)?;
    if let Some(width) = width {
        let y_start = SEC1_PREFIX_BYTES.checked_add(width).ok_or(Reason::Limit)?;
        let x = material
            .get(SEC1_PREFIX_BYTES..y_start)
            .ok_or(Reason::Key)?;
        let y = material.get(y_start..).ok_or(Reason::Key)?;
        bstr(&mut encoded, x)?;
        byte(&mut encoded, Y_LABEL)?;
        match encoding {
            PeerPointEncoding::Ec2Coordinates => bstr(&mut encoded, y)?,
            PeerPointEncoding::Ec2YSign => {
                let parity = y.last().copied().ok_or(Reason::Key)? & 1;
                // Point compression is representation only: the complete input
                // point was validated before any coordinate can be discarded.
                byte(
                    &mut encoded,
                    if parity == 0 { CBOR_FALSE } else { CBOR_TRUE },
                )?;
            }
            PeerPointEncoding::Okp => return Err(Reason::Profile.into()),
        }
    } else {
        bstr(&mut encoded, material)?;
    }
    Ok(encoded)
}

fn byte(output: &mut Vec<u8>, value: u8) -> Result<(), ContainerError> {
    reserve(output, 1)?;
    output.push(value);
    Ok(())
}
