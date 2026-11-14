// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    inspect_peer_key, ContainerError, ContainerErrorReason as Reason, InspectedPeerKey, PeerCurve,
    PeerKeyUsage, PeerPointEncoding,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::AgreementEc2EncodingPolicy;

/// Explicit agreement-key validation policy; no curves are enabled implicitly.
///
/// The caller assigns protocol roles. For ISO/IEC 18013-5:2021, select
/// `FullCoordinatesOnly` for EReaderKey and `FullOrCompressed` for EDeviceKey.
/// Optional positive parameters are interpreted under the selected policy;
/// private and unknown negative parameters are always rejected.
pub use crate::generated_contract::AgreementKeyPolicy;

impl AgreementKeyPolicy<'_> {
    pub(crate) fn check_allowlist_size(count: usize) -> Result<(), ContainerError> {
        if count == 0 || count > crate::generated_contract::values::MAX_AGREEMENT_CURVES {
            return Err(Reason::Limit.into());
        }
        Ok(())
    }

    pub(crate) fn validate(self) -> Result<(), ContainerError> {
        Self::check_allowlist_size(self.allowed_curves.len())?;
        for (index, curve) in self.allowed_curves.iter().enumerate() {
            super::inspect_key::check_usage(*curve, PeerKeyUsage::Agreement)?;
            let previous = self.allowed_curves.get(..index).ok_or(Reason::Limit)?;
            if previous.contains(curve) {
                return Err(Reason::Duplicate.into());
            }
        }
        Ok(())
    }

    pub(super) fn check_curve(self, curve: PeerCurve) -> Result<(), ContainerError> {
        super::inspect_key::check_usage(curve, PeerKeyUsage::Agreement)?;
        if !self.allowed_curves.contains(&curve) {
            return Err(Reason::Algorithm.into());
        }
        Ok(())
    }

    pub(super) fn check_encoding(
        self,
        curve: PeerCurve,
        encoding: PeerPointEncoding,
    ) -> Result<(), ContainerError> {
        match (curve.coordinate_bytes(), encoding) {
            (Some(_), PeerPointEncoding::Ec2Coordinates) | (None, PeerPointEncoding::Okp) => Ok(()),
            (Some(_), PeerPointEncoding::Ec2YSign)
                if self.ec2_encoding == AgreementEc2EncodingPolicy::FullOrCompressed =>
            {
                Ok(())
            }
            _ => Err(Reason::Profile.into()),
        }
    }
}

/// Crypto-owned agreement point validation and normalization capability.
///
/// Implementations must validate the exact named curve, agreement suitability,
/// point/subgroup membership and non-contributory encodings. Return full SEC1
/// `04 || x || y` for EC2 and canonical public bytes for X25519/X448. Width alone
/// does not establish validity. Provider implementations belong in crypto;
/// unavailable capabilities must fail closed without substituting a curve.
pub trait AgreementKeyProvider {
    /// Validate a SEC1 (compressed or full) or Montgomery public point.
    ///
    /// # Errors
    /// Returns fixed `Key`, `Provider` or `Backend` failures without diagnostics.
    fn normalize_public_key(
        &self,
        curve: PeerCurve,
        public_material: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ContainerError>;
}

/// Validated public agreement key with separate wire and mathematical owners.
///
/// This type cannot contain private d, fabricate a signing registration, or
/// select an ECDH/KDF/transcript protocol. Its buffers zeroize on every drop path.
/// It deliberately has no formatting, cloning or serialization implementation.
pub struct AgreementKey {
    pub(super) received: InspectedPeerKey,
    pub(super) normalized: Zeroizing<Vec<u8>>,
}

impl AgreementKey {
    /// Import an untagged, definite/preferred, unique COSE_Key map in any order.
    ///
    /// The exact map bytes are owned without re-encoding. A surrounding tag 24
    /// or encoded-byte-string wrapper remains caller-owned and is not consumed.
    /// Encoding policy is checked before point normalization, so normalization
    /// cannot repair a forbidden wire representation.
    ///
    /// # Errors
    /// Returns fixed malformed, encoding, duplicate, limit, key, algorithm,
    /// profile or provider failures. Input is bounded by `MAX_COSE_KEY_BYTES`.
    pub fn from_slice(
        encoded: &[u8],
        policy: AgreementKeyPolicy<'_>,
        provider: &dyn AgreementKeyProvider,
    ) -> Result<Self, ContainerError> {
        parse_agreement_key(encoded, policy, provider)
    }

    /// Exact received map bytes, or the minimal map emitted by the constructor.
    /// Never substitute normalized or reconstructed bytes in a transcript.
    #[must_use]
    pub fn original_cose_key(&self) -> &[u8] {
        self.received.original_cose_key()
    }

    /// Validated full SEC1 EC2 point or canonical Montgomery public bytes.
    /// This representation is separate from the received map and point encoding.
    #[must_use]
    pub fn public_material(&self) -> &[u8] {
        &self.normalized
    }

    /// Exact registered named curve; never inferred from point width.
    #[must_use]
    pub const fn curve(&self) -> PeerCurve {
        self.received.curve()
    }

    /// Original or constructed wire point encoding, before normalization.
    #[must_use]
    pub const fn point_encoding(&self) -> PeerPointEncoding {
        self.received.point_encoding()
    }
}
impl ZeroizeOnDrop for AgreementKey {}

pub(crate) fn parse_agreement_key(
    encoded: &[u8],
    policy: AgreementKeyPolicy<'_>,
    provider: &dyn AgreementKeyProvider,
) -> Result<AgreementKey, ContainerError> {
    policy.validate()?;
    let received = inspect_peer_key(encoded, PeerKeyUsage::Agreement, policy.optional_parameters)?;
    policy.check_curve(received.curve())?;
    policy.check_encoding(received.curve(), received.point_encoding())?;
    let normalized = super::normalize_agreement_key::normalize(
        provider,
        received.curve(),
        received.public_material(),
    )?;
    Ok(AgreementKey {
        received,
        normalized,
    })
}
