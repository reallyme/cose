// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerError, PeerCurve, SignatureSuite};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Intended operation, independently of a COSE signing or HPKE KEM identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerKeyUsage {
    /// Verification under this exact algorithm/curve pair.
    Signature(SignatureSuite),
    /// ECDH/XDH peer key; no signature alg label is required or invented.
    Agreement,
    /// Recipient key for an externally selected crypto HPKE suite.
    HpkeRecipient,
}

/// Optional-parameter interpretation selected explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionalKeyPolicy {
    /// Enforce supplied algorithm and key_ops restrictions; reject other fields.
    Cose,
    /// ISO peer-key contract: ignore optional positive labels, never private d.
    IsoPeer,
}

/// Received public-point encoding, preserved independently of provider normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerPointEncoding {
    /// EC2 x and full y coordinates.
    Ec2Coordinates,
    /// EC2 x and boolean y sign.
    Ec2YSign,
    /// Exact compressed Edwards or Montgomery OKP public bytes.
    Okp,
}

/// Parsed public representation, not yet a cryptographically validated key.
///
/// Private d is rejected before any encoded bytes are copied. Unknown negative
/// parameters are rejected too; an inspector never exports private key material.
pub struct InspectedPeerKey {
    pub(super) original: Zeroizing<Vec<u8>>,
    pub(super) material: Zeroizing<Vec<u8>>,
    pub(super) curve: PeerCurve,
    pub(super) usage: PeerKeyUsage,
    pub(super) encoding: PeerPointEncoding,
}

impl InspectedPeerKey {
    /// Exact received COSE_Key bytes, including the original point representation.
    #[must_use]
    pub fn original_cose_key(&self) -> &[u8] {
        &self.original
    }
    /// SEC1 or OKP public material; point validity is not established yet.
    #[must_use]
    pub fn public_material(&self) -> &[u8] {
        &self.material
    }
    /// Exact named curve.
    #[must_use]
    pub const fn curve(&self) -> PeerCurve {
        self.curve
    }
    /// Intended operation, not a KEM selector.
    #[must_use]
    pub const fn usage(&self) -> PeerKeyUsage {
        self.usage
    }
    /// Received point encoding; the reader applies EReaderKey/EDeviceKey policy.
    #[must_use]
    pub const fn point_encoding(&self) -> PeerPointEncoding {
        self.encoding
    }

    /// Move into a validated owner only after external crypto point/usage checks.
    ///
    /// # Errors
    /// Returns fixed key, provider or backend failures from the crypto boundary.
    pub fn validate(
        self,
        validator: &dyn PeerKeyValidator,
    ) -> Result<ValidatedPeerKey, ContainerError> {
        validator.validate(self.curve, self.usage, &self.material)?;
        Ok(ValidatedPeerKey { key: self })
    }
}
impl ZeroizeOnDrop for InspectedPeerKey {}

/// Cryptographically validated public key plus original wire representation.
/// HPKE construction and role-specific encoding policy remain with the reader.
pub struct ValidatedPeerKey {
    key: InspectedPeerKey,
}
impl ValidatedPeerKey {
    /// Validated public material and exact original representation, together.
    #[must_use]
    pub fn public_view(&self) -> &InspectedPeerKey {
        &self.key
    }
}
impl ZeroizeOnDrop for ValidatedPeerKey {}

/// Crypto-owned validation boundary for named points, subgroups and intended usage.
/// Recognition of an enum or an encoding length must never satisfy this contract.
pub trait PeerKeyValidator {
    /// Validate the exact named curve and intended operation; no fallback curves.
    ///
    /// # Errors
    /// Returns fixed key, provider or backend failures. Missing coverage is `Provider`.
    fn validate(
        &self,
        curve: PeerCurve,
        usage: PeerKeyUsage,
        public_material: &[u8],
    ) -> Result<(), ContainerError>;
}

/// Published reallyme-crypto point-validation adapter for NIST/Ed25519/X25519.
pub struct CryptoPeerKeyValidator;
impl PeerKeyValidator for CryptoPeerKeyValidator {
    fn validate(
        &self,
        curve: PeerCurve,
        usage: PeerKeyUsage,
        public_material: &[u8],
    ) -> Result<(), ContainerError> {
        use crate::iso18013::Iso18013SignatureCurve as Curve;
        use reallyme_crypto::core::Algorithm;
        // Inspection has already checked usage family and key parameter policy.
        super::inspect_key::check_usage(curve, usage)?;
        let algorithm = match curve {
            PeerCurve::Named(Curve::P256) => Algorithm::P256,
            PeerCurve::Named(Curve::P384) => Algorithm::P384,
            PeerCurve::Named(Curve::P521) => Algorithm::P521,
            PeerCurve::Named(Curve::Ed25519) => Algorithm::Ed25519,
            PeerCurve::X25519 => Algorithm::X25519,
            _ => return Err(super::ContainerErrorReason::Provider.into()),
        };
        crate::key::validate_public_key(algorithm, public_material).map_err(Into::into)
    }
}
