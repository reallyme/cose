// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate generated result metadata; response framing does not grant trust.

use super::profile_input::{iso_suite, peer_curve, policy, suite};
use super::profile_input::{SHA256_DIGEST_BYTES, VERIFICATION_CONTEXT_BYTES};
use crate::containers::normalize_agreement_key::{
    SEC1_COMPRESSED_EVEN, SEC1_COMPRESSED_ODD, SEC1_PREFIX_BYTES, SEC1_UNCOMPRESSED,
};
use crate::containers::{
    inspect_peer_key_operation, OptionalKeyPolicy, PeerKeyUsage, PeerPointEncoding,
};
use crate::wire::{
    CoseAgreementKeyResult, CoseContainerProfile, CoseContainerVerifyResult,
    CoseEndEntityIntegrity, CoseIsoSign1VerifyResult, CoseMac0VerifyResult, CosePeerKeyPurpose,
    CosePeerKeyResult, CoseSuiteInfoResult, CoseWorkingKey, CoseX5ChainHeaderPlacement,
};
use reallyme_crypto::operations::constant_time::equal;

pub(crate) fn agreement(value: &CoseAgreementKeyResult) -> bool {
    if value.curve.as_known().is_none() {
        return false;
    }
    let Ok(key) = inspect_peer_key_operation(
        &value.cose_key,
        PeerKeyUsage::Agreement,
        OptionalKeyPolicy::IsoPeer,
    ) else {
        return false;
    };
    if key.curve().identifier() != i64::from(value.curve.to_i32())
        || super::profile_result::encoding(key.point_encoding())
            != match value.point_encoding.as_known() {
                Some(v) => v,
                None => return false,
            }
    {
        return false;
    }
    let public = &value.public_key;
    if let Some(width) = key.curve().coordinate_bytes() {
        let Some(size) = width
            .checked_mul(2)
            .and_then(|n| n.checked_add(SEC1_PREFIX_BYTES))
        else {
            return false;
        };
        if public.len() != size || public.first() != Some(&SEC1_UNCOMPRESSED) {
            return false;
        }
        if key.point_encoding() == PeerPointEncoding::Ec2Coordinates {
            return equal(key.public_material(), public);
        }
        let Some(end) = width.checked_add(SEC1_PREFIX_BYTES) else {
            return false;
        };
        let (Some(x), Some(original_x), Some(last), Some(prefix)) = (
            public.get(SEC1_PREFIX_BYTES..end),
            key.public_material().get(SEC1_PREFIX_BYTES..),
            public.last(),
            key.public_material().first(),
        ) else {
            return false;
        };
        equal(x, original_x)
            && *prefix
                == if last & 1 == 0 {
                    SEC1_COMPRESSED_EVEN
                } else {
                    SEC1_COMPRESSED_ODD
                }
    } else {
        equal(key.public_material(), public)
    }
}

pub(crate) fn peer(value: &CosePeerKeyResult) -> bool {
    let usage = match value.purpose.as_known() {
        Some(CosePeerKeyPurpose::Signature) => {
            let Some(s) = value.signature_suite.as_option() else {
                return false;
            };
            let Ok(s) = suite(s) else {
                return false;
            };
            PeerKeyUsage::Signature(s)
        }
        Some(CosePeerKeyPurpose::Agreement) if value.signature_suite.as_option().is_none() => {
            PeerKeyUsage::Agreement
        }
        Some(CosePeerKeyPurpose::HpkeRecipient) if value.signature_suite.as_option().is_none() => {
            PeerKeyUsage::HpkeRecipient
        }
        _ => return false,
    };
    let Ok(key) = inspect_peer_key_operation(&value.cose_key, usage, OptionalKeyPolicy::IsoPeer)
    else {
        return false;
    };
    peer_curve(value.curve).is_ok_and(|curve| curve == key.curve())
        && value.point_encoding.as_known()
            == Some(super::profile_result::encoding(key.point_encoding()))
        && equal(key.public_material(), &value.public_key)
}

pub(crate) fn mac0(value: &CoseMac0VerifyResult) -> bool {
    matches!(
        value.algorithm.as_known(),
        Some(
            crate::wire::CoseMacAlgorithm::Hmac25664
                | crate::wire::CoseMacAlgorithm::Hmac256256
                | crate::wire::CoseMacAlgorithm::Hmac384384
                | crate::wire::CoseMacAlgorithm::Hmac512512
        )
    ) && value.algorithm.as_known().is_some()
        && !value.protected_headers.is_empty()
        && value.protected_headers.len() <= crate::limits::MAX_COSE_MAC0_BYTES
        && value
            .protected_kid
            .as_ref()
            .is_none_or(|kid| kid.len() <= crate::limits::MAX_COSE_MAC0_BYTES)
        && crate::containers::validate_preferred_cbor_operation(&value.protected_headers).is_ok()
}

pub(crate) fn iso(value: &CoseIsoSign1VerifyResult) -> bool {
    value
        .suite
        .as_option()
        .is_some_and(|s| iso_suite(s).is_ok())
        && !value.protected_headers.is_empty()
        && value.protected_headers.len() <= crate::limits::MAX_COSE_SIGN1_ENCODED_BYTES
        && value
            .attached_payload
            .as_ref()
            .is_none_or(|payload| payload.len() <= crate::limits::MAX_DETACHED_PAYLOAD_BYTES)
        && value
            .protected_kid
            .as_ref()
            .is_none_or(|kid| kid.len() <= crate::limits::MAX_COSE_MAC0_BYTES)
}

pub(crate) fn working_key(value: &CoseWorkingKey) -> bool {
    value
        .suite
        .as_option()
        .is_some_and(|s| iso_suite(s).is_ok() || suite(s).is_ok())
        && !value.public_key.is_empty()
        && value.public_key.len() <= crate::limits::MAX_COSE_KEY_BYTES
        && value.context_id.len() == VERIFICATION_CONTEXT_BYTES
}

pub(crate) fn container(value: &CoseContainerVerifyResult) -> bool {
    if value.encoded.is_empty()
        || value.encoded.len() > crate::limits::MAX_COSE_SIGN1_ENCODED_BYTES
        || value.protected_headers.len() > crate::limits::MAX_COSE_SIGN1_ENCODED_BYTES
        || value.unprotected_headers.len() > crate::limits::MAX_COSE_SIGN1_ENCODED_BYTES
        || value.payload.len() > crate::limits::MAX_DETACHED_PAYLOAD_BYTES
        || policy(value.policy.as_option()).is_err()
        || !value.key.as_option().is_some_and(working_key)
        || value
            .certificate_sha256
            .as_ref()
            .is_some_and(|digest| digest.len() != SHA256_DIGEST_BYTES)
    {
        return false;
    }
    let placement = value.chain_placement.as_known();
    match value.end_entity_integrity.as_known() {
        Some(CoseEndEntityIntegrity::ExternalKey) => {
            placement == Some(CoseX5ChainHeaderPlacement::Unspecified)
                && !value.protected_thumbprint
                && value.certificate_sha256.is_none()
        }
        Some(CoseEndEntityIntegrity::ProtectedChain) => {
            placement == Some(CoseX5ChainHeaderPlacement::Protected)
                && !value.protected_thumbprint
                && value.certificate_sha256.is_some()
        }
        Some(CoseEndEntityIntegrity::ProtectedThumbprint) => {
            placement.is_some() && value.protected_thumbprint && value.certificate_sha256.is_some()
        }
        Some(CoseEndEntityIntegrity::IsoUnprotectedChain) => {
            placement == Some(CoseX5ChainHeaderPlacement::Unprotected)
                && !value.protected_thumbprint
                && value.certificate_sha256.is_some()
                && value
                    .policy
                    .as_option()
                    .is_some_and(|p| p.profile.as_known() != Some(CoseContainerProfile::Rfc9360))
        }
        _ => false,
    }
}

pub(crate) fn suite_info(value: &CoseSuiteInfoResult) -> bool {
    let Some(s) = value.suite.as_option() else {
        return false;
    };
    let curve = iso_suite(s)
        .map(|s| s.curve())
        .or_else(|_| suite(s).map(|s| s.curve()));
    let Ok(curve) = curve else {
        return false;
    };
    u64::try_from(curve.signature_length().unwrap_or_default()).ok() == Some(value.signature_bytes)
        && u64::try_from(curve.coordinate_length().unwrap_or_default()).ok()
            == Some(value.coordinate_bytes)
        && u64::try_from(curve.okp_public_length().unwrap_or_default()).ok()
            == Some(value.okp_public_bytes)
        && value.signature_bytes != 0
}
