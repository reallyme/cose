// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity_with_providers, field, hex, reason, success, suite};
use crate::api::{
    contract::{
        __buffa::oneof::{
            cose_operation_request::Operation, cose_operation_result::Result as Branch,
        },
        CoseContainerPolicy, CoseContainerProfile, CoseContainerPurpose,
        CoseContainerVerifyRequest, CoseContentMode, CoseEnvelopePolicy, CoseErrorReason,
        CoseKeySource, CoseWorkingKey,
    },
    OperationProviders,
};
use crate::containers::{
    CertificateHeaders, CertificateSelection, CertificateValidator, ContainerError,
    ContainerErrorReason as Reason, CryptoVerificationKey, VerificationSource,
};
use crate::CoseError;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Vectors {
    certificate_a: String,
    certificate_b: String,
    certificate_a_sha256: String,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    id: String,
    algorithm: i64,
    curve: i64,
    public_key: String,
    protected: String,
    unprotected: String,
    payload: String,
    encoded: String,
}

struct Trust<'a> {
    key: &'a CryptoVerificationKey,
    certificate: &'a [u8],
}
impl CertificateValidator for Trust<'_> {
    fn resolve(
        &self,
        _: &CertificateHeaders<'_>,
        _: i64,
    ) -> Result<CertificateSelection<'_>, ContainerError> {
        Ok(CertificateSelection {
            key: self.key,
            end_entity_der: self.certificate,
        })
    }
}
impl OperationProviders for Trust<'_> {
    fn certificate_validator(
        &self,
        handle: u64,
    ) -> Result<&dyn CertificateValidator, ContainerError> {
        if handle != 1 {
            return Err(Reason::Provider.into());
        }
        Ok(self)
    }
}

fn policy(case: &Case) -> CoseContainerPolicy {
    let purpose = match case.id.as_str() {
        "device" => CoseContainerPurpose::DeviceAuthentication,
        "reader" => CoseContainerPurpose::ReaderAuthentication,
        "reader-all" => CoseContainerPurpose::ReaderAuthenticationAll,
        "revocation" => CoseContainerPurpose::MsoRevocation,
        "vical" => CoseContainerPurpose::Vical,
        "rical" => CoseContainerPurpose::Rical,
        "strict-modern" => CoseContainerPurpose::Generic,
        _ => CoseContainerPurpose::IssuerMso,
    };
    CoseContainerPolicy {
        profile: match case.id.as_str() {
            "issuer-2021" => CoseContainerProfile::Iso2021,
            "strict-modern" => CoseContainerProfile::Rfc9360,
            _ => CoseContainerProfile::IsoEdition2Dis,
        }
        .into(),
        purpose: purpose.into(),
        envelope: CoseEnvelopePolicy::Untagged.into(),
    }
}

fn input(case: &Case) -> Result<CoseContainerVerifyRequest, CoseError> {
    let detached = matches!(case.id.as_str(), "device" | "reader" | "reader-all");
    Ok(CoseContainerVerifyRequest {
        encoded: hex(&case.encoded).into(),
        content_mode: if detached {
            CoseContentMode::Detached
        } else {
            CoseContentMode::Attached
        }
        .into(),
        detached_payload: if detached {
            hex(&case.payload).into()
        } else {
            Vec::new().into()
        },
        external_aad: Vec::new().into(),
        policy: field(policy(case)),
        allowed_suites: vec![suite(case.algorithm, case.curve)?].into(),
        key_source: if detached {
            CoseKeySource::Direct
        } else {
            CoseKeySource::Certificates
        }
        .into(),
        key: if detached {
            field(CoseWorkingKey {
                suite: field(suite(case.algorithm, case.curve)?),
                public_key: hex(&case.public_key).into(),
                context_id: vec![0x42; 32].into(),
            })
        } else {
            Default::default()
        },
        capability: super::support::capability(
            if detached { 0 } else { 1 },
            crate::api::contract::CoseProviderKind::CertificateValidator,
        ),
        limits: Default::default(),
    })
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn all_independent_container_receipts_match_borrowed_rust_and_all_codecs() -> Result<(), CoseError>
{
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/containers.json"))
            .map_err(|_| CoseError::Cbor)?;
    assert_eq!(vectors.cases.len(), 10);
    let certificate = hex(&vectors.certificate_a);
    for case in &vectors.cases {
        let wire = input(case)?;
        let selected = super::super::profile_input::suite(&suite(case.algorithm, case.curve)?)
            .map_err(|_| CoseError::UnsupportedAlgorithm)?;
        let key =
            CryptoVerificationKey::new(selected, Zeroizing::new(hex(&case.public_key)), [0x42; 32])
                .map_err(|_| CoseError::InvalidKeyMaterial)?;
        let ports = Trust {
            key: &key,
            certificate: &certificate,
        };
        let payload = hex(&case.payload);
        let native = crate::containers::verify_container(
            crate::containers::ContainerVerifyRequest {
                encoded: &wire.encoded,
                content: if wire.content_mode.as_known() == Some(CoseContentMode::Detached) {
                    crate::containers::ContainerContent::Detached(&payload)
                } else {
                    crate::containers::ContainerContent::Attached
                },
                external_aad: &[],
                policy: super::super::profile_input::policy(wire.policy.as_option())
                    .map_err(|_| CoseError::InvalidFormat)?,
                allowed_suites: &[selected],
                limits: crate::containers::ContainerLimits::default(),
            },
            if wire.capability.as_option().is_none() {
                VerificationSource::Key(&key)
            } else {
                VerificationSource::Certificates(&ports)
            },
        )
        .map_err(|_| CoseError::InvalidSignature)?;
        let Branch::ContainerVerify(value) = &mut success(codec_parity_with_providers(
            Operation::ContainerVerify(Box::new(wire.clone())),
            &ports,
        )?) else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(value.encoded, native.encoded());
        assert_eq!(value.protected_headers, native.protected_headers());
        assert_eq!(value.protected_headers, hex(&case.protected));
        assert_eq!(value.unprotected_headers, native.unprotected_headers());
        assert_eq!(value.unprotected_headers, hex(&case.unprotected));
        assert_eq!(value.payload, native.payload());
        assert_eq!(value.payload, payload);
        let actual = value.key.as_option().ok_or(CoseError::InvalidFormat)?;
        assert_eq!(actual.public_key, native.verification_public_key());
        assert_eq!(actual.context_id, native.verification_context());
        assert_eq!(
            actual
                .suite
                .as_option()
                .ok_or(CoseError::InvalidFormat)?
                .registration
                .to_i32(),
            buffa::Enumeration::to_i32(&crate::api::contract::CoseSignatureAlgorithm::from(
                crate::CoseSignatureAlgorithm::from_identifier(case.algorithm)?
            ))
        );
        if let Some(digest) = value.certificate_sha256.as_deref() {
            assert_eq!(digest, hex(&vectors.certificate_a_sha256));
        }
        let mut changed = wire;
        *changed.encoded.last_mut().ok_or(CoseError::InvalidFormat)? ^= 1;
        assert_eq!(
            reason(&codec_parity_with_providers(
                Operation::ContainerVerify(Box::new(changed)),
                &ports
            )?),
            CoseErrorReason::Sign1InvalidSignature
        );
        if native.selected_certificate_sha256().is_some() {
            let substituted = hex(&vectors.certificate_b);
            let ports = Trust {
                key: &key,
                certificate: &substituted,
            };
            assert_eq!(
                reason(&codec_parity_with_providers(
                    Operation::ContainerVerify(Box::new(input(case)?)),
                    &ports
                )?),
                CoseErrorReason::ContainerCertificateMismatch
            );
        }
    }
    Ok(())
}
