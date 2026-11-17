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

// Splice only the original nil slot. Protected bytes, unprotected map order,
// signature, and detached content remain exactly as in the independent vector.
fn replace_payload_slot(
    encoded: &[u8],
    replacement: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    use reallyme_codec::cbor::general::{frame_exact, LengthPolicy, Limits};

    let frame = frame_exact(encoded, Limits::default(), LengthPolicy::DefiniteOnly)
        .map_err(|_| CoseError::Cbor)?;
    let mut cursor = frame.children().map_err(|_| CoseError::Cbor)?;
    for _ in 0..2 {
        cursor
            .next()
            .ok_or(CoseError::Cbor)?
            .map_err(|_| CoseError::Cbor)?;
    }
    let start = frame
        .header()
        .received_bytes()
        .len()
        .checked_add(cursor.consumed_bytes().len())
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let slot = cursor
        .next()
        .ok_or(CoseError::Cbor)?
        .map_err(|_| CoseError::Cbor)?;
    if slot.simple_value().map_err(|_| CoseError::Cbor)? != 22 {
        return Err(CoseError::InvalidFormat);
    }
    let end = start
        .checked_add(slot.received_bytes().len())
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let size = encoded
        .len()
        .checked_sub(slot.received_bytes().len())
        .and_then(|size| size.checked_add(replacement.len()))
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(size)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    output.extend_from_slice(encoded.get(..start).ok_or(CoseError::Cbor)?);
    output.extend_from_slice(replacement);
    output.extend_from_slice(encoded.get(end..).ok_or(CoseError::Cbor)?);
    Ok(output)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn detached_payload_slot_requires_exact_nil_and_rejects_scalar_substitutions(
) -> Result<(), CoseError> {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/containers.json"))
            .map_err(|_| CoseError::Cbor)?;
    for case in vectors
        .cases
        .iter()
        .filter(|case| matches!(case.id.as_str(), "device" | "reader" | "reader-all"))
    {
        let baseline = input(case)?;
        let selected = super::super::profile_input::suite(&suite(case.algorithm, case.curve)?)?;
        let key = CryptoVerificationKey::new(
            selected,
            Zeroizing::new(hex(&case.public_key)),
            [0x42; 32],
        )?;
        let payload = hex(&case.payload);
        for (slot, preferred, primitive_failure) in [
            (b"\xf6".as_slice(), true, None),
            (
                b"\xf9\x00\x16".as_slice(),
                true,
                Some(CoseError::NonCanonicalCbor),
            ),
            (
                b"\xfa\x00\x00\x00\x16".as_slice(),
                true,
                Some(CoseError::NonCanonicalCbor),
            ),
            (
                b"\xfb\x00\x00\x00\x00\x00\x00\x00\x16".as_slice(),
                true,
                Some(CoseError::NonCanonicalCbor),
            ),
            // Invalid overlong simple encoding must not normalize to null.
            (b"\xf8\x16".as_slice(), false, None),
            (b"\xf4".as_slice(), true, None),
            (b"\xf5".as_slice(), true, None),
            (b"\xf7".as_slice(), true, None),
            (b"\x16".as_slice(), true, None),
            (b"\xc0\xf6".as_slice(), true, None),
            (b"\x80".as_slice(), true, None),
            (b"\xa0".as_slice(), true, None),
        ] {
            let mut encoded = replace_payload_slot(&baseline.encoded, slot)?;
            let preflight = crate::containers::validate_preferred_cbor(&encoded);
            if preferred {
                preflight?;
            } else {
                assert_eq!(
                    preflight.err().map(CoseError::reason),
                    Some(Reason::Malformed)
                );
            }
            let native = crate::containers::verify_container(
                crate::containers::ContainerVerifyRequest {
                    encoded: &encoded,
                    content: crate::containers::ContainerContent::Detached(&payload),
                    external_aad: &[],
                    policy: super::super::profile_input::policy(baseline.policy.as_option())?,
                    allowed_suites: &[selected],
                    limits: crate::containers::ContainerLimits::default(),
                },
                VerificationSource::Key(&key),
            );
            let valid_nil = slot == b"\xf6";
            if valid_nil {
                let receipt = native?;
                assert_eq!(receipt.encoded(), encoded.as_slice());
                assert_eq!(receipt.protected_headers(), hex(&case.protected));
                assert_eq!(receipt.payload(), payload);
            } else {
                assert_eq!(
                    native.err().map(|error| error.reason()),
                    Some(Reason::Malformed)
                );
                if let Some(expected) = primitive_failure {
                    assert_eq!(
                        crate::cose_verify1_detached(&encoded, &payload, |_, _| Some(hex(
                            &case.public_key
                        )))
                        .err(),
                        Some(expected)
                    );
                }
            }
            let mut changed = baseline.clone();
            changed.encoded = core::mem::take(&mut *encoded).into();
            let response =
                super::support::codec_parity(Operation::ContainerVerify(Box::new(changed)))?;
            if valid_nil {
                let Branch::ContainerVerify(verified) = &success(response) else {
                    return Err(CoseError::InvalidFormat);
                };
                assert_eq!(verified.payload, payload);
                assert_eq!(verified.encoded, baseline.encoded);
            } else {
                assert_eq!(reason(&response), CoseErrorReason::Malformed);
            }
        }
    }
    Ok(())
}
