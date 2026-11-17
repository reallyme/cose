// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, hex, reason, success};
use crate::api::contract::{
    __buffa::oneof::{
        cose_key_set_entry::Outcome, cose_operation_request::Operation,
        cose_operation_result::Result as Branch,
    },
    CoseKeySetCreateRequest, CoseKeySetKeyType as Kind, CoseKeySetParseRequest, CoseKeySetPolicy,
    CoseKeySetProjection as Projection,
};
use crate::CoseError;
use buffa::Message;

fn policy(projection: Projection) -> CoseKeySetPolicy {
    CoseKeySetPolicy {
        projection: projection.into(),
        allowed_key_types: vec![
            Kind::Okp.into(),
            Kind::Ec2.into(),
            Kind::Rsa.into(),
            Kind::Symmetric.into(),
            Kind::Akp.into(),
        ]
        .into(),
    }
}

fn rfc_key() -> Vec<u8> {
    // RFC 9052 C.7.1, first public key, in its published unsorted map order.
    let mut key = hex("a5200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c0102025824");
    key.extend_from_slice(b"meriadoc.brandybuck@buckland.example");
    key
}

fn set(keys: &[&[u8]]) -> Result<Vec<u8>, CoseError> {
    let length = u8::try_from(keys.len()).map_err(|_| CoseError::ResourceLimitExceeded)?;
    if length > 23 {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let mut encoded = vec![0x80 | length];
    for key in keys {
        encoded.extend_from_slice(key);
    }
    Ok(encoded)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn key_set_roundtrips_rfc_public_map_with_exact_unsorted_bytes_and_projections(
) -> Result<(), CoseError> {
    let key = rfc_key();
    let expected = set(&[&key])?;
    for projection in [Projection::SensitiveStorage, Projection::PublicParameters] {
        let request = CoseKeySetCreateRequest {
            keys: vec![key.clone().into()].into(),
            policy: field(policy(projection)),
        };
        let response = success(codec_parity(Operation::KeySetCreate(Box::new(request)))?);
        let Branch::KeySetCreate(created) = &response else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(created.key_count, 1);
        if projection == Projection::SensitiveStorage {
            assert_eq!(created.encoded, expected);
        }
        let response = success(codec_parity(Operation::KeySetParse(Box::new(
            CoseKeySetParseRequest {
                encoded: created.encoded.clone(),
                policy: field(policy(projection)),
            },
        )))?);
        let Branch::KeySetParse(parsed) = &response else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(parsed.entries.len(), 1);
        let Some(Outcome::Key(member)) = parsed
            .entries
            .first()
            .and_then(|entry| entry.outcome.as_ref())
        else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(member.key_type.as_known(), Some(Kind::Ec2));
        if projection == Projection::SensitiveStorage {
            assert_eq!(member.encoded, key);
        } else {
            // Public projection is an explicit new encoding, accepted by the
            // existing cryptographic importer. Parsing alone grants no trust.
            let public = crate::cose_key_from_slice(&member.encoded)?;
            let material = crate::cose_key_to_public_bytes(&public)?;
            assert_eq!(material.len(), 33);
            assert!(!member
                .encoded
                .windows(b"meriadoc".len())
                .any(|bytes| bytes == b"meriadoc"));
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn key_set_processes_bad_unknown_and_disallowed_members_independently() -> Result<(), CoseError> {
    let good = rfc_key();
    let duplicate = hex("a201020102");
    let unknown = hex("a1011863");
    let wrong = hex("182a");
    let rsa = hex("a30103204301020321420103");
    let symmetric = hex("a201042043010203");
    let encoded = set(&[&good, &duplicate, &unknown, &wrong, &rsa, &symmetric])?;
    for projection in [Projection::SensitiveStorage, Projection::PublicParameters] {
        let response = success(codec_parity(Operation::KeySetParse(Box::new(
            CoseKeySetParseRequest {
                encoded: encoded.clone().into(),
                policy: field(policy(projection)),
            },
        )))?);
        let Branch::KeySetParse(result) = &response else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(result.entries.len(), 6);
        for (index, expected) in [
            None,
            Some(CoseError::DuplicateMapLabel),
            Some(CoseError::UnsupportedAlgorithm),
            Some(CoseError::InvalidFormat),
            None,
            if projection == Projection::SensitiveStorage {
                None
            } else {
                Some(CoseError::InvalidKeyMaterial)
            },
        ]
        .into_iter()
        .enumerate()
        {
            let entry = result.entries.get(index).ok_or(CoseError::InvalidFormat)?;
            assert_eq!(usize::try_from(entry.source_index).ok(), Some(index));
            if let Some(error) = expected {
                assert!(
                    matches!(entry.outcome.as_ref(), Some(Outcome::Rejected(reason)) if reason.as_known() == Some(error.reason()))
                );
            } else {
                assert!(matches!(entry.outcome.as_ref(), Some(Outcome::Key(_))));
            }
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn key_set_projection_drops_private_parameters_and_opaque_secret_extensions(
) -> Result<(), CoseError> {
    let mut key = rfc_key();
    *key.first_mut().ok_or(CoseError::InvalidFormat)? = 0xa7;
    key.extend_from_slice(b"\x23\x43\x01\x02\x03\x61d\x43\x55\x66\x77");
    let result = success(codec_parity(Operation::KeySetParse(Box::new(
        CoseKeySetParseRequest {
            encoded: set(&[&key])?.into(),
            policy: field(policy(Projection::PublicParameters)),
        },
    )))?);
    let Branch::KeySetParse(parsed) = &result else {
        return Err(CoseError::InvalidFormat);
    };
    let Some(Outcome::Key(member)) = parsed
        .entries
        .first()
        .and_then(|entry| entry.outcome.as_ref())
    else {
        return Err(CoseError::InvalidFormat);
    };
    assert!(!member
        .encoded
        .windows(3)
        .any(|v| v == [0x55, 0x66, 0x77] || v == [1, 2, 3]));
    let owned = crate::cose_key_from_slice(&member.encoded)?;
    assert_eq!(
        crate::cose_key_to_private_bytes(&owned).err(),
        Some(CoseError::MissingKeyMaterial)
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn key_set_boundaries_and_sensitive_clear_are_explicit() -> Result<(), CoseError> {
    for (encoded, expected) in [
        (hex("80"), CoseError::InvalidFormat),
        (hex("9f0102ff"), CoseError::NonCanonicalCbor),
        (hex("81a1010400"), CoseError::Cbor),
        (hex("9841"), CoseError::Cbor),
    ] {
        let response = codec_parity(Operation::KeySetParse(Box::new(CoseKeySetParseRequest {
            encoded: encoded.into(),
            policy: field(policy(Projection::SensitiveStorage)),
        })))?;
        assert_eq!(reason(&response), expected.reason());
    }
    let key = rfc_key();
    for (count, accepted) in [(64_u8, true), (65, false)] {
        let mut encoded = vec![0x98, count];
        for _ in 0..count {
            encoded.extend_from_slice(&key);
        }
        let response = codec_parity(Operation::KeySetParse(Box::new(CoseKeySetParseRequest {
            encoded: encoded.into(),
            policy: field(policy(Projection::SensitiveStorage)),
        })))?;
        if accepted {
            let _ = success(response);
        } else {
            assert_eq!(reason(&response), CoseError::ResourceLimitExceeded.reason());
        }
    }
    for encoded in [vec![0; 1_048_577], {
        // Structurally valid map with one oversized opaque extension.
        let mut member = key.clone();
        *member.first_mut().ok_or(CoseError::InvalidFormat)? = 0xa6;
        member.extend_from_slice(b"\x61z\x59\x40\x00");
        member.resize(member.len() + 16_384, 0);
        set(&[&member])?
    }] {
        let response = codec_parity(Operation::KeySetParse(Box::new(CoseKeySetParseRequest {
            encoded: encoded.into(),
            policy: field(policy(Projection::SensitiveStorage)),
        })))?;
        if let Some(
            crate::api::contract::__buffa::oneof::cose_operation_response_v2::Outcome::Result(_),
        ) = response.outcome.as_ref()
        {
            let Branch::KeySetParse(ref parsed) = success(response) else {
                return Err(CoseError::InvalidFormat);
            };
            assert!(
                matches!(parsed.entries.first().and_then(|v|v.outcome.as_ref()), Some(Outcome::Rejected(reason)) if reason.as_known() == Some(CoseError::ResourceLimitExceeded.reason()))
            );
        } else {
            assert_eq!(reason(&response), CoseError::ResourceLimitExceeded.reason());
        }
    }
    let mut request = CoseKeySetCreateRequest {
        keys: vec![vec![0xa5; 64].into()].into(),
        policy: field(policy(Projection::SensitiveStorage)),
    };
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("165, 165"));
    request.clear();
    assert!(request.keys.is_empty());
    Ok(())
}
