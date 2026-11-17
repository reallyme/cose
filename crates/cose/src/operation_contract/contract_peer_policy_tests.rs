// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, hex, keys, reason, success};
use crate::api::contract::{
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
    CoseAgreementEc2EncodingPolicy, CoseAgreementKeyParseRequest, CoseAgreementKeyPolicy,
    CoseAgreementOptionalParameters, CoseNamedCurve, CosePeerKeyPurpose, CosePeerKeyRequest,
    CoseProviderKind, CoseSignatureSuite,
};
use crate::containers::{
    inspect_peer_key, AgreementEc2EncodingPolicy, AgreementKey, AgreementKeyPolicy,
    AgreementKeyProvider, ContainerError, ContainerErrorReason as Reason,
    CryptoAgreementKeyProvider, CryptoPeerKeyValidator, OptionalKeyPolicy, PeerCurve, PeerKeyUsage,
    SignatureSuite,
};
use crate::iso18013::{Iso18013SignatureAlgorithm, Iso18013SignatureCurve};
use crate::CoseError;
use ciborium::value::Value;
use core::cell::Cell;
use zeroize::Zeroizing;

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

fn selected() -> Result<SignatureSuite, CoseError> {
    SignatureSuite::iso(
        Iso18013SignatureAlgorithm::Es256,
        Iso18013SignatureCurve::P256,
    )
}

fn key(extra: &[(i64, Value)]) -> Result<Vec<u8>, CoseError> {
    let case = keys()?
        .into_iter()
        .find(|v| v.curve == 1)
        .ok_or(Reason::Key)?;
    let Value::Map(mut params) =
        ciborium::de::from_reader(hex(&case.key).as_slice()).map_err(|_| Reason::Malformed)?
    else {
        return Err(Reason::Malformed.into());
    };
    params.extend(
        extra
            .iter()
            .map(|(label, value)| (int(*label), value.clone())),
    );
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&Value::Map(params), &mut encoded).map_err(|_| Reason::Malformed)?;
    Ok(encoded)
}

struct CountedProvider(Cell<usize>);

impl AgreementKeyProvider for CountedProvider {
    fn normalize_public_key(
        &self,
        curve: PeerCurve,
        public_material: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
        self.0
            .set(self.0.get().checked_add(1).ok_or(Reason::Limit)?);
        CryptoAgreementKeyProvider.normalize_public_key(curve, public_material)
    }
}

fn check(
    encoded: &[u8],
    usage: PeerKeyUsage,
    optional: OptionalKeyPolicy,
    expected: Option<Reason>,
) -> Result<(), CoseError> {
    let native = inspect_peer_key(encoded, usage, optional);
    assert_eq!(
        native.as_ref().err().copied().map(CoseError::reason),
        expected
    );
    if let Ok(key) = native {
        assert_eq!(key.original_cose_key(), encoded);
        key.validate(&CryptoPeerKeyValidator)?;
    }
    let (purpose, suite) = match usage {
        PeerKeyUsage::Signature(suite) => (
            CosePeerKeyPurpose::Signature,
            field(CoseSignatureSuite::from(suite)),
        ),
        PeerKeyUsage::Agreement => (CosePeerKeyPurpose::Agreement, Default::default()),
        PeerKeyUsage::HpkeRecipient => (CosePeerKeyPurpose::HpkeRecipient, Default::default()),
    };
    for validate in [false, true] {
        let input = Box::new(CosePeerKeyRequest {
            cose_key: encoded.to_vec().into(),
            purpose: purpose.into(),
            signature_suite: suite.clone(),
            optional_parameters: CoseAgreementOptionalParameters::from(optional).into(),
            capability: Default::default(),
        });
        let response = codec_parity(if validate {
            Operation::PeerKeyValidate(input)
        } else {
            Operation::PeerKeyInspect(input)
        })?;
        if let Some(expected) = expected {
            assert_eq!(reason(&response), expected);
        } else {
            let branch = success(response);
            let output = match &branch {
                Branch::PeerKeyInspect(output) | Branch::PeerKeyValidate(output) => output,
                _ => return Err(Reason::Malformed.into()),
            };
            assert_eq!(output.cose_key, encoded);
            assert_eq!(output.validated, validate);
        }
    }
    if usage == PeerKeyUsage::Agreement {
        let provider = CountedProvider(Cell::new(0));
        let result = AgreementKey::from_slice(
            encoded,
            AgreementKeyPolicy {
                allowed_curves: &[PeerCurve::P256],
                optional_parameters: optional,
                ec2_encoding: AgreementEc2EncodingPolicy::FullCoordinatesOnly,
            },
            &provider,
        );
        assert_eq!(
            result.as_ref().err().copied().map(CoseError::reason),
            expected
        );
        if let Ok(key) = result {
            assert_eq!(key.original_cose_key(), encoded);
            assert_eq!(provider.0.get(), 1);
        } else {
            assert_eq!(provider.0.get(), 0);
        }
        let input = CoseAgreementKeyParseRequest {
            cose_key: encoded.to_vec().into(),
            policy: field(CoseAgreementKeyPolicy {
                allowed_curves: vec![CoseNamedCurve::P256.into()].into(),
                optional_parameters: CoseAgreementOptionalParameters::from(optional).into(),
                ec2_encoding: CoseAgreementEc2EncodingPolicy::FullCoordinatesOnly.into(),
            }),
            capability: super::support::capability(0, CoseProviderKind::AgreementKeyNormalizer),
        };
        let response = codec_parity(Operation::AgreementKeyParse(Box::new(input)))?;
        if let Some(expected) = expected {
            assert_eq!(reason(&response), expected);
        } else {
            let Branch::AgreementKeyParse(parsed) = &success(response) else {
                return Err(Reason::Malformed.into());
            };
            assert_eq!(parsed.cose_key, encoded);
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn iso_peer_enforces_exact_algorithms_and_operation_roles() -> Result<(), CoseError> {
    let selected = selected()?;
    for optional in [OptionalKeyPolicy::Cose, OptionalKeyPolicy::IsoPeer] {
        for usage in [
            PeerKeyUsage::Signature(selected),
            PeerKeyUsage::Agreement,
            PeerKeyUsage::HpkeRecipient,
        ] {
            check(&key(&[])?, usage, optional, None)?;
            for algorithm in [-7, -9, -35, -8] {
                // ESP256 cannot replace ES256 even though both use P-256.
                let permitted = matches!(usage, PeerKeyUsage::Signature(_)) && algorithm == -7;
                check(
                    &key(&[(3, int(algorithm))])?,
                    usage,
                    optional,
                    if permitted { None } else { Some(Reason::Key) },
                )?;
            }
            for operations in [
                vec![2],
                vec![1, 2],
                vec![1],
                vec![7],
                vec![8],
                vec![7, 8],
                vec![2, 7],
                vec![7, 7],
                vec![],
            ] {
                let permitted = match usage {
                    PeerKeyUsage::Signature(_) => operations == [2] || operations == [1, 2],
                    _ => operations == [7] || operations == [8] || operations == [7, 8],
                };
                check(
                    &key(&[(4, Value::Array(operations.into_iter().map(int).collect()))])?,
                    usage,
                    optional,
                    if permitted { None } else { Some(Reason::Key) },
                )?;
            }
            // Regression: a signing-only ES256 key cannot become an agreement
            // key, or pass public signature import without verify permission.
            check(
                &key(&[(3, int(-7)), (4, Value::Array(vec![int(1)]))])?,
                usage,
                optional,
                Some(Reason::Key),
            )?;
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn iso_peer_rejects_malformed_known_optional_parameter_types() -> Result<(), CoseError> {
    for optional in [OptionalKeyPolicy::Cose, OptionalKeyPolicy::IsoPeer] {
        for usage in [
            PeerKeyUsage::Signature(selected()?),
            PeerKeyUsage::Agreement,
            PeerKeyUsage::HpkeRecipient,
        ] {
            for (label, malformed) in [
                (3, Value::Bytes(vec![0x26])),
                (3, Value::Bool(false)),
                (3, Value::Null),
                (3, Value::Float(0.0)),
                (3, Value::Array(vec![])),
                (3, Value::Map(vec![])),
                (4, int(7)),
                (4, Value::Bytes(vec![7])),
                (4, Value::Bool(false)),
                (4, Value::Null),
                (4, Value::Float(0.0)),
                (4, Value::Map(vec![])),
                (4, Value::Array(vec![Value::Text("verify".into())])),
                (4, Value::Array(vec![Value::Bool(true)])),
                (4, Value::Array(vec![Value::Float(2.0)])),
                (5, int(0)),
                (5, Value::Text("iv".into())),
                (5, Value::Bool(false)),
                (5, Value::Null),
                (5, Value::Float(0.0)),
                (5, Value::Array(vec![])),
                (5, Value::Map(vec![])),
            ] {
                check(
                    &key(&[(label, malformed)])?,
                    usage,
                    optional,
                    Some(Reason::Malformed),
                )?;
            }
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn iso_peer_retains_unknown_parameters_and_well_typed_base_iv() -> Result<(), CoseError> {
    for usage in [
        PeerKeyUsage::Signature(selected()?),
        PeerKeyUsage::Agreement,
        PeerKeyUsage::HpkeRecipient,
    ] {
        let original = inspect_peer_key(&key(&[])?, usage, OptionalKeyPolicy::IsoPeer)?;
        for iv in [vec![], vec![0xa5; 12]] {
            let encoded = key(&[(5, Value::Bytes(iv)), (99, Value::Null)])?;
            check(&encoded, usage, OptionalKeyPolicy::IsoPeer, None)?;
            let imported = inspect_peer_key(&encoded, usage, OptionalKeyPolicy::IsoPeer)?;
            assert_eq!(imported.public_material(), original.public_material());
            check(&encoded, usage, OptionalKeyPolicy::Cose, Some(Reason::Key))?;
        }
        check(
            &key(&[(99, Value::Null), (99, Value::Null)])?,
            usage,
            OptionalKeyPolicy::IsoPeer,
            Some(Reason::Duplicate),
        )?;
        check(
            &key(&[(-4, Value::Bytes(vec![0x42; 32]))])?,
            usage,
            OptionalKeyPolicy::IsoPeer,
            Some(Reason::Key),
        )?;
        check(
            &key(&[(0, Value::Null)])?,
            usage,
            OptionalKeyPolicy::IsoPeer,
            Some(Reason::Key),
        )?;
    }
    Ok(())
}

// Splice raw bytes rather than using a value encoder, which would normalize
// overlong simple values and could hide the exact encoding under test.
fn replace_y(encoded: &[u8], replacement: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    use reallyme_codec::cbor::general::{frame_exact, LengthPolicy, Limits};
    let frame = frame_exact(encoded, Limits::default(), LengthPolicy::DefiniteOnly)
        .map_err(|_| CoseError::Cbor)?;
    let mut children = frame.children().map_err(|_| CoseError::Cbor)?;
    while let Some(label) = children.next() {
        let label = label.map_err(|_| CoseError::Cbor)?;
        let start = frame
            .header()
            .received_bytes()
            .len()
            .checked_add(children.consumed_bytes().len())
            .ok_or(CoseError::ResourceLimitExceeded)?;
        let value = children
            .next()
            .ok_or(CoseError::Cbor)?
            .map_err(|_| CoseError::Cbor)?;
        if label.integer().map_err(|_| CoseError::Cbor)?.to_i128() != -3 {
            continue;
        }
        let end = start
            .checked_add(value.received_bytes().len())
            .ok_or(CoseError::ResourceLimitExceeded)?;
        let size = encoded
            .len()
            .checked_sub(value.received_bytes().len())
            .and_then(|len| len.checked_add(replacement.len()))
            .ok_or(CoseError::ResourceLimitExceeded)?;
        let mut changed = Zeroizing::new(Vec::new());
        changed
            .try_reserve_exact(size)
            .map_err(|_| CoseError::ResourceLimitExceeded)?;
        changed.extend_from_slice(encoded.get(..start).ok_or(CoseError::Cbor)?);
        changed.extend_from_slice(replacement);
        changed.extend_from_slice(encoded.get(end..).ok_or(CoseError::Cbor)?);
        return Ok(changed);
    }
    Err(CoseError::InvalidFormat)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn peer_and_agreement_y_require_exact_booleans_in_every_transport() -> Result<(), CoseError> {
    let baseline = key(&[])?;
    let signature = PeerKeyUsage::Signature(selected()?);
    for optional in [OptionalKeyPolicy::Cose, OptionalKeyPolicy::IsoPeer] {
        for valid in [b"\xf4".as_slice(), b"\xf5".as_slice()] {
            check(&replace_y(&baseline, valid)?, signature, optional, None)?;
        }
        for (replacement, expected) in [
            (b"\xf9\x00\x14".as_slice(), Reason::Key),
            (b"\xf9\x00\x15".as_slice(), Reason::Key),
            (b"\xfa\x00\x00\x00\x14".as_slice(), Reason::Key),
            (b"\xfa\x00\x00\x00\x15".as_slice(), Reason::Key),
            (
                b"\xfb\x00\x00\x00\x00\x00\x00\x00\x14".as_slice(),
                Reason::Key,
            ),
            (
                b"\xfb\x00\x00\x00\x00\x00\x00\x00\x15".as_slice(),
                Reason::Key,
            ),
            (b"\xf8\x14".as_slice(), Reason::Malformed),
            (b"\xf8\x15".as_slice(), Reason::Malformed),
            (b"\x14".as_slice(), Reason::Key),
            (b"\x15".as_slice(), Reason::Key),
            (b"\xf6".as_slice(), Reason::Key),
            (b"\xf7".as_slice(), Reason::Key),
            (b"\xc0\xf4".as_slice(), Reason::Key),
            (b"\xc0\xf5".as_slice(), Reason::Key),
            (b"\x80".as_slice(), Reason::Key),
            (b"\xa0".as_slice(), Reason::Key),
        ] {
            let encoded = replace_y(&baseline, replacement)?;
            for usage in [signature, PeerKeyUsage::Agreement] {
                check(&encoded, usage, optional, Some(expected))?;
            }
        }
    }
    Ok(())
}
