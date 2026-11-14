// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::agreement_support::{case, cases, ordered, parameters, policy};
use super::support::{assert_error, hex, int, map, value};
use crate::containers::{
    ContainerError, ContainerErrorReason as Reason, OptionalKeyPolicy, PeerCurve, PeerPointEncoding,
};
use crate::key::{
    AgreementEc2EncodingPolicy as EncodingPolicy, AgreementKey, CryptoAgreementKeyProvider,
};
use ciborium::value::Value;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sorted_and_unsorted_keys_keep_exact_bytes_and_equal_validated_points(
) -> Result<(), ContainerError> {
    for id in [1, 2, 3, 4] {
        let case = case(id)?;
        let received = hex(&case.key);
        let mut params = parameters(&case)?;
        params.sort_by_key(|(label, _)| super::support::encode(label.clone()));
        let sorted = map(params);
        assert_ne!(received, sorted);
        let policy = policy(EncodingPolicy::FullCoordinatesOnly);
        let a = AgreementKey::from_slice(&received, policy, &CryptoAgreementKeyProvider)?;
        let b = AgreementKey::from_slice(&sorted, policy, &CryptoAgreementKeyProvider)?;
        assert_eq!(a.original_cose_key(), received);
        assert_eq!(b.original_cose_key(), sorted);
        assert_eq!(a.public_material(), b.public_material());
        assert_eq!(a.public_material(), hex(&case.public));
        assert_eq!(a.curve(), PeerCurve::from_identifier(id)?);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn agreement_construction_emits_only_public_parameters_without_signature_alg(
) -> Result<(), ContainerError> {
    for id in [1, 2, 3, 4] {
        let case = case(id)?;
        let curve = PeerCurve::from_identifier(id)?;
        let encoding = if curve.coordinate_bytes().is_some() {
            PeerPointEncoding::Ec2Coordinates
        } else {
            PeerPointEncoding::Okp
        };
        let policy = policy(EncodingPolicy::FullCoordinatesOnly);
        let key = AgreementKey::from_public_key(
            curve,
            &hex(&case.public),
            encoding,
            policy,
            &CryptoAgreementKeyProvider,
        )?;
        let mut params = parameters(&case)?;
        params.sort_by_key(|(label, _)| super::support::encode(label.clone()));
        assert_eq!(key.original_cose_key(), map(params));
        let Value::Map(params) = value(key.original_cose_key()) else {
            return Err(Reason::Malformed.into());
        };
        assert!(params
            .iter()
            .all(|(label, _)| *label != int(3) && *label != int(4) && *label != int(-4)));
        let decoded =
            AgreementKey::from_slice(key.original_cose_key(), policy, &CryptoAgreementKeyProvider)?;
        assert_eq!(decoded.public_material(), key.public_material());
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn explicit_full_coordinate_policy_cannot_be_repaired_by_normalizing_compression(
) -> Result<(), ContainerError> {
    for id in [1, 2, 3] {
        let case = case(id)?;
        let full = policy(EncodingPolicy::FullCoordinatesOnly);
        let permissive = policy(EncodingPolicy::FullOrCompressed);
        let compressed = hex(&case.compressed);
        assert_error(
            AgreementKey::from_slice(&compressed, full, &CryptoAgreementKeyProvider),
            Reason::Profile,
        );
        let imported =
            AgreementKey::from_slice(&compressed, permissive, &CryptoAgreementKeyProvider)?;
        assert_eq!(imported.point_encoding(), PeerPointEncoding::Ec2YSign);
        assert_eq!(imported.original_cose_key(), compressed);
        assert_eq!(imported.public_material(), hex(&case.public));
        let curve = imported.curve();
        let emitted = AgreementKey::from_public_key(
            curve,
            imported.public_material(),
            PeerPointEncoding::Ec2YSign,
            permissive,
            &CryptoAgreementKeyProvider,
        )?;
        assert_eq!(emitted.original_cose_key(), ordered(&compressed)?);
        assert_error(
            AgreementKey::from_public_key(
                curve,
                imported.public_material(),
                PeerPointEncoding::Ec2YSign,
                full,
                &CryptoAgreementKeyProvider,
            ),
            Reason::Profile,
        );
        // Compressed mathematical input is safe when the emitted wire key has
        // full coordinates; only the wire representation carries the ISO rule.
        let inspected = crate::containers::inspect_peer_key(
            &compressed,
            crate::containers::PeerKeyUsage::Agreement,
            OptionalKeyPolicy::Cose,
        )?;
        let expanded = AgreementKey::from_public_key(
            curve,
            inspected.public_material(),
            PeerPointEncoding::Ec2Coordinates,
            full,
            &CryptoAgreementKeyProvider,
        )?;
        assert_eq!(expanded.point_encoding(), PeerPointEncoding::Ec2Coordinates);
        assert_eq!(expanded.original_cose_key(), ordered(&hex(&case.key))?);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn supplied_agreement_operations_are_distinct_from_signature_operations(
) -> Result<(), ContainerError> {
    for id in [1, 2, 3, 4] {
        let case = case(id)?;
        for ops in [vec![7], vec![8], vec![7, 8], vec![8, 7]] {
            let mut params = parameters(&case)?;
            params.push((int(4), Value::Array(ops.into_iter().map(int).collect())));
            let encoded = map(params);
            let key = AgreementKey::from_slice(
                &encoded,
                policy(EncodingPolicy::FullCoordinatesOnly),
                &CryptoAgreementKeyProvider,
            )?;
            assert_eq!(key.original_cose_key(), encoded);
        }
        for ops in [
            vec![],
            vec![1],
            vec![2],
            vec![7, 2],
            vec![7, 7],
            vec![0],
            vec![-1],
            vec![16],
        ] {
            let mut params = parameters(&case)?;
            params.push((int(4), Value::Array(ops.into_iter().map(int).collect())));
            assert_error(
                AgreementKey::from_slice(
                    &map(params),
                    policy(EncodingPolicy::FullCoordinatesOnly),
                    &CryptoAgreementKeyProvider,
                ),
                Reason::Key,
            );
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn optional_fields_require_explicit_iso_ignore_policy() -> Result<(), ContainerError> {
    let case = case(1)?;
    for (label, optional) in [
        (3, int(-7)),
        (4, Value::Array(vec![int(2)])),
        (42, Value::Null),
    ] {
        let mut params = parameters(&case)?;
        params.push((int(label), optional));
        let encoded = map(params);
        let mut selected = policy(EncodingPolicy::FullCoordinatesOnly);
        assert_error(
            AgreementKey::from_slice(&encoded, selected, &CryptoAgreementKeyProvider),
            Reason::Key,
        );
        selected.optional_parameters = OptionalKeyPolicy::IsoPeer;
        let key = AgreementKey::from_slice(&encoded, selected, &CryptoAgreementKeyProvider)?;
        assert_eq!(key.original_cose_key(), encoded);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn curve_allowlist_and_agreement_family_fail_closed_independently_of_width(
) -> Result<(), ContainerError> {
    for case in cases()? {
        let curve = PeerCurve::from_identifier(case.curve)?;
        let encoded = hex(&case.key);
        let selected = policy(EncodingPolicy::FullCoordinatesOnly);
        let reason = if matches!(case.curve, 6 | 7) {
            Reason::Key
        } else {
            Reason::Provider
        };
        if !matches!(case.curve, 1..=4) {
            assert_error(
                AgreementKey::from_slice(&encoded, selected, &CryptoAgreementKeyProvider),
                reason,
            );
            let encoding = if curve.coordinate_bytes().is_some() {
                PeerPointEncoding::Ec2Coordinates
            } else {
                PeerPointEncoding::Okp
            };
            assert_error(
                AgreementKey::from_public_key(
                    curve,
                    &hex(&case.public),
                    encoding,
                    selected,
                    &CryptoAgreementKeyProvider,
                ),
                reason,
            );
        }
        let mut forbidden = selected;
        forbidden.allowed_curves = &[];
        assert_error(
            AgreementKey::from_slice(&encoded, forbidden, &CryptoAgreementKeyProvider),
            Reason::Limit,
        );
    }
    let mut wrong = parameters(&case(1)?)?;
    for (label, parameter) in &mut wrong {
        if *label == int(-1) {
            *parameter = int(256);
        }
    }
    let selected = crate::containers::AgreementKeyPolicy {
        allowed_curves: &[PeerCurve::from_identifier(1)?],
        ..policy(EncodingPolicy::FullCoordinatesOnly)
    };
    assert_error(
        AgreementKey::from_slice(&map(wrong), selected, &CryptoAgreementKeyProvider),
        Reason::Algorithm,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn agreement_key_owners_are_independent_zeroizing_and_signing_defaults_stay_separate(
) -> Result<(), ContainerError> {
    fn zeroizing<T: zeroize::ZeroizeOnDrop>() {}
    zeroizing::<AgreementKey>();
    assert!(core::mem::needs_drop::<AgreementKey>());
    let case = case(1)?;
    let mut encoded = hex(&case.key);
    let retained = encoded.clone();
    let imported = AgreementKey::from_slice(
        &encoded,
        policy(EncodingPolicy::FullCoordinatesOnly),
        &CryptoAgreementKeyProvider,
    )?;
    encoded.fill(0);
    assert_eq!(imported.original_cose_key(), retained);
    assert_eq!(imported.public_material(), hex(&case.public));
    let mut material = hex(&case.public);
    let constructed = AgreementKey::from_public_key(
        imported.curve(),
        &material,
        PeerPointEncoding::Ec2Coordinates,
        policy(EncodingPolicy::FullCoordinatesOnly),
        &CryptoAgreementKeyProvider,
    )?;
    material.fill(0);
    assert_eq!(constructed.public_material(), imported.public_material());
    let signing =
        crate::cose_key_from_public_bytes(crate::Algorithm::P256, imported.public_material())?;
    assert_eq!(
        crate::cose_key_signature_algorithm(&signing)?,
        Some(crate::CoseSignatureAlgorithm::Esp256)
    );
    assert!(crate::cose_key_from_slice(&retained).is_err());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn imported_and_constructed_ecdh_points_execute_through_crypto() -> Result<(), ContainerError> {
    use reallyme_crypto::dispatch::derive_shared_secret;
    use zeroize::Zeroizing;
    // Independent named generators in peer-keys.json: multiplication by scalar
    // one must return their x coordinate. COSE performs no key agreement itself.
    for (id, algorithm, width) in [
        (1, crate::Algorithm::P256, 32),
        (2, crate::Algorithm::P384, 48),
        (3, crate::Algorithm::P521, 66),
    ] {
        let case = case(id)?;
        let policy = policy(EncodingPolicy::FullCoordinatesOnly);
        let imported =
            AgreementKey::from_slice(&hex(&case.key), policy, &CryptoAgreementKeyProvider)?;
        let emitted = AgreementKey::from_public_key(
            imported.curve(),
            imported.public_material(),
            PeerPointEncoding::Ec2Coordinates,
            policy,
            &CryptoAgreementKeyProvider,
        )?;
        let mut scalar = Zeroizing::new(vec![0; width]);
        *scalar.last_mut().ok_or(Reason::Key)? = 1;
        let secret = derive_shared_secret(algorithm, &scalar, emitted.public_material())
            .map_err(|_| Reason::Backend)?;
        assert_eq!(
            &*secret,
            imported
                .public_material()
                .get(1..=width)
                .ok_or(Reason::Key)?
        );
    }
    Ok(())
}
