// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::agreement_support::{case, parameters, policy};
use super::support::{assert_error, hex, int, map};
use crate::containers::{
    AgreementEc2EncodingPolicy as EncodingPolicy, AgreementKey, AgreementKeyProvider,
    ContainerError, ContainerErrorReason as Reason, CryptoAgreementKeyProvider, OptionalKeyPolicy,
    PeerCurve, PeerPointEncoding,
};
use ciborium::value::Value;
use core::cell::Cell;
use zeroize::Zeroizing;

struct RejectingProvider(Cell<usize>);
impl AgreementKeyProvider for RejectingProvider {
    fn normalize_public_key(
        &self,
        _: PeerCurve,
        _: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
        self.0.set(self.0.get() + 1);
        Err(Reason::Provider.into())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn duplicate_and_private_parameters_fail_before_provider_and_are_not_ignored(
) -> Result<(), ContainerError> {
    let case = case(1)?;
    let provider = RejectingProvider(Cell::new(0));
    for optional in [OptionalKeyPolicy::Cose, OptionalKeyPolicy::IsoPeer] {
        let mut selected = policy(EncodingPolicy::FullCoordinatesOnly);
        selected.optional_parameters = optional;
        for label in [1, -1, -2, -3, 42] {
            let mut params = parameters(&case)?;
            if label == 42 {
                params.push((int(42), Value::Null));
            }
            params.push((int(label), Value::Null));
            assert_error(
                AgreementKey::from_slice(&map(params), selected, &provider),
                Reason::Duplicate,
            );
        }
        for label in [-4, -5] {
            let mut params = parameters(&case)?;
            params.push((int(label), Value::Bytes(vec![0x42; 32])));
            assert_error(
                AgreementKey::from_slice(&map(params), selected, &provider),
                Reason::Key,
            );
        }
    }
    assert_eq!(provider.0.get(), 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn malformed_truncated_nonpreferred_tagged_and_trailing_inputs_are_rejected(
) -> Result<(), ContainerError> {
    let encoded = hex(&case(1)?.key);
    let selected = policy(EncodingPolicy::FullCoordinatesOnly);
    let provider = RejectingProvider(Cell::new(0));
    for end in 0..encoded.len() {
        assert_error(
            AgreementKey::from_slice(&encoded[..end], selected, &provider),
            Reason::Malformed,
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_error(
        AgreementKey::from_slice(&trailing, selected, &provider),
        Reason::Malformed,
    );
    let mut nonpreferred = vec![0xb8, 4];
    nonpreferred.extend_from_slice(&encoded[1..]);
    assert_error(
        AgreementKey::from_slice(&nonpreferred, selected, &provider),
        Reason::Encoding,
    );
    let mut indefinite = vec![0xbf];
    indefinite.extend_from_slice(&encoded[1..]);
    indefinite.push(0xff);
    assert_error(
        AgreementKey::from_slice(&indefinite, selected, &provider),
        Reason::Encoding,
    );
    // Tag/wrapper bytes belong to the caller's transcript owner, rather than
    // being silently stripped by this untagged COSE_Key boundary.
    let mut tagged = vec![0xd8, 24];
    tagged.extend_from_slice(&super::support::encode(Value::Bytes(encoded)));
    assert_error(
        AgreementKey::from_slice(&tagged, selected, &provider),
        Reason::Malformed,
    );
    assert_eq!(provider.0.get(), 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn representation_and_allowlist_failures_do_not_invoke_provider() -> Result<(), ContainerError> {
    let case = case(1)?;
    let selected = policy(EncodingPolicy::FullCoordinatesOnly);
    let provider = RejectingProvider(Cell::new(0));
    assert_error(
        AgreementKey::from_slice(&hex(&case.compressed), selected, &provider),
        Reason::Profile,
    );
    let mut forbidden = selected;
    forbidden.allowed_curves = &[];
    assert_error(
        AgreementKey::from_slice(&hex(&case.key), forbidden, &provider),
        Reason::Limit,
    );
    for encoding in [PeerPointEncoding::Ec2YSign, PeerPointEncoding::Okp] {
        assert_error(
            AgreementKey::from_public_key(
                PeerCurve::from_identifier(1)?,
                &hex(&case.public),
                encoding,
                selected,
                &provider,
            ),
            Reason::Profile,
        );
    }
    assert_error(
        AgreementKey::from_public_key(
            PeerCurve::X25519,
            &[9; 32],
            PeerPointEncoding::Ec2Coordinates,
            selected,
            &provider,
        ),
        Reason::Profile,
    );
    for bytes in [&[][..], &[0x04; 32][..], &[0x04; 64][..], &[0x02; 65][..]] {
        assert_error(
            AgreementKey::from_public_key(
                PeerCurve::from_identifier(1)?,
                bytes,
                PeerPointEncoding::Ec2Coordinates,
                selected,
                &provider,
            ),
            Reason::Key,
        );
    }
    assert_eq!(provider.0.get(), 0);
    assert_error(
        AgreementKey::from_slice(&hex(&case.key), selected, &provider),
        Reason::Provider,
    );
    assert_eq!(provider.0.get(), 1);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn invalid_full_points_are_not_repaired_by_discarding_y() -> Result<(), ContainerError> {
    let case = case(1)?;
    let mut wrong = hex(&case.public);
    *wrong.last_mut().ok_or(Reason::Key)? ^= 2;
    for encoding in [
        PeerPointEncoding::Ec2Coordinates,
        PeerPointEncoding::Ec2YSign,
    ] {
        assert_error(
            AgreementKey::from_public_key(
                PeerCurve::from_identifier(1)?,
                &wrong,
                encoding,
                policy(EncodingPolicy::FullOrCompressed),
                &CryptoAgreementKeyProvider,
            ),
            Reason::Key,
        );
    }
    let mut low_order_one = vec![0; 32];
    low_order_one[0] = 1;
    for point in [vec![0; 32], low_order_one, vec![0xff; 32]] {
        assert_error(
            AgreementKey::from_public_key(
                PeerCurve::X25519,
                &point,
                PeerPointEncoding::Okp,
                policy(EncodingPolicy::FullCoordinatesOnly),
                &CryptoAgreementKeyProvider,
            ),
            Reason::Key,
        );
    }
    Ok(())
}

struct ReturningProvider(Vec<u8>);
impl AgreementKeyProvider for ReturningProvider {
    fn normalize_public_key(
        &self,
        _: PeerCurve,
        _: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
        Ok(Zeroizing::new(self.0.clone()))
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn malformed_or_substituted_provider_output_cannot_change_key_identity(
) -> Result<(), ContainerError> {
    let case = case(1)?;
    let full = hex(&case.public);
    let mut wrong_x = full.clone();
    wrong_x[1] ^= 1;
    let mut wrong_parity = full.clone();
    *wrong_parity.last_mut().ok_or(Reason::Key)? ^= 1;
    let mut same_parity_wrong_y = full;
    *same_parity_wrong_y.last_mut().ok_or(Reason::Key)? ^= 2;
    for returned in [
        Vec::new(),
        vec![2; 33],
        vec![4; 66],
        wrong_x,
        wrong_parity,
        same_parity_wrong_y,
    ] {
        assert_error(
            AgreementKey::from_slice(
                &hex(&case.key),
                policy(EncodingPolicy::FullCoordinatesOnly),
                &ReturningProvider(returned),
            ),
            Reason::Key,
        );
    }
    // A compressed input still binds x and parity before accepting a provider's
    // decompression. Mathematical correctness remains the crypto contract.
    let mut different_x = hex(&case.public);
    different_x[1] ^= 1;
    let mut different_parity = hex(&case.public);
    *different_parity.last_mut().ok_or(Reason::Key)? ^= 1;
    for returned in [different_x, different_parity] {
        assert_error(
            AgreementKey::from_slice(
                &hex(&case.compressed),
                policy(EncodingPolicy::FullOrCompressed),
                &ReturningProvider(returned),
            ),
            Reason::Key,
        );
    }
    let xdh = case_x25519()?;
    assert_error(
        AgreementKey::from_slice(
            &hex(&xdh.key),
            policy(EncodingPolicy::FullCoordinatesOnly),
            &ReturningProvider(vec![9; 32]),
        ),
        Reason::Key,
    );
    Ok(())
}

fn case_x25519() -> Result<super::agreement_support::Case, ContainerError> {
    case(4)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn agreement_input_limits_are_checked_before_crypto() -> Result<(), ContainerError> {
    use crate::limits::MAX_COSE_KEY_BYTES;
    let case = case(1)?;
    let provider = RejectingProvider(Cell::new(0));
    let selected = policy(EncodingPolicy::FullCoordinatesOnly);
    let oversized = vec![0; MAX_COSE_KEY_BYTES.checked_add(1).ok_or(Reason::Limit)?];
    assert_error(
        AgreementKey::from_slice(&oversized, selected, &provider),
        Reason::Limit,
    );
    assert_error(
        AgreementKey::from_public_key(
            PeerCurve::from_identifier(1)?,
            &oversized,
            PeerPointEncoding::Ec2Coordinates,
            selected,
            &provider,
        ),
        Reason::Limit,
    );
    let mut too_many = parameters(&case)?;
    for label in 100..129 {
        too_many.push((int(label), Value::Null));
    }
    let mut iso = selected;
    iso.optional_parameters = OptionalKeyPolicy::IsoPeer;
    assert_error(
        AgreementKey::from_slice(&map(too_many), iso, &provider),
        Reason::Limit,
    );
    assert_eq!(provider.0.get(), 0);
    let mut maximum = parameters(&case)?;
    maximum.push((int(99), Value::Bytes(Vec::new())));
    let overhead = map(maximum.clone())
        .len()
        .checked_add(2)
        .ok_or(Reason::Limit)?;
    if let Some((_, parameter)) = maximum.last_mut() {
        *parameter = Value::Bytes(vec![
            0x42;
            MAX_COSE_KEY_BYTES
                .checked_sub(overhead)
                .ok_or(Reason::Limit)?
        ]);
    }
    let maximum = map(maximum);
    assert_eq!(maximum.len(), MAX_COSE_KEY_BYTES);
    let key = AgreementKey::from_slice(&maximum, iso, &CryptoAgreementKeyProvider)?;
    assert_eq!(key.original_cose_key(), maximum);
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn malformed_and_private_input_errors_allocate_nothing() -> Result<(), ContainerError> {
    let mut params = parameters(&case(1)?)?;
    params.push((int(-4), Value::Bytes(vec![0x42; 32])));
    let encoded = map(params);
    let selected = policy(EncodingPolicy::FullCoordinatesOnly);
    let measured = allocation_counter::measure(|| {
        assert_error(
            AgreementKey::from_slice(&[], selected, &CryptoAgreementKeyProvider),
            Reason::Malformed,
        );
        assert_error(
            AgreementKey::from_slice(&encoded, selected, &CryptoAgreementKeyProvider),
            Reason::Key,
        );
        let error: ContainerError = Reason::Key.into();
        assert_eq!(error.reason(), Reason::Key);
    });
    assert_eq!(measured.count_total, 0);
    Ok(())
}
