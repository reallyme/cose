// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use coset::{iana, CborSerializable, CoseKey as WireKey, Label};
use reallyme_cose::{
    cose_key_from_public_bytes, cose_key_from_slice, cose_key_signature_algorithm, cose_key_to_vec,
    cose_sign1_detached, cose_verify1_detached, Algorithm, CoseError,
};
use reallyme_crypto::dispatch::generate_keypair;

#[test]
fn present_private_parameters_require_byte_strings_in_every_key_family() {
    for (algorithm, label) in [
        (Algorithm::Ed25519, iana::OkpKeyParameter::D as i64),
        (Algorithm::X25519, iana::OkpKeyParameter::D as i64),
        (Algorithm::P256, iana::Ec2KeyParameter::D as i64),
        (Algorithm::P384, iana::Ec2KeyParameter::D as i64),
        (Algorithm::P521, iana::Ec2KeyParameter::D as i64),
        (Algorithm::Secp256k1, iana::Ec2KeyParameter::D as i64),
        (Algorithm::MlDsa44, iana::AkpKeyParameter::Priv as i64),
        (Algorithm::MlDsa65, iana::AkpKeyParameter::Priv as i64),
        (Algorithm::MlDsa87, iana::AkpKeyParameter::Priv as i64),
        (Algorithm::MlKem512, iana::AkpKeyParameter::Priv as i64),
        (Algorithm::MlKem768, iana::AkpKeyParameter::Priv as i64),
        (Algorithm::MlKem1024, iana::AkpKeyParameter::Priv as i64),
    ] {
        let (public, _private) = generate_keypair(algorithm).expect("fixture key generation");
        let key = cose_key_from_public_bytes(algorithm, &public).expect("public key construction");
        let encoded = cose_key_to_vec(&key).expect("public key encoding");
        for invalid in [
            Value::Null,
            Value::Bool(false),
            Value::Text("invalid".into()),
            Value::Array(vec![]),
            Value::Integer(1.into()),
        ] {
            let mut wire = WireKey::from_slice(&encoded).expect("fixture decode");
            wire.params.push((Label::Int(label), invalid));
            let malformed = wire.to_vec().expect("fixture encoding");
            assert!(
                matches!(
                    cose_key_from_slice(&malformed),
                    Err(CoseError::InvalidFormat)
                ),
                "{algorithm:?}"
            );
        }
    }
}

#[test]
fn omitted_ed25519_algorithm_is_not_reported_as_present() {
    let (public, _private) = generate_keypair(Algorithm::Ed25519).expect("fixture generation");
    let key = cose_key_from_public_bytes(Algorithm::Ed25519, &public).expect("public key");
    let mut wire = WireKey::from_slice(&cose_key_to_vec(&key).expect("encoding")).expect("decode");
    wire.alg = None;
    let encoded = wire.to_vec().expect("encoding without algorithm");
    let parsed = cose_key_from_slice(&encoded).expect("optional algorithm remains supported");
    assert_eq!(cose_key_signature_algorithm(&parsed), Ok(None));
    assert_eq!(
        cose_key_to_vec(&parsed).expect("round trip").as_slice(),
        encoded
    );
}

#[test]
fn detached_sign1_rejects_undefined_in_place_of_null() {
    let (public, private) = generate_keypair(Algorithm::Ed25519).expect("fixture generation");
    let encoded =
        cose_sign1_detached(Algorithm::Ed25519, b"payload", &private, None).expect("signing");
    let mut cose = coset::CoseSign1::from_slice(&encoded).expect("fixture decode");
    // Preserve the authenticated protected bytes and signature, replacing only
    // the detached payload marker. Undefined is not a COSE payload type.
    let mut malformed = vec![0x84];
    ciborium::ser::into_writer(
        &Value::Bytes(
            cose.protected
                .original_data
                .take()
                .expect("protected bytes"),
        ),
        &mut malformed,
    )
    .expect("header encoding");
    malformed.extend_from_slice(&[0xa0, 0xf7]);
    ciborium::ser::into_writer(&Value::Bytes(cose.signature), &mut malformed)
        .expect("signature encoding");
    assert_eq!(
        cose_verify1_detached(&malformed, b"payload", |_, _| Some(public.clone())),
        Err(CoseError::Cbor)
    );
}

#[test]
fn canonical_nested_key_extensions_preserve_supported_values() {
    let (public, _private) = generate_keypair(Algorithm::Ed25519).expect("fixture generation");
    let key = cose_key_from_public_bytes(Algorithm::Ed25519, &public).expect("public key");
    let mut wire = WireKey::from_slice(&cose_key_to_vec(&key).expect("encoding")).expect("decode");
    wire.params.push((
        Label::Int(-3),
        Value::Array(vec![Value::Map(vec![
            (Value::Integer(1.into()), Value::Null),
            (Value::Integer(2.into()), Value::Bool(false)),
            (Value::Integer(24.into()), Value::Bool(true)),
        ])]),
    ));
    let encoded = wire.to_vec().expect("encoding");
    let parsed = cose_key_from_slice(&encoded).expect("canonical nested extension");
    assert_eq!(
        cose_key_to_vec(&parsed).expect("round trip").as_slice(),
        encoded
    );
}
