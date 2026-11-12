// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::build_authentication_structure::{
    build_authentication_structure, AuthenticationContext,
};
use crate::mac0::{
    cose_verify_mac0_detached, CoseMac0Error, CoseMac0ErrorReason, CoseMacAlgorithm, CoseMacKey,
};

use super::support::{
    assert_reason, detached, encode, envelope, hex, request, tag, verify, ALGORITHM, KEY,
};

// Independent COSE Working Group examples at immutable revision
// https://github.com/cose-wg/Examples/tree/53c9d634333bb4f529d78f5980fffa2667ee2c12
// mac0-tests/HMac-01.json and hmac-examples/HMac-enc-{02,03,05}.json.
// Only the transport payload slot is replaced with null. MAC_structure and
// tags remain unchanged, as required for detached transport by RFC 9052 §6.3.
const WG_KEY_256: &str = "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188";
const WG_KEY_384: &str = "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c42718800112233778899aa2122232425262728";
const WG_KEY_512: &str = "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c42718800112233778899aa2122232425262728aabbccddeeffa5a6a7a8a9a0b1b2b3b4";
const WG_PAYLOAD: &[u8] = b"This is the content.";

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn working_group_vectors_verify_for_all_hmac_registrations() -> Result<(), CoseMac0Error> {
    let vectors = [
        (CoseMacAlgorithm::Hmac256_64, WG_KEY_256, "a10104", "11f9e357975fb849"),
        (ALGORITHM, WG_KEY_256, "a10105", "a1a848d3471f9d61ee49018d244c824772f223ad4f935293f1789fc3a08d8c58"),
        (CoseMacAlgorithm::Hmac384_384, WG_KEY_384, "a10106", "998d26c6459aaeecf44ed20ce00c8ccedf0a1f3d22a92fc05db08c5aeb1cb594caaf5a5c5e2e9d01cce7e77a93aa8c62"),
        (CoseMacAlgorithm::Hmac512_512, WG_KEY_512, "a10107", "4a555bf971f7c1891d9ddf304a1a132e2d6f817449474d813e6d04d65962bed8bba70c17e1f5308fa39962959a4b9b8d7da8e6d849b209dcd3e98cc0f11eddf2"),
    ];
    for (algorithm, key_hex, protected_hex, tag_hex) in vectors {
        let key = CoseMacKey::new(algorithm, Zeroizing::new(hex(key_hex)))?;
        let protected = hex(protected_hex);
        for tagged in [false, true] {
            let mut encoded = detached(&protected, &hex(tag_hex));
            if tagged {
                encoded.insert(0, 0xd1);
            }
            let mut input = request(&encoded, WG_PAYLOAD, &[]);
            input.allowed_algorithms = std::slice::from_ref(&algorithm);
            let result = cose_verify_mac0_detached(input, &key)?;
            assert_eq!(result.algorithm(), algorithm);
            assert_eq!(result.protected_header_bytes(), protected);
            assert_eq!(result.protected_key_id(), None);

            for (payload, aad) in [(b"changed".as_slice(), &[][..]), (WG_PAYLOAD, b"aad")] {
                let mut input = request(&encoded, payload, aad);
                input.allowed_algorithms = std::slice::from_ref(&algorithm);
                assert_reason(
                    cose_verify_mac0_detached(input, &key),
                    CoseMac0ErrorReason::AuthenticationFailed,
                );
            }
            let wrong_key = CoseMacKey::new(
                algorithm,
                Zeroizing::new(vec![0x22; algorithm.key_length()]),
            )?;
            let mut input = request(&encoded, WG_PAYLOAD, &[]);
            input.allowed_algorithms = std::slice::from_ref(&algorithm);
            assert_reason(
                cose_verify_mac0_detached(input, &wrong_key),
                CoseMac0ErrorReason::AuthenticationFailed,
            );

            let mut changed_tag = hex(tag_hex);
            for byte in &mut changed_tag {
                *byte ^= 1;
            }
            let changed = detached(&protected, &changed_tag);
            let mut input = request(&changed, WG_PAYLOAD, &[]);
            input.allowed_algorithms = std::slice::from_ref(&algorithm);
            assert_reason(
                cose_verify_mac0_detached(input, &key),
                CoseMac0ErrorReason::AuthenticationFailed,
            );
        }
    }
    let message = build_authentication_structure(
        AuthenticationContext::Mac0,
        &hex("a10105"),
        &[],
        WG_PAYLOAD,
    )?;
    assert_eq!(
        *message,
        hex("84644d41433043a101054054546869732069732074686520636f6e74656e742e")
    );
    Ok(())
}

#[test]
fn changed_payload_aad_key_and_every_tag_byte_fail() -> Result<(), CoseMac0Error> {
    let protected = hex("a10105");
    let expected_tag = tag(&protected, b"payload", b"aad");
    let encoded = detached(&protected, &expected_tag);
    let key = CoseMacKey::new(ALGORITHM, Zeroizing::new(KEY.to_vec()))?;
    assert_reason(
        cose_verify_mac0_detached(request(&encoded, b"changed", b"aad"), &key),
        CoseMac0ErrorReason::AuthenticationFailed,
    );
    assert_reason(
        cose_verify_mac0_detached(request(&encoded, b"payload", b"changed"), &key),
        CoseMac0ErrorReason::AuthenticationFailed,
    );
    assert_reason(
        cose_verify_mac0_detached(request(&encoded, b"payload", &[]), &key),
        CoseMac0ErrorReason::AuthenticationFailed,
    );
    let wrong_key = CoseMacKey::new(ALGORITHM, Zeroizing::new(vec![0x22; 32]))?;
    assert_reason(
        cose_verify_mac0_detached(request(&encoded, b"payload", b"aad"), &wrong_key),
        CoseMac0ErrorReason::AuthenticationFailed,
    );
    for index in 0..expected_tag.len() {
        let mut changed = expected_tag.clone();
        changed[index] ^= 1;
        assert_reason(
            verify(&detached(&protected, &changed)),
            CoseMac0ErrorReason::AuthenticationFailed,
        );
    }
    Ok(())
}

#[test]
fn protected_bytes_are_never_normalized_and_metadata_is_authenticated() -> Result<(), CoseMac0Error>
{
    // Python 3 stdlib hmac/sha256 over the manually encoded MAC_structure:
    // 84644d41433047a204426964010543616164477061796c6f6164
    // This order is permitted by COSE but differs from sorted map order.
    let protected = hex("a2044269640105");
    let expected_tag = hex("261f47de2629ef7421c0a952c82cac05ba5cff842c238b4548af4d01b854861f");
    let encoded = detached(&protected, &expected_tag);
    let verified = verify(&encoded)?;
    assert_eq!(verified.protected_header_bytes(), protected);
    assert_eq!(verified.protected_key_id(), Some(b"id".as_slice()));
    assert_reason(
        verify(&detached(&hex("a2010504426964"), &expected_tag)),
        CoseMac0ErrorReason::AuthenticationFailed,
    );
    assert_reason(
        verify(&detached(&hex("a2044269650105"), &expected_tag)),
        CoseMac0ErrorReason::AuthenticationFailed,
    );
    Ok(())
}

#[test]
fn unprotected_kid_is_ignored_and_never_reported_as_authenticated() -> Result<(), CoseMac0Error> {
    let protected = hex("a10105");
    let expected_tag = tag(&protected, b"payload", b"aad");
    for kid in [b"first".as_slice(), b"changed".as_slice()] {
        let encoded = envelope(
            &protected,
            Value::Map(vec![(4.into(), Value::Bytes(kid.to_vec()))]),
            Value::Null,
            &expected_tag,
        );
        let result = verify(&encoded)?;
        assert_eq!(result.protected_key_id(), None);
    }
    Ok(())
}

#[test]
fn critical_known_headers_and_noncritical_extensions() -> Result<(), CoseMac0Error> {
    let protected = hex("a40105044269640282010461618100");
    let encoded = detached(&protected, &tag(&protected, b"payload", b"aad"));
    assert_eq!(verify(&encoded)?.protected_key_id(), Some(b"id".as_slice()));
    Ok(())
}

#[test]
fn empty_payload_and_explicit_empty_aad_verify() -> Result<(), CoseMac0Error> {
    let protected = hex("a10105");
    let encoded = detached(&protected, &tag(&protected, &[], &[]));
    let key = CoseMacKey::new(ALGORITHM, Zeroizing::new(KEY.to_vec()))?;
    cose_verify_mac0_detached(request(&encoded, &[], &[]), &key)?;
    Ok(())
}

#[test]
fn exact_allowlist_and_exact_key_binding_fail_closed() -> Result<(), CoseMac0Error> {
    let encoded = detached(&hex("a10105"), &[0; 32]);
    let key = CoseMacKey::new(ALGORITHM, Zeroizing::new(KEY.to_vec()))?;
    for allowed in [&[][..], &[CoseMacAlgorithm::Hmac256_64][..]] {
        let mut input = request(&encoded, &[], &[]);
        input.allowed_algorithms = allowed;
        assert_reason(
            cose_verify_mac0_detached(input, &key),
            CoseMac0ErrorReason::UnsupportedAlgorithm,
        );
    }
    let wrong_algorithm =
        CoseMacKey::new(CoseMacAlgorithm::Hmac256_64, Zeroizing::new(KEY.to_vec()))?;
    assert_reason(
        cose_verify_mac0_detached(request(&encoded, &[], &[]), &wrong_algorithm),
        CoseMac0ErrorReason::KeyAlgorithmMismatch,
    );
    let attached = encode(Value::Array(vec![
        Value::Bytes(hex("a10105")),
        Value::Map(vec![]),
        Value::Bytes(b"payload".to_vec()),
        Value::Bytes(vec![0; 32]),
    ]));
    assert_reason(
        verify(&attached),
        CoseMac0ErrorReason::DetachedPayloadRequired,
    );
    Ok(())
}

#[test]
fn all_key_lengths_are_enforced_and_sensitive_owners_zeroize_on_drop() {
    fn requires_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    requires_zeroize_on_drop::<CoseMacKey>();
    requires_zeroize_on_drop::<crate::mac0::VerifiedDetachedCoseMac0>();
    for algorithm in [
        CoseMacAlgorithm::Hmac256_64,
        ALGORITHM,
        CoseMacAlgorithm::Hmac384_384,
        CoseMacAlgorithm::Hmac512_512,
    ] {
        for length in [
            0,
            1,
            algorithm.key_length() - 1,
            algorithm.key_length() + 1,
            4097,
        ] {
            assert_reason(
                CoseMacKey::new(algorithm, Zeroizing::new(vec![0; length])),
                CoseMac0ErrorReason::InvalidKeyLength,
            );
        }
    }
}
