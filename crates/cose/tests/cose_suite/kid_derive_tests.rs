#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_cose::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_from_signature_private_bytes,
    cose_key_from_signature_public_bytes, cose_key_from_signature_public_bytes_with_encoding,
    cose_key_from_slice, cose_key_signature_algorithm, cose_key_to_public_bytes, cose_key_to_vec,
    derive_kid_from_cose_key_public, CoseEc2PointEncoding, CoseError, CoseSignatureAlgorithm,
};
use zeroize::Zeroizing;

use super::support::{gen_ed25519, gen_p256, gen_p384, gen_p521, gen_secp256k1};

const P256_GENERATOR_COMPRESSED: [u8; 33] = [
    0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96,
];

#[test]
fn kid_is_stable_for_same_public_key() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&cose_key).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid1, kid2);
}

#[test]
fn kid_ignores_private_key_material() {
    let k = gen_ed25519();

    let public_only = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let with_private = cose_key_from_private_bytes(k.alg, &k.private, Some(&k.public)).unwrap();

    let kid_pub = derive_kid_from_cose_key_public(&public_only).unwrap();
    let kid_priv = derive_kid_from_cose_key_public(&with_private).unwrap();

    assert_eq!(kid_pub, kid_priv);
}

#[test]
fn ed25519_kid_matches_independent_canonical_public_map() -> Result<(), CoseError> {
    // RFC 8032 §7.1, TEST 1. The expected digest is SHA-256 of the
    // deterministic four-entry map prefix followed by the public key.
    let public = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        .map_err(|_| CoseError::InvalidKeyMaterial)?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        seed.as_mut_slice(),
    )
    .map_err(|_| CoseError::InvalidKeyMaterial)?;

    const EXPECTED_KID: &str = "3606e96f48d6fbe487c2816a7742861d2ea9908fcf943b705151889cd1001819";
    let explicit_public =
        cose_key_from_signature_public_bytes(CoseSignatureAlgorithm::Ed25519, &public)?;
    let mut expected_map = b"\xa4\x01\x01\x03\x32\x20\x06\x21\x58\x20".to_vec();
    expected_map.extend_from_slice(&public);
    assert_eq!(cose_key_to_vec(&explicit_public)?.as_slice(), expected_map);
    assert_eq!(
        hex::encode(derive_kid_from_cose_key_public(&explicit_public)?),
        EXPECTED_KID
    );

    // Parse a private key with kid and key_ops in addition to x and d. The
    // optional alg changes the input metadata, while the hash uses -19 in
    // both cases according to the Ed25519 profile.
    const PRIVATE_FIXTURE_CAPACITY: usize = 83;
    for explicit_algorithm in [false, true] {
        let mut encoded = Zeroizing::new(Vec::with_capacity(PRIVATE_FIXTURE_CAPACITY));
        encoded.push(if explicit_algorithm { 0xa7 } else { 0xa6 });
        encoded.extend_from_slice(b"\x01\x01\x02\x41\x99");
        let algorithm_value = encoded
            .len()
            .checked_add(1)
            .ok_or(CoseError::InvalidFormat)?;
        if explicit_algorithm {
            encoded.extend_from_slice(b"\x03\x32");
        }
        encoded.extend_from_slice(b"\x04\x81\x02\x20\x06\x21\x58\x20");
        encoded.extend_from_slice(&public);
        encoded.extend_from_slice(b"\x23\x58\x20");
        encoded.extend_from_slice(seed.as_slice());
        let key = cose_key_from_slice(&encoded)?;
        assert_eq!(
            cose_key_signature_algorithm(&key)?,
            explicit_algorithm.then_some(CoseSignatureAlgorithm::Ed25519)
        );
        assert_eq!(
            hex::encode(derive_kid_from_cose_key_public(&key)?),
            EXPECTED_KID
        );

        // Changing d leaves x intact but invalidates the private/public binding.
        let last_seed_byte = encoded.last_mut().ok_or(CoseError::InvalidFormat)?;
        *last_seed_byte ^= 1;
        assert!(matches!(
            cose_key_from_slice(&encoded),
            Err(CoseError::InvalidKeyMaterial)
        ));

        if explicit_algorithm {
            *encoded.last_mut().ok_or(CoseError::InvalidFormat)? ^= 1;
            // Exercise legacy registration rejection with the valid pair.
            let alg = encoded
                .get_mut(algorithm_value)
                .ok_or(CoseError::InvalidFormat)?;
            *alg = 0x27;
            assert!(matches!(
                cose_key_from_slice(&encoded),
                Err(CoseError::UnsupportedAlgorithm)
            ));
        }
    }
    Ok(())
}

#[test]
fn p256_kid_matches_independent_public_preimage_for_each_registration() -> Result<(), CoseError> {
    // SEC1 compressed encoding of the P-256 generator, with private scalar 1.
    let public = P256_GENERATOR_COMPRESSED;
    let mut private = Zeroizing::new([0_u8; 32]);
    private[31] = 1;

    // SHA-256 of the independently encoded CBOR map with keys 1, 3, -1,
    // -2 and -3, and alg -7 or -9. Neither expected digest uses the SDK's
    // constructors or encoder.
    for (algorithm, expected) in [
        (
            CoseSignatureAlgorithm::Es256,
            "4bafea17955805ebfe7ab93d0f1d6e9e8f5bdeaf5fdb666cdab5dc7f75ecbfb4",
        ),
        (
            CoseSignatureAlgorithm::Esp256,
            "0130e4882984971aae371f882c0cbdd21adfb91b71b8b310b4f5098289b9bfd2",
        ),
    ] {
        let private_key =
            cose_key_from_signature_private_bytes(algorithm, private.as_slice(), Some(&public))?;
        assert_eq!(cose_key_to_public_bytes(&private_key)?.as_slice(), public);
        assert_eq!(
            hex::encode(derive_kid_from_cose_key_public(&private_key)?),
            expected
        );
        for encoding in [
            CoseEc2PointEncoding::Compressed,
            CoseEc2PointEncoding::FullCoordinates,
        ] {
            let public_key =
                cose_key_from_signature_public_bytes_with_encoding(algorithm, &public, encoding)?;
            assert_eq!(cose_key_to_public_bytes(&public_key)?.as_slice(), public);
            if encoding == CoseEc2PointEncoding::Compressed {
                let canonical = cose_key_to_vec(&public_key)?;
                assert_eq!(
                    hex::encode(reallyme_codec::cbor::sha2_256_content_hash(&canonical)),
                    expected
                );
            }
            assert_eq!(
                hex::encode(derive_kid_from_cose_key_public(&public_key)?),
                expected
            );
        }
    }
    Ok(())
}

#[test]
fn parsed_p256_full_coordinate_private_key_yields_only_its_public_point() -> Result<(), CoseError> {
    // Canonical EC2 map of the generator with full coordinates and d = 1.
    // Assemble under a wipe owner because the stock private-key constructor
    // deliberately normalizes to a compact representation.
    const FULL_PRIVATE_KEY_BYTES: usize = 112;
    let mut d = Zeroizing::new([0_u8; 32]);
    d[31] = 1;
    let y = [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ];
    for (algorithm, id) in [
        (CoseSignatureAlgorithm::Es256, 0x26),
        (CoseSignatureAlgorithm::Esp256, 0x28),
    ] {
        let mut encoded = Zeroizing::new(Vec::with_capacity(FULL_PRIVATE_KEY_BYTES));
        encoded.extend_from_slice(&[0xa6, 0x01, 0x02, 0x03, id, 0x20, 0x01, 0x21, 0x58, 0x20]);
        encoded.extend_from_slice(&P256_GENERATOR_COMPRESSED[1..]);
        encoded.extend_from_slice(&[0x22, 0x58, 0x20]);
        encoded.extend_from_slice(&y);
        encoded.extend_from_slice(&[0x23, 0x58, 0x20]);
        encoded.extend_from_slice(d.as_slice());
        assert_eq!(encoded.len(), FULL_PRIVATE_KEY_BYTES);
        let key = cose_key_from_slice(&encoded)?;
        assert_eq!(
            cose_key_to_public_bytes(&key)?.as_slice(),
            P256_GENERATOR_COMPRESSED
        );
        let public = cose_key_from_signature_public_bytes_with_encoding(
            algorithm,
            &P256_GENERATOR_COMPRESSED,
            CoseEc2PointEncoding::Compressed,
        )?;
        assert_eq!(
            derive_kid_from_cose_key_public(&key)?.as_slice(),
            derive_kid_from_cose_key_public(&public)?.as_slice()
        );
    }
    Ok(())
}

#[test]
fn p256_kid_matches_canonical_public_encoding_for_both_point_signs() -> Result<(), CoseError> {
    // Both compressed signs with the generator X encode valid points (G and
    // -G). Compare with the general COSE_Key encoder for both registrations.
    let mut point = P256_GENERATOR_COMPRESSED;
    for prefix in [0x02, 0x03] {
        point[0] = prefix;
        for registration in [
            CoseSignatureAlgorithm::Es256,
            CoseSignatureAlgorithm::Esp256,
        ] {
            let key = cose_key_from_signature_public_bytes_with_encoding(
                registration,
                &point,
                CoseEc2PointEncoding::Compressed,
            )?;
            let canonical = cose_key_to_vec(&key)?;
            let expected = reallyme_codec::cbor::sha2_256_content_hash(&canonical);
            assert_eq!(derive_kid_from_cose_key_public(&key)?.as_slice(), expected);
        }
    }
    Ok(())
}

#[test]
fn kid_differs_for_different_keys() {
    let k1 = gen_ed25519();
    let k2 = gen_ed25519();

    let key1 = cose_key_from_public_bytes(k1.alg, &k1.public).unwrap();
    let key2 = cose_key_from_public_bytes(k2.alg, &k2.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&key1).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&key2).unwrap();

    assert_ne!(kid1, kid2);
}

#[test]
fn kid_is_stable_for_ec_p256() {
    let k = gen_p256();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&cose_key).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid1, kid2);
}

#[test]
fn kid_is_stable_for_ec_p384() {
    let k = gen_p384();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&cose_key).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid1, kid2);
}

#[test]
fn kid_is_stable_for_ec_p521() {
    let k = gen_p521();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&cose_key).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid1, kid2);
}

#[test]
fn kid_is_stable_for_ec_secp256k1() {
    let k = gen_secp256k1();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&cose_key).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid1, kid2);
}

#[test]
fn kid_length_is_sha256() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid.len(), 32);
}
