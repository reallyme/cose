// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_crypto::dispatch::generate_keypair;
use zeroize::Zeroizing;

use crate::Algorithm;

use super::convert::{cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_to_vec};
use super::parse::{cose_key_from_slice, parse_cose_key, CoseKeyParseInput};

#[test]
fn native_facade_and_semantic_parse_match_for_all_pilot_owner_classes() {
    let (classical_public, classical_private) =
        generate_keypair(Algorithm::Ed25519).expect("Ed25519 fixture generation must succeed");
    let (pq_public, pq_private) =
        generate_keypair(Algorithm::MlKem768).expect("ML-KEM-768 fixture generation must succeed");

    let fixtures = [
        encode_public(Algorithm::Ed25519, &classical_public),
        encode_ed25519_private(&classical_private, &classical_public),
        encode_public(Algorithm::MlKem768, &pq_public),
        encode_private(Algorithm::MlKem768, &pq_private, &pq_public),
    ];

    for encoded in fixtures {
        let native = cose_key_from_slice(&encoded).expect("native fixture parse must succeed");
        let semantic = parse_cose_key(CoseKeyParseInput::new(&encoded))
            .expect("semantic fixture parse must succeed")
            .into_key();

        assert_eq!(
            cose_key_to_vec(&native)
                .expect("native result must encode")
                .as_slice(),
            encoded.as_slice(),
        );
        assert_eq!(
            cose_key_to_vec(&semantic)
                .expect("semantic result must encode")
                .as_slice(),
            encoded.as_slice(),
        );
    }
}

fn encode_public(algorithm: Algorithm, public_key: &[u8]) -> Zeroizing<Vec<u8>> {
    let key = cose_key_from_public_bytes(algorithm, public_key)
        .expect("public fixture COSE_Key must build");
    cose_key_to_vec(&key).expect("public fixture COSE_Key must encode")
}

fn encode_private(
    algorithm: Algorithm,
    private_key: &[u8],
    public_key: &[u8],
) -> Zeroizing<Vec<u8>> {
    let key = cose_key_from_private_bytes(algorithm, private_key, Some(public_key))
        .expect("private fixture COSE_Key must build");
    cose_key_to_vec(&key).expect("private fixture COSE_Key must encode")
}

fn encode_ed25519_private(private_key: &[u8], public_key: &[u8]) -> Zeroizing<Vec<u8>> {
    // The fixture is independently assembled in RFC 8949 bytewise key order:
    // kty, alg, crv, x, d. It tests parsing without depending on the separate
    // private-key construction path owned by the key-family boundary.
    let mut encoded = Zeroizing::new(vec![
        0xa5, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06, 0x21, 0x58, 0x20,
    ]);
    encoded.extend_from_slice(public_key);
    encoded.extend_from_slice(&[0x23, 0x58, 0x20]);
    encoded.extend_from_slice(private_key);
    encoded
}
