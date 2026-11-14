// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{hash_p256_kid, CoseError, CoseSignatureAlgorithm};

#[kani::proof]
#[kani::unwind(48)]
#[kani::stub(super::sha2_256_content_hash, read_preimage_algorithm_and_sign)]
fn p256_kid_hash_input_preserves_exact_registration_and_y_sign() {
    let es256: bool = kani::any();
    let mut point: [u8; 33] = kani::any();
    let odd_y: bool = kani::any();
    point[0] = if odd_y { 0x03 } else { 0x02 };
    let (algorithm, expected_algorithm_byte) = if es256 {
        (CoseSignatureAlgorithm::Es256, 0x26)
    } else {
        (CoseSignatureAlgorithm::Esp256, 0x28)
    };

    let result = hash_p256_kid(algorithm, &point);
    assert!(result.is_ok());
    if let Ok(witness) = result {
        assert!(witness[0] == expected_algorithm_byte);
        assert!(witness[1] == if odd_y { 0xf5 } else { 0xf4 });
    }
    kani::cover!(es256 && !odd_y, "ES256 with even Y");
    kani::cover!(es256 && odd_y, "ES256 with odd Y");
    kani::cover!(!es256 && !odd_y, "ESP256 with even Y");
    kani::cover!(!es256 && odd_y, "ESP256 with odd Y");
}

#[kani::proof]
#[kani::unwind(48)]
#[kani::stub(super::sha2_256_content_hash, read_preimage_x)]
fn p256_kid_hash_input_has_only_the_canonical_public_fields() {
    let es256: bool = kani::any();
    let odd_y: bool = kani::any();
    let expected_x: [u8; 32] = kani::any();
    let mut point = [0_u8; 33];
    point[0] = if odd_y { 0x03 } else { 0x02 };
    point[1..].copy_from_slice(&expected_x);
    let algorithm = if es256 {
        CoseSignatureAlgorithm::Es256
    } else {
        CoseSignatureAlgorithm::Esp256
    };
    let result = hash_p256_kid(algorithm, &point);
    assert!(result.is_ok());
    if let Ok(x) = result {
        assert!(x == expected_x);
    }

    kani::cover!(es256 && expected_x[0] == 0xff, "ES256 with symbolic X");
    kani::cover!(!es256 && expected_x[0] == 0x00, "ESP256 with symbolic X");
}

#[kani::proof]
#[kani::unwind(3)]
#[kani::stub(super::sha2_256_content_hash, unexpected_hash)]
fn p256_kid_rejects_invalid_compressed_point_prefixes_before_hashing() {
    let point: [u8; 33] = kani::any();
    kani::assume(!matches!(point[0], 0x02 | 0x03));

    assert_eq!(
        hash_p256_kid(CoseSignatureAlgorithm::Es256, &point),
        Err(CoseError::InvalidKeyMaterial)
    );
    assert_eq!(
        hash_p256_kid(CoseSignatureAlgorithm::Esp256, &point),
        Err(CoseError::InvalidKeyMaterial)
    );
    kani::cover!(point[0] == 0x04, "uncompressed point prefix");
    kani::cover!(point[0] == 0xff, "unassigned point prefix");
}

#[kani::proof]
#[kani::unwind(3)]
#[kani::stub(super::sha2_256_content_hash, unexpected_hash)]
fn p256_kid_rejects_every_other_registration_before_hashing() {
    let id: i64 = kani::any();
    kani::assume(!matches!(id, -7 | -9));
    let selection = CoseSignatureAlgorithm::from_identifier(id);
    if let Ok(algorithm) = selection {
        let mut point: [u8; 33] = kani::any();
        point[0] = 0x02;
        assert_eq!(
            hash_p256_kid(algorithm, &point),
            Err(CoseError::UnsupportedAlgorithm)
        );
        kani::cover!(id == -35, "ES384 is rejected by the P-256 encoder");
        kani::cover!(id == -19, "Ed25519 is rejected by the P-256 encoder");
    }
}

// Each stub returns observable bytes from the exact slice passed to
// SHA-256, so the proof does not depend on collision resistance.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn read_preimage_algorithm_and_sign(bytes: &[u8]) -> [u8; 32] {
    assert!(bytes.len() == 44);
    let mut witness = [0_u8; 32];
    witness[0] = bytes[4];
    witness[1] = bytes[43];
    witness
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn read_preimage_x(bytes: &[u8]) -> [u8; 32] {
    assert!(bytes.len() == 44);
    assert!(bytes.get(..4) == Some(&[0xa5, 0x01, 0x02, 0x03]));
    assert!(bytes.get(5..10) == Some(&[0x20, 0x01, 0x21, 0x58, 0x20]));
    assert!(matches!(bytes[4], 0x26 | 0x28));
    assert!(bytes[42] == 0x22 && matches!(bytes[43], 0xf4 | 0xf5));
    let mut witness = [0_u8; 32];
    witness.copy_from_slice(&bytes[10..42]);
    witness
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn unexpected_hash(_bytes: &[u8]) -> [u8; 32] {
    assert!(false, "a rejected preimage must never be hashed");
    [0_u8; 32]
}
