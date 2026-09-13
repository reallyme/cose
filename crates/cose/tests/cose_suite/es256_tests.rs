#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_cose::{
    cose_key_from_public_bytes, cose_key_from_signature_private_bytes,
    cose_key_from_signature_public_bytes, cose_key_from_slice, cose_key_signature_algorithm,
    cose_key_to_public_bytes, cose_key_to_vec, cose_sign1_with_signature_algorithm,
    cose_verify1_with_policy, derive_kid_from_cose_key_public, Algorithm, CoseError, CosePolicy,
    CoseSignatureAlgorithm,
};

use super::support::{gen_p256, test_kid};

// WebAuthn Level 3 §6.5.1.1 publishes this canonical EC2/P-256/ES256
// credentialPublicKey. Keeping the external bytes literal prevents the test
// from sharing this crate's encoder and accidentally validating itself.
const WEBAUTHN_ES256_COSE_KEY: [u8; 77] = [
    0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x65, 0xed, 0xa5, 0xa1, 0x25, 0x77,
    0xc2, 0xba, 0xe8, 0x29, 0x43, 0x7f, 0xe3, 0x38, 0x70, 0x1a, 0x10, 0xaa, 0xa3, 0x75, 0xe1, 0xbb,
    0x5b, 0x5d, 0xe1, 0x08, 0xde, 0x43, 0x9c, 0x08, 0x55, 0x1d, 0x22, 0x58, 0x20, 0x1e, 0x52, 0xed,
    0x75, 0x70, 0x11, 0x63, 0xf7, 0xf9, 0xe4, 0x0d, 0xdf, 0x9f, 0x34, 0x1b, 0x3d, 0xc9, 0xba, 0x86,
    0x0a, 0xf7, 0xe0, 0xca, 0x7c, 0xa7, 0xe9, 0xee, 0xcd, 0x00, 0x84, 0xd1, 0x9c,
];

#[test]
fn webauthn_es256_credential_public_key_parses_and_preserves_registration() {
    let key = cose_key_from_slice(&WEBAUTHN_ES256_COSE_KEY)
        .expect("published WebAuthn ES256 key must parse");

    assert_eq!(
        cose_key_signature_algorithm(&key).expect("algorithm inspection must succeed"),
        Some(CoseSignatureAlgorithm::Es256),
    );
    assert_eq!(
        cose_key_to_vec(&key)
            .expect("validated key must re-encode")
            .as_slice(),
        WEBAUTHN_ES256_COSE_KEY,
    );

    let public_key = cose_key_to_public_bytes(&key).expect("public point must extract");
    assert_eq!(public_key.len(), 33);
    assert_eq!(public_key.first(), Some(&0x02));
    assert_eq!(public_key.get(1..), Some(&WEBAUTHN_ES256_COSE_KEY[10..42]));
}

#[test]
fn exact_es256_constructors_preserve_public_and_private_key_binding() {
    let keypair = gen_p256();
    let public =
        cose_key_from_signature_public_bytes(CoseSignatureAlgorithm::Es256, &keypair.public)
            .expect("ES256 public key must construct");
    let private = cose_key_from_signature_private_bytes(
        CoseSignatureAlgorithm::Es256,
        &keypair.private,
        Some(&keypair.public),
    )
    .expect("ES256 private key must construct");

    for key in [&public, &private] {
        assert_eq!(
            cose_key_signature_algorithm(key).expect("algorithm inspection must succeed"),
            Some(CoseSignatureAlgorithm::Es256),
        );
        assert_eq!(
            cose_key_to_public_bytes(key).expect("public point must extract"),
            keypair.public,
        );
    }
    assert_eq!(
        derive_kid_from_cose_key_public(&public).expect("public kid must derive"),
        derive_kid_from_cose_key_public(&private).expect("private kid must derive"),
    );
}

#[test]
fn legacy_p256_constructor_remains_esp256_and_kids_are_registration_bound() {
    let keypair = gen_p256();
    let es256 =
        cose_key_from_signature_public_bytes(CoseSignatureAlgorithm::Es256, &keypair.public)
            .expect("ES256 key must construct");
    let esp256 = cose_key_from_public_bytes(Algorithm::P256, &keypair.public)
        .expect("legacy P-256 key must construct");

    assert_eq!(
        cose_key_signature_algorithm(&esp256).expect("algorithm inspection must succeed"),
        Some(CoseSignatureAlgorithm::Esp256),
    );
    assert_ne!(
        derive_kid_from_cose_key_public(&es256).expect("ES256 kid must derive"),
        derive_kid_from_cose_key_public(&esp256).expect("ESP256 kid must derive"),
    );
}

#[test]
fn es256_rejects_wrong_key_type_and_curve() {
    let mut wrong_key_type = WEBAUTHN_ES256_COSE_KEY;
    wrong_key_type[2] = 0x01;
    assert_eq!(
        cose_key_from_slice(&wrong_key_type).err(),
        Some(CoseError::UnsupportedAlgorithm),
    );

    let mut wrong_curve = WEBAUTHN_ES256_COSE_KEY;
    wrong_curve[6] = 0x02;
    assert_eq!(
        cose_key_from_slice(&wrong_curve).err(),
        Some(CoseError::UnsupportedAlgorithm),
    );
}

#[test]
fn es256_sign1_roundtrip_reports_exact_registration_and_policy_distinguishes_it() {
    let keypair = gen_p256();
    let cose = cose_sign1_with_signature_algorithm(
        CoseSignatureAlgorithm::Es256,
        b"payload",
        &keypair.private,
        Some(test_kid()),
    )
    .expect("ES256 COSE_Sign1 must sign");
    let policy = CosePolicy::new().allow_cose_algorithm(CoseSignatureAlgorithm::Es256);
    let verified = cose_verify1_with_policy(&cose, &policy, |algorithm, kid| {
        (algorithm == Algorithm::P256 && kid == test_kid()).then(|| keypair.public.clone())
    })
    .expect("ES256 COSE_Sign1 must verify");
    assert_eq!(verified.alg, Algorithm::P256);
    assert_eq!(verified.cose_algorithm, CoseSignatureAlgorithm::Es256);

    let incompatible_policy =
        CosePolicy::new().allow_cose_algorithm(CoseSignatureAlgorithm::Esp256);
    assert_eq!(
        cose_verify1_with_policy(&cose, &incompatible_policy, |_, _| {
            Some(keypair.public.clone())
        })
        .err(),
        Some(CoseError::UnsupportedAlgorithm),
    );
}

#[test]
fn parsed_ec2_key_rejects_modified_y_with_unchanged_parity() {
    let mut malformed = WEBAUTHN_ES256_COSE_KEY;
    // Change a high Y byte, retaining X and Y parity. Compression used to
    // discard this corruption and validate the original point instead.
    malformed[45] ^= 0x01;
    assert!(matches!(
        cose_key_from_slice(&malformed),
        Err(CoseError::InvalidKeyMaterial)
    ));
}
