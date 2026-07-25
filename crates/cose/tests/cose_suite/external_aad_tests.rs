#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{
    cose_sign1_detached_with_options_and_external_aad, cose_sign1_with_options_and_external_aad,
    cose_verify1_detached_with_policy_and_external_aad, cose_verify1_with_policy_and_external_aad,
    CoseError, CosePolicy, CoseSign1EncodeOptions,
};

use crate::support::{gen_ed25519, sample_payload, test_kid};

#[test]
fn attached_external_aad_roundtrips_and_wrong_aad_fails_authentication() {
    let key = gen_ed25519();
    let payload = sample_payload();
    let external_aad = b"reallyme-cose/external-aad/v1";
    let cose = cose_sign1_with_options_and_external_aad(
        key.alg,
        &payload,
        &key.private,
        Some(test_kid()),
        external_aad,
        CoseSign1EncodeOptions::default(),
    )
    .expect("attached signing with external AAD must succeed");

    let verified = cose_verify1_with_policy_and_external_aad(
        &cose,
        external_aad,
        &CosePolicy::default(),
        |_, kid| (kid == test_kid()).then(|| key.public.clone()),
    )
    .expect("matching external AAD must verify");
    assert_eq!(verified.payload.as_slice(), payload.as_slice());

    let error = cose_verify1_with_policy_and_external_aad(
        &cose,
        b"wrong-external-aad",
        &CosePolicy::default(),
        |_, kid| (kid == test_kid()).then(|| key.public.clone()),
    )
    .err()
    .expect("wrong external AAD must not verify");
    assert_eq!(error, CoseError::InvalidSignature);
}

#[test]
fn detached_external_aad_roundtrips_and_wrong_aad_fails_authentication() {
    let key = gen_ed25519();
    let payload = sample_payload();
    let external_aad = b"reallyme-cose/detached-external-aad/v1";
    let cose = cose_sign1_detached_with_options_and_external_aad(
        key.alg,
        &payload,
        &key.private,
        Some(test_kid()),
        external_aad,
        CoseSign1EncodeOptions::default(),
    )
    .expect("detached signing with external AAD must succeed");

    let verified = cose_verify1_detached_with_policy_and_external_aad(
        &cose,
        &payload,
        external_aad,
        &CosePolicy::default(),
        |_, kid| (kid == test_kid()).then(|| key.public.clone()),
    )
    .expect("matching detached external AAD must verify");
    assert_eq!(verified.kid.as_slice(), test_kid());

    let error = cose_verify1_detached_with_policy_and_external_aad(
        &cose,
        &payload,
        b"wrong-external-aad",
        &CosePolicy::default(),
        |_, kid| (kid == test_kid()).then(|| key.public.clone()),
    )
    .err()
    .expect("wrong detached external AAD must not verify");
    assert_eq!(error, CoseError::InvalidSignature);
}
