// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_cose::iso18013::{
    cose_verify_iso18013_sign1, Iso18013CryptoVerifier, Iso18013Sign1Content, Iso18013Sign1Limits,
    Iso18013Sign1Request, Iso18013SignatureAlgorithm, Iso18013SignatureCurve,
    Iso18013SignatureSuite,
};
use zeroize::Zeroizing;

// The scalar-one P-256 generator is public synthetic test material.
const PUBLIC_KEY: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];
const PAYLOAD: &[u8] = b"ISO 18013-5 synthetic authentication content";

fuzz_target!(|data: &[u8]| {
    let Ok(suite) = Iso18013SignatureSuite::new(
        Iso18013SignatureAlgorithm::Es256,
        Iso18013SignatureCurve::P256,
    ) else {
        return;
    };
    let Ok(verifier) = Iso18013CryptoVerifier::new(suite, Zeroizing::new(PUBLIC_KEY.to_vec()))
    else {
        return;
    };
    for content in [
        Iso18013Sign1Content::IssuerAttached,
        Iso18013Sign1Content::DeviceDetached(PAYLOAD),
        Iso18013Sign1Content::ReaderDetached(data),
    ] {
        let _ = cose_verify_iso18013_sign1(
            Iso18013Sign1Request {
                encoded: data,
                content,
                allowed_suites: &[suite],
                limits: Iso18013Sign1Limits::default(),
            },
            &verifier,
        );
    }
    let _ = Iso18013CryptoVerifier::from_cose_key(suite, data);
});
