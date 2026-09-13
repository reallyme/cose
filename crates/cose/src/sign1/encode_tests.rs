// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use ciborium::value::Value;
use coset::{AsCborValue, CoseSign1};

use super::{build_protected_header, encode_cose_sign1, CoseSign1EncodeOptions};
use crate::CoseSignatureAlgorithm;

#[test]
fn sensitive_sign1_encoder_matches_coset_for_every_supported_registration() {
    for algorithm in [
        CoseSignatureAlgorithm::Ed25519,
        CoseSignatureAlgorithm::Es256,
        CoseSignatureAlgorithm::Esp256,
        CoseSignatureAlgorithm::Esp384,
        CoseSignatureAlgorithm::Esp512,
        CoseSignatureAlgorithm::Es256K,
        CoseSignatureAlgorithm::MlDsa44,
        CoseSignatureAlgorithm::MlDsa65,
        CoseSignatureAlgorithm::MlDsa87,
    ] {
        for kid in [None, Some(&[][..]), Some(&b"identifier"[..])] {
            for payload in [None, Some(vec![]), Some(vec![0x55; 256])] {
                for tag in [false, true] {
                    // These synthetic signatures isolate serialization from
                    // provider randomness. Published vectors verify the crypto.
                    let cose = CoseSign1 {
                        protected: build_protected_header(algorithm, kid).expect("header"),
                        payload: payload.clone(),
                        signature: vec![0x33; 64],
                        ..Default::default()
                    };
                    let mut reference = cose.clone().to_cbor_value().expect("coset encoding");
                    if tag {
                        reference = Value::Tag(18, Box::new(reference));
                    }
                    let mut expected = Vec::new();
                    ciborium::ser::into_writer(&reference, &mut expected).expect("CBOR");
                    let actual =
                        encode_cose_sign1(cose, CoseSign1EncodeOptions::default().with_tag(tag))
                            .expect("sensitive encoding");
                    assert_eq!(actual.as_slice(), expected);
                }
            }
        }
    }
}
