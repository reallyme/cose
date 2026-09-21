// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use ciborium::value::Value;
use coset::{AsCborValue, CoseSign1};

use super::{build_protected_header, encode_cose_sign1, CoseSign1EncodeOptions};
use crate::encode_cbor::encode_protected_header;
use crate::sign1::cose_type::CoseType;
use crate::CoseSignatureAlgorithm;

const STATUS_LIST_CWT_MEDIA_TYPE: &str = "application/statuslist+cwt";

#[test]
fn status_list_type_uses_draft_protected_header_shape() {
    let cose_type = CoseType::Text(STATUS_LIST_CWT_MEDIA_TYPE.to_owned());
    let protected = build_protected_header(CoseSignatureAlgorithm::Es256, None, Some(&cose_type))
        .expect("protected header");
    let encoded = encode_protected_header(&protected).expect("protected header encoding");

    // draft-ietf-oauth-status-list-21 uses a two-entry protected map with
    // `alg` (-7 / ES256) followed by RFC 9596 `typ` (label 16).
    let value = encoded
        .strip_prefix(&[0xa2, 0x01, 0x26, 0x10, 0x78, 0x1a])
        .expect("protected header must use the draft map shape");
    assert_eq!(value, STATUS_LIST_CWT_MEDIA_TYPE.as_bytes());
}

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
                        protected: build_protected_header(algorithm, kid, None).expect("header"),
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
