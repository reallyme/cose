// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proto-first RFC 9360 x5chain signing contract coverage.

use buffa::Message;
use reallyme_cose::wire::{
    CoseSign1CreateResult, CoseSign1Options, CoseSignatureAlgorithm, CoseX5Chain,
};

use crate::support::{gen_p256, sample_payload, OperationOutputStatus};

use super::{execute_cose_sign1_create_request, sign1_create_request};

#[test]
fn sign1_wire_contract_preserves_es256_and_x5chain() {
    const LEAF_CERTIFICATE_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];

    let key = gen_p256();
    let mut create = sign1_create_request(
        CoseSignatureAlgorithm::Es256,
        sample_payload(),
        key.private,
        Vec::new(),
        false,
    );
    create.options = buffa::MessageField::some(CoseSign1Options {
        tag: false,
        max_cose_sign1_bytes: 0,
        x5chain: buffa::MessageField::some(CoseX5Chain {
            certificates_der: vec![LEAF_CERTIFICATE_DER.to_vec()],
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    });

    let signed = execute_cose_sign1_create_request(&create.encode_to_vec());
    assert_eq!(signed.status(), OperationOutputStatus::Result);
    let result = CoseSign1CreateResult::decode_from_slice(signed.bytes())
        .expect("ES256 x5chain create result must decode");
    let sign1: ciborium::value::Value = ciborium::de::from_reader(result.cose_sign1.as_slice())
        .expect("COSE_Sign1 must be valid CBOR");
    let fields = match sign1 {
        ciborium::value::Value::Array(fields) => fields,
        _ => panic!("COSE_Sign1 must be an array"),
    };
    let protected_bytes = fields
        .first()
        .and_then(ciborium::value::Value::as_bytes)
        .expect("protected header must be a byte string");
    let protected: ciborium::value::Value = ciborium::de::from_reader(protected_bytes.as_slice())
        .expect("protected header must be valid CBOR");
    let protected_entries = protected.as_map().expect("protected header must be a map");
    assert!(protected_entries.iter().any(|(label, value)| {
        label.as_integer().map(i128::from) == Some(1)
            && value.as_integer().map(i128::from) == Some(-7)
    }));

    let unprotected_entries = fields
        .get(1)
        .and_then(ciborium::value::Value::as_map)
        .expect("unprotected header must be a map");
    assert!(unprotected_entries.iter().any(|(label, value)| {
        label.as_integer().map(i128::from) == Some(33)
            && value
                .as_bytes()
                .is_some_and(|bytes| bytes.as_slice() == LEAF_CERTIFICATE_DER)
    }));
}
