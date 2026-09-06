// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use ciborium::value::Value;
use coset::{iana, AsCborValue, CoseEncrypt, CoseRecipient, RegisteredLabelWithPrivate};

use super::{body_unprotected, encode, protected_header, recipient_unprotected};
use crate::encrypt::profile::suite_for;
use crate::encrypt::{CoseMlKemAlgorithm, CoseMlKemMode};

#[test]
fn sensitive_encrypt_encoder_matches_coset_for_every_suite() {
    for kem in [
        CoseMlKemAlgorithm::MlKem512,
        CoseMlKemAlgorithm::MlKem768,
        CoseMlKemAlgorithm::MlKem1024,
    ] {
        for mode in [CoseMlKemMode::Direct, CoseMlKemMode::KeyWrap] {
            let suite = suite_for(kem, mode).expect("supported suite");
            for content in [
                iana::Algorithm::A128GCM,
                iana::Algorithm::A192GCM,
                iana::Algorithm::A256GCM,
            ] {
                // Synthetic ciphertext isolates representation, including the
                // direct-mode null versus wrapped-key byte string distinction.
                let cose = CoseEncrypt {
                    protected: protected_header(
                        RegisteredLabelWithPrivate::Assigned(content),
                        None,
                    ),
                    unprotected: body_unprotected(&[0x44; 12]),
                    ciphertext: Some(vec![0x55; 256]),
                    recipients: vec![CoseRecipient {
                        protected: protected_header(
                            RegisteredLabelWithPrivate::PrivateUse(suite.cose_algorithm),
                            Some(&[0x11; 32]),
                        ),
                        unprotected: recipient_unprotected(vec![
                            0x22;
                            suite.encapsulated_key_length
                        ]),
                        ciphertext: match mode {
                            CoseMlKemMode::Direct => None,
                            CoseMlKemMode::KeyWrap => Some(vec![0x33; 40]),
                        },
                        recipients: Vec::new(),
                    }],
                };
                let reference =
                    Value::Tag(96, Box::new(cose.clone().to_cbor_value().expect("coset")));
                let mut expected = Vec::new();
                ciborium::ser::into_writer(&reference, &mut expected).expect("CBOR");
                assert_eq!(
                    encode(cose).expect("sensitive encoding").as_slice(),
                    expected
                );
            }
        }
    }
}
