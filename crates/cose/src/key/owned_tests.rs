// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use ciborium::value::Value;
use coset::{Label, RegisteredLabel, RegisteredLabelWithPrivate};

use super::zeroize_cose_key;

#[test]
fn rejected_text_labels_and_owned_values_are_wiped() {
    let mut key = coset::CoseKey {
        kty: RegisteredLabel::Text("sensitive-kty".to_owned()),
        key_id: b"sensitive-kid".to_vec(),
        alg: Some(RegisteredLabelWithPrivate::Text("sensitive-alg".to_owned())),
        key_ops: [RegisteredLabel::Text("sensitive-operation".to_owned())]
            .into_iter()
            .collect(),
        base_iv: b"sensitive-base-iv".to_vec(),
        params: vec![(
            Label::Text("sensitive-label".to_owned()),
            Value::Bytes(b"sensitive-value".to_vec()),
        )],
    };

    zeroize_cose_key(&mut key);

    assert!(matches!(key.kty, RegisteredLabel::Text(ref value) if value.is_empty()));
    assert!(key.key_id.iter().all(|byte| *byte == 0));
    assert!(
        matches!(key.alg, Some(RegisteredLabelWithPrivate::Text(ref value)) if value.is_empty())
    );
    assert!(key.key_ops.is_empty());
    assert!(key.base_iv.iter().all(|byte| *byte == 0));
    assert!(matches!(
        key.params.as_slice(),
        [(Label::Text(label), Value::Bytes(value))]
            if label.is_empty() && value.iter().all(|byte| *byte == 0)
    ));
}
