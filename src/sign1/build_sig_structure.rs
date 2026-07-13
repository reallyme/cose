// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_codec::cbor::{encode_dag_cbor, CborValue};

/// Build Sig_structure bytes per RFC 9052 §4.4.
pub(crate) fn build_sig_structure(protected_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    let structure = CborValue::Array(vec![
        CborValue::String("Signature1".to_string()),
        CborValue::Bytes(protected_bytes.to_vec()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(payload.to_vec()),
    ]);

    encode_dag_cbor(&structure)
}
