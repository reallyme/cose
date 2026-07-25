// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::CoseError;

use super::SensitiveCborValue;

const HOSTILE_NESTING_DEPTH: usize = 40;

#[test]
fn decode_cose_key_rejects_excessive_nesting_before_tree_decode() {
    let mut encoded = Vec::with_capacity(HOSTILE_NESTING_DEPTH.saturating_add(1));
    encoded.extend(core::iter::repeat_n(0x81, HOSTILE_NESTING_DEPTH));
    encoded.push(0xf6);

    assert!(matches!(
        SensitiveCborValue::decode_cose_key(&encoded),
        Err(CoseError::ResourceLimitExceeded),
    ));
}
