// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use allocation_counter::measure;
use ciborium::value::Value;

use super::encode_cbor_value;
use crate::CoseError;

#[test]
fn sensitive_cbor_output_uses_exactly_one_allocation() -> Result<(), CoseError> {
    let value = Value::Array(vec![
        Value::Bytes(vec![0x41; 4_096]),
        Value::Bytes(vec![0x53; 4_627]),
    ]);
    let mut result = None;

    // Initialize the counter's thread-local state before measuring the encoder.
    let _ = measure(|| {});
    let allocations = measure(|| {
        result = Some(encode_cbor_value(value));
    });
    let encoded = result.ok_or(CoseError::Cbor)??;
    let capacity_u64 =
        u64::try_from(encoded.capacity()).map_err(|_| CoseError::ResourceLimitExceeded)?;

    // The input tree is consumed and freed inside the measured closure, so net
    // allocation fields include those deallocations. Total allocations still
    // isolates the property under test: only the final output buffer allocates.
    assert_eq!(allocations.count_total, 1);
    assert_eq!(allocations.count_max, 1);
    assert_eq!(allocations.bytes_total, capacity_u64);
    Ok(())
}
