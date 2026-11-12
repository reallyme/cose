// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use zeroize::Zeroizing;

use crate::limits::{MAX_COSE_MAC0_BYTES, MAX_DETACHED_PAYLOAD_BYTES, MAX_MAC0_EXTERNAL_AAD_BYTES};
use crate::mac0::{cose_verify_mac0_detached, CoseMac0Error, CoseMac0ErrorReason, CoseMacKey};

use super::support::{
    assert_reason, detached, encode, envelope, hex, request, tag, verify, ALGORITHM, KEY,
};

#[test]
fn maximum_encoded_size_and_header_count_are_accepted() -> Result<(), CoseMac0Error> {
    let entries = (0..31).map(|index| (Value::Text(index.to_string()), Value::Null));
    let mut protected_entries = vec![(1.into(), 5.into())];
    protected_entries.extend(entries);
    let protected = encode(Value::Map(protected_entries));
    verify(&detached(&protected, &tag(&protected, b"payload", b"aad")))?;

    let protected = hex("a10105");
    // One extension byte string fills the unprotected bucket up to the exact
    // wire cap. Its fixed overhead includes the three-byte bstr length header.
    const ENVELOPE_OVERHEAD: usize = 45;
    let padding = vec![0; MAX_COSE_MAC0_BYTES - ENVELOPE_OVERHEAD];
    let encoded = envelope(
        &protected,
        Value::Map(vec![(0.into(), Value::Bytes(padding))]),
        Value::Null,
        &tag(&protected, b"payload", b"aad"),
    );
    assert_eq!(encoded.len(), MAX_COSE_MAC0_BYTES);
    verify(&encoded)?;
    Ok(())
}

#[test]
fn caller_byte_limits_accept_the_boundary_and_reject_one_over() -> Result<(), CoseMac0Error> {
    let protected = hex("a10105");
    let encoded = detached(&protected, &tag(&protected, b"payload", b"aad"));
    let key = CoseMacKey::new(ALGORITHM, Zeroizing::new(KEY.to_vec()))?;
    let mut input = request(&encoded, b"payload", b"aad");
    input.limits.max_encoded_bytes = encoded.len();
    input.limits.max_payload_bytes = 7;
    input.limits.max_external_aad_bytes = 3;
    cose_verify_mac0_detached(input, &key)?;
    for field in 0..3 {
        let mut input = request(&encoded, b"payload", b"aad");
        match field {
            0 => input.limits.max_encoded_bytes = encoded.len() - 1,
            1 => input.limits.max_payload_bytes = 6,
            _ => input.limits.max_external_aad_bytes = 2,
        }
        assert_reason(
            cose_verify_mac0_detached(input, &key),
            CoseMac0ErrorReason::ResourceLimitExceeded,
        );
    }
    Ok(())
}

#[test]
fn hard_limits_cannot_be_raised_and_fail_before_parsing() -> Result<(), CoseMac0Error> {
    let key = CoseMacKey::new(ALGORITHM, Zeroizing::new(KEY.to_vec()))?;
    for (encoded, payload, aad) in [
        (vec![0; MAX_COSE_MAC0_BYTES + 1], vec![], vec![]),
        (vec![], vec![0; MAX_DETACHED_PAYLOAD_BYTES + 1], vec![]),
        (vec![], vec![], vec![0; MAX_MAC0_EXTERNAL_AAD_BYTES + 1]),
    ] {
        let mut input = request(&encoded, &payload, &aad);
        input.limits.max_encoded_bytes = usize::MAX;
        input.limits.max_payload_bytes = usize::MAX;
        input.limits.max_external_aad_bytes = usize::MAX;
        assert_reason(
            cose_verify_mac0_detached(input, &key),
            CoseMac0ErrorReason::ResourceLimitExceeded,
        );
    }
    Ok(())
}

#[test]
fn maximum_payload_and_aad_are_accepted() -> Result<(), CoseMac0Error> {
    let protected = hex("a10105");
    let payload = vec![0x44; MAX_DETACHED_PAYLOAD_BYTES];
    let aad = vec![0x33; MAX_MAC0_EXTERNAL_AAD_BYTES];
    let encoded = detached(&protected, &tag(&protected, &payload, &aad));
    let key = CoseMacKey::new(ALGORITHM, Zeroizing::new(KEY.to_vec()))?;
    cose_verify_mac0_detached(request(&encoded, &payload, &aad), &key)?;
    Ok(())
}

#[test]
fn oversized_collections_nesting_and_lengths_fail_without_large_allocations() {
    let mut nested = Value::Null;
    for _ in 0..33 {
        nested = Value::Array(vec![nested]);
    }
    let protected = encode(Value::Map(vec![
        (1.into(), 5.into()),
        (Value::Text("x".into()), nested),
    ]));
    assert_reason(
        verify(&detached(&protected, &[0; 32])),
        CoseMac0ErrorReason::ResourceLimitExceeded,
    );
    let entries = (0..33)
        .map(|index| (Value::Text(index.to_string()), Value::Null))
        .collect();
    let protected = encode(Value::Map(entries));
    assert_reason(
        verify(&detached(&protected, &[0; 32])),
        CoseMac0ErrorReason::ResourceLimitExceeded,
    );
    let protected = hex("a201056178990401");
    assert_reason(
        verify(&detached(&protected, &[0; 32])),
        CoseMac0ErrorReason::ResourceLimitExceeded,
    );
    for (bytes, reason) in [
        (
            "8443a10105a0f65bffffffffffffffff",
            CoseMac0ErrorReason::MalformedCbor,
        ),
        ("845bffffffffffffffff", CoseMac0ErrorReason::MalformedCbor),
        (
            "8443a10105bbffffffffffffffff",
            CoseMac0ErrorReason::ResourceLimitExceeded,
        ),
    ] {
        assert_reason(verify(&hex(bytes)), reason);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn errors_are_copy_values_and_byte_limit_rejection_allocates_nothing() -> Result<(), CoseMac0Error>
{
    let key = CoseMacKey::new(ALGORITHM, Zeroizing::new(KEY.to_vec()))?;
    let encoded = vec![0; MAX_COSE_MAC0_BYTES + 1];
    let info = allocation_counter::measure(|| {
        let result = cose_verify_mac0_detached(request(&encoded, &[], &[]), &key);
        assert_reason(result, CoseMac0ErrorReason::ResourceLimitExceeded);
    });
    assert_eq!(info.count_total, 0);
    fn requires_copy<T: Copy>() {}
    requires_copy::<CoseMac0Error>();
    Ok(())
}
