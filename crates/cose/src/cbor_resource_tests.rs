// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::cbor::general::{self, ErrorReason};

use crate::{containers::validate_preferred_cbor, zeroize_coset::SensitiveCborValue, CoseError};

// Pin the admission contract independently of codec's default constants so a
// dependency update cannot silently widen the tree-copying allocation budget.
const MAX_NODES: usize = 65_536;
const ONE_MIB: usize = 1_048_576;
const ROWS: usize = 64;
const ROW_ENTRIES: usize = 1_024;

fn dense_array(nodes: usize) -> Result<Vec<u8>, CoseError> {
    let containers = ROWS
        .checked_add(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let mut leaves = nodes
        .checked_sub(containers)
        .ok_or(CoseError::InvalidFormat)?;
    let mut encoded = vec![0x98, 0x40]; // 64 rows; each leaf is one null node.
    for _ in 0..ROWS {
        let count = leaves.min(ROW_ENTRIES);
        // These fixtures use 16-bit preferred counts in every row.
        if count < 256 {
            return Err(CoseError::InvalidFormat);
        }
        encoded.push(0x99);
        encoded.extend_from_slice(
            &u16::try_from(count)
                .map_err(|_| CoseError::ResourceLimitExceeded)?
                .to_be_bytes(),
        );
        let end = encoded
            .len()
            .checked_add(count)
            .ok_or(CoseError::ResourceLimitExceeded)?;
        encoded.resize(end, 0xf6);
        leaves = leaves
            .checked_sub(count)
            .ok_or(CoseError::ResourceLimitExceeded)?;
    }
    if leaves != 0 {
        return Err(CoseError::InvalidFormat);
    }
    Ok(encoded)
}

fn dense_encrypt() -> Result<Vec<u8>, CoseError> {
    // A structurally valid four-slot Encrypt envelope. Its unprotected
    // extension is dense while its ciphertext fills the byte budget. A byte
    // ceiling alone would not prevent a large decoded Value tree.
    let mut encoded = vec![0x84, 0x40, 0xa1, 0x18, 0x64];
    encoded.extend_from_slice(&dense_array(MAX_NODES)?);
    const RECIPIENT: &[u8] = &[0x81, 0x83, 0x40, 0xa0, 0xf6];
    const BYTE_STRING_HEADER: usize = 5;
    let padding = ONE_MIB
        .checked_sub(encoded.len())
        .and_then(|remaining| remaining.checked_sub(BYTE_STRING_HEADER))
        .and_then(|remaining| remaining.checked_sub(RECIPIENT.len()))
        .ok_or(CoseError::ResourceLimitExceeded)?;
    encoded.push(0x5a);
    encoded.extend_from_slice(
        &u32::try_from(padding)
            .map_err(|_| CoseError::ResourceLimitExceeded)?
            .to_be_bytes(),
    );
    let end = encoded
        .len()
        .checked_add(padding)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    encoded.resize(end, 0);
    encoded.extend_from_slice(RECIPIENT);
    assert_eq!(encoded.len(), ONE_MIB);
    Ok(encoded)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn aggregate_node_limit_accepts_65536_and_rejects_the_next_node() -> Result<(), CoseError> {
    assert_eq!(super::limits()?.nodes(), MAX_NODES);
    validate_preferred_cbor(&dense_array(MAX_NODES)?)?;
    let over = dense_array(
        MAX_NODES
            .checked_add(1)
            .ok_or(CoseError::ResourceLimitExceeded)?,
    )?;
    assert_eq!(
        validate_preferred_cbor(&over),
        Err(CoseError::ResourceLimitExceeded)
    );
    let failure = general::validate_exact(&over, super::preferred(false)?, super::limits()?);
    assert_eq!(
        failure.err().map(|error| error.reason()),
        Some(ErrorReason::NodeLimit)
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn dense_one_mib_input_is_rejected_before_owned_tree_construction() -> Result<(), CoseError> {
    let encoded = dense_encrypt()?;
    assert_eq!(
        validate_preferred_cbor(&encoded),
        Err(CoseError::ResourceLimitExceeded)
    );
    assert_eq!(
        SensitiveCborValue::decode_cose_encrypt(&encoded).err(),
        Some(CoseError::ResourceLimitExceeded)
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn dense_node_limit_rejection_allocates_no_tree_or_error_storage() -> Result<(), CoseError> {
    let encoded = dense_encrypt()?;
    let measured = allocation_counter::measure(|| {
        assert_eq!(
            SensitiveCborValue::decode_cose_encrypt(&encoded).err(),
            Some(CoseError::ResourceLimitExceeded)
        );
    });
    assert_eq!(measured.count_total, 0);
    assert_eq!(measured.bytes_total, 0);
    Ok(())
}
