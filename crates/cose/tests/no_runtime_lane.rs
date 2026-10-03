// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Assertions for the structure-only build without a crypto runtime.

#![cfg(not(feature = "cose-crypto"))]

use reallyme_cose::{cose_key_from_public_bytes, Algorithm, CoseError};

#[test]
fn key_construction_without_a_runtime_lane_fails_closed() {
    let public_key = [9_u8; 32];
    assert_eq!(
        cose_key_from_public_bytes(Algorithm::X25519, &public_key).err(),
        Some(CoseError::UnsupportedAlgorithm),
    );
}
