// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{independent_verify, Algorithm, AuditResult};

#[test]
fn ed25519_oracle_rejects_identity_point_forgery() -> AuditResult<()> {
    // A permissive Ed25519 verifier accepts R = identity, S = 0 under
    // A = identity for every message. Such a key provides no authentication.
    let mut public_key = [0_u8; 32];
    public_key[0] = 1;
    let mut signature = [0_u8; 64];
    signature[0] = 1;
    for message in [b"first message".as_slice(), b"different message".as_slice()] {
        assert!(!independent_verify(
            Algorithm::Ed25519,
            &public_key,
            message,
            &signature
        )?);
    }
    Ok(())
}
