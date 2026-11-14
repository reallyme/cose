// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use coset::ProtectedHeader;
use zeroize::Zeroizing;

use crate::build_authentication_structure::{
    build_authentication_structure, AuthenticationContext,
};
use crate::CoseError;

/// Build Sig_structure bytes per RFC 9052 §4.4.
pub(crate) fn build_sig_structure(
    protected_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    build_authentication_structure(
        AuthenticationContext::Signature1,
        protected_bytes,
        external_aad,
        payload,
    )
}

/// Prepare verification input while preserving the received protected header bstr.
pub(super) fn build_received_sig_structure(
    protected: &ProtectedHeader,
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    // The wire decoder always records the original bstr, including an empty
    // one. A missing bstr means the input did not come from that decoder.
    let protected_bytes = protected
        .original_data
        .as_deref()
        .ok_or(CoseError::InvalidFormat)?;
    build_sig_structure(protected_bytes, external_aad, payload)
}

#[cfg(kani)]
#[path = "verify_sig_structure_proof_tests.rs"]
mod verification;

#[cfg(test)]
#[path = "build_sig_structure_tests.rs"]
mod tests;
