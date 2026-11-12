// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

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

#[cfg(test)]
#[path = "build_sig_structure_tests.rs"]
mod tests;
