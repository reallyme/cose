// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::Zeroizing;

use crate::build_authentication_structure::{
    build_bounded_authentication_structure, AuthenticationContext,
};
use crate::CoseError;

/// Encode the RFC 9052 section 4.4 `Sig_structure` for COSE_Sign1.
///
/// The context is always `"Signature1"`. All three input slices are encoded as
/// byte strings, preserving the received protected-header bytes exactly. The
/// helper applies the caller's complete output budget, independently of the
/// Sign1 verification-profile limits. Empty external AAD is permitted.
///
/// The caller retains ownership of the input slices. The returned owner wipes
/// the encoded authentication input, including its payload, on drop.
///
/// # Errors
///
/// Returns [`CoseError::ResourceLimitExceeded`] when encoded-length arithmetic
/// overflows, the complete output exceeds `max_output_bytes`, or the fallible
/// output reservation fails. Budget rejection occurs before output allocation.
pub fn build_sign1_signature_structure(
    protected: &[u8],
    external_aad: &[u8],
    payload: &[u8],
    max_output_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    build_bounded_authentication_structure(
        AuthenticationContext::Signature1,
        protected,
        external_aad,
        payload,
        max_output_bytes,
    )
}
