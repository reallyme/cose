// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::Zeroizing;

use crate::CoseError;

#[path = "measure_authentication_structure.rs"]
mod measure;

#[cfg(feature = "cose-crypto")]
use measure::checked_bstr_size;

/// Domain separation contexts supported by the single-authenticator profiles.
#[derive(Clone, Copy)]
pub(crate) enum AuthenticationContext {
    Signature1,
    #[cfg(feature = "cose-crypto")]
    Mac0,
}

/// Encode a four-field COSE authentication structure without normalizing protected bytes.
#[cfg(feature = "cose-crypto")]
pub(crate) fn build_authentication_structure(
    context: AuthenticationContext,
    protected_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    build_bounded_authentication_structure(
        context,
        protected_bytes,
        external_aad,
        payload,
        usize::MAX,
    )
}

pub(crate) fn build_bounded_authentication_structure(
    context: AuthenticationContext,
    protected_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
    max_output_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    const ARRAY_OF_FOUR: u8 = 0x84;
    const TEXT_MAJOR: u8 = 0x60;
    // Typed contexts prevent accidental loss of domain separation. Both use
    // a direct-length text header and are always valid UTF-8.
    let context: &[u8] = match context {
        AuthenticationContext::Signature1 => b"Signature1",
        #[cfg(feature = "cose-crypto")]
        AuthenticationContext::Mac0 => b"MAC0",
    };
    let context_len = u8::try_from(context.len()).map_err(|_| CoseError::InvalidFormat)?;

    let capacity = measure::authentication_structure_size(
        context.len(),
        protected_bytes.len(),
        external_aad.len(),
        payload.len(),
        max_output_bytes,
    )?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    encoded.push(ARRAY_OF_FOUR);
    encoded.push(TEXT_MAJOR | context_len);
    encoded.extend_from_slice(context);
    append_bstr(&mut encoded, protected_bytes)?;
    append_bstr(&mut encoded, external_aad)?;
    append_bstr(&mut encoded, payload)?;
    Ok(encoded)
}

#[cfg(test)]
#[cfg(feature = "cose-crypto")]
#[path = "build_authentication_structure_tests.rs"]
mod tests;

#[cfg(all(kani, feature = "cose-crypto"))]
#[path = "verify_authentication_lengths_proof_tests.rs"]
mod verification;

#[cfg(feature = "cose-crypto")]
pub(crate) fn encoded_bstr_size(payload_len: usize) -> Result<usize, CoseError> {
    checked_bstr_size(0, payload_len).ok_or(CoseError::ResourceLimitExceeded)
}

fn append_bstr(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CoseError> {
    const BSTR_MAJOR: u8 = 0x40;
    match bytes.len() {
        0..=23 => {
            let length = u8::try_from(bytes.len()).map_err(|_| CoseError::ResourceLimitExceeded)?;
            output.push(BSTR_MAJOR | length);
        }
        24..=0xff => {
            output.push(BSTR_MAJOR | 24);
            output.push(u8::try_from(bytes.len()).map_err(|_| CoseError::ResourceLimitExceeded)?);
        }
        0x100..=0xffff => {
            output.push(BSTR_MAJOR | 25);
            output.extend_from_slice(
                &u16::try_from(bytes.len())
                    .map_err(|_| CoseError::ResourceLimitExceeded)?
                    .to_be_bytes(),
            );
        }
        0x1_0000..=0xffff_ffff => {
            output.push(BSTR_MAJOR | 26);
            output.extend_from_slice(
                &u32::try_from(bytes.len())
                    .map_err(|_| CoseError::ResourceLimitExceeded)?
                    .to_be_bytes(),
            );
        }
        _ => {
            output.push(BSTR_MAJOR | 27);
            output.extend_from_slice(
                &u64::try_from(bytes.len())
                    .map_err(|_| CoseError::ResourceLimitExceeded)?
                    .to_be_bytes(),
            );
        }
    }
    output.extend_from_slice(bytes);
    Ok(())
}
