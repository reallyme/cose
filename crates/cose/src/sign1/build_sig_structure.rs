// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::CoseError;

const CBOR_DIRECT_ARGUMENT_MAX: usize = 23;
const CBOR_ONE_BYTE_ARGUMENT_MAX: usize = 0xff;
const CBOR_TWO_BYTE_ARGUMENT_MAX: usize = 0xffff;
const CBOR_FOUR_BYTE_ARGUMENT_MAX: usize = 0xffff_ffff;

/// Build Sig_structure bytes per RFC 9052 §4.4.
pub(crate) fn build_sig_structure(
    protected_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    const ARRAY_OF_FOUR: u8 = 0x84;
    const SIGNATURE1_TEXT: &[u8] = b"Signature1";
    const SIGNATURE1_TEXT_HEADER: u8 = 0x6a;

    let capacity = 1usize
        .checked_add(1)
        .and_then(|size| size.checked_add(SIGNATURE1_TEXT.len()))
        .and_then(|size| checked_bstr_size(size, protected_bytes.len()))
        .and_then(|size| checked_bstr_size(size, external_aad.len()))
        .and_then(|size| checked_bstr_size(size, payload.len()))
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    encoded.push(ARRAY_OF_FOUR);
    encoded.push(SIGNATURE1_TEXT_HEADER);
    encoded.extend_from_slice(SIGNATURE1_TEXT);
    append_bstr(&mut encoded, protected_bytes)?;
    append_bstr(&mut encoded, external_aad)?;
    append_bstr(&mut encoded, payload)?;
    Ok(encoded)
}

fn checked_bstr_size(current: usize, payload_len: usize) -> Option<usize> {
    current
        .checked_add(cbor_length_header_size(payload_len))?
        .checked_add(payload_len)
}

const fn cbor_length_header_size(length: usize) -> usize {
    if length <= CBOR_DIRECT_ARGUMENT_MAX {
        1
    } else if length <= CBOR_ONE_BYTE_ARGUMENT_MAX {
        2
    } else if length <= CBOR_TWO_BYTE_ARGUMENT_MAX {
        3
    } else if length <= CBOR_FOUR_BYTE_ARGUMENT_MAX {
        5
    } else {
        9
    }
}

#[cfg(test)]
#[path = "build_sig_structure_tests.rs"]
mod tests;

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
