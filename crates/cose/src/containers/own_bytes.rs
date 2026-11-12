// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerError, ContainerErrorReason as Reason};
use zeroize::Zeroizing;

pub(super) fn copy(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
    let mut result = Zeroizing::new(Vec::new());
    result
        .try_reserve_exact(bytes.len())
        .map_err(|_| Reason::Limit)?;
    result.extend_from_slice(bytes);
    Ok(result)
}

pub(super) fn reserve(bytes: &mut Vec<u8>, additional: usize) -> Result<(), ContainerError> {
    bytes.len().checked_add(additional).ok_or(Reason::Limit)?;
    bytes
        .try_reserve_exact(additional)
        .map_err(|_| Reason::Limit.into())
}

pub(super) fn head(output: &mut Vec<u8>, major: u8, n: u64) -> Result<(), ContainerError> {
    reserve(output, 9)?;
    match n {
        0..=23 => output.push((major << 5) | u8::try_from(n).map_err(|_| Reason::Limit)?),
        24..=0xff => {
            output.push((major << 5) | 24);
            output.push(u8::try_from(n).map_err(|_| Reason::Limit)?);
        }
        0x100..=0xffff => {
            output.push((major << 5) | 25);
            output.extend_from_slice(&u16::try_from(n).map_err(|_| Reason::Limit)?.to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push((major << 5) | 26);
            output.extend_from_slice(&u32::try_from(n).map_err(|_| Reason::Limit)?.to_be_bytes());
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend_from_slice(&n.to_be_bytes());
        }
    }
    Ok(())
}

pub(super) fn bstr(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ContainerError> {
    head(
        output,
        2,
        u64::try_from(bytes.len()).map_err(|_| Reason::Limit)?,
    )?;
    reserve(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}
