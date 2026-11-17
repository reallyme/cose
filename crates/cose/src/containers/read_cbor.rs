// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerError, ContainerErrorReason as Reason};

pub(super) const MAX_DEPTH: usize = 32;
pub(super) const MAX_SCAN_WORK: usize = 1_048_576;

/// Borrowed spans avoid partially allocated sensitive decoder trees entirely.
#[derive(Clone, Copy)]
pub(super) struct Item<'a> {
    pub encoded: &'a [u8],
    pub data: &'a [u8],
    pub major: u8,
    pub argument: u64,
    pub additional: u8,
    pub legacy_widths: bool,
}

impl<'a> Item<'a> {
    pub(super) fn integer(self) -> Result<i64, ContainerError> {
        let n = i64::try_from(self.argument).map_err(|_| Reason::Malformed)?;
        match self.major {
            0 => Ok(n),
            1 => n
                .checked_neg()
                .and_then(|negative| negative.checked_sub(1))
                .ok_or(Reason::Malformed.into()),
            _ => Err(Reason::Malformed.into()),
        }
    }

    pub(super) fn bytes(self) -> Result<&'a [u8], ContainerError> {
        if self.major != 2 {
            return Err(Reason::Malformed.into());
        }
        Ok(self.data)
    }

    pub(super) fn count(self, major: u8) -> Result<usize, ContainerError> {
        if self.major != major {
            return Err(Reason::Malformed.into());
        }
        usize::try_from(self.argument).map_err(|_| Reason::Limit.into())
    }

    pub(super) fn cursor(self) -> Cursor<'a> {
        Cursor {
            remaining: self.data,
            legacy_widths: self.legacy_widths,
        }
    }
}

pub(super) struct Cursor<'a> {
    pub remaining: &'a [u8],
    pub legacy_widths: bool,
}

impl<'a> Cursor<'a> {
    // Only used after the complete bounded preflight, so traversal allocates no
    // trees and cannot expose a successful prefix of malformed input.
    pub(super) fn next(&mut self) -> Result<Item<'a>, ContainerError> {
        let mut remaining_work = MAX_SCAN_WORK;
        self.next_with_budget(&mut remaining_work)
    }

    pub(super) fn next_with_budget(
        &mut self,
        remaining_work: &mut usize,
    ) -> Result<Item<'a>, ContainerError> {
        let (item, consumed) = scan(self.remaining, 0, remaining_work, self.legacy_widths)?;
        self.remaining = self.remaining.get(consumed..).ok_or(Reason::Malformed)?;
        Ok(item)
    }
}

pub(super) fn head_with_width_policy(
    input: &[u8],
    legacy_widths: bool,
) -> Result<(u8, u8, u64, usize), ContainerError> {
    let first = *input.first().ok_or(Reason::Malformed)?;
    let major = first >> 5;
    let additional = first & 31;
    let width: usize = match additional {
        0..=23 => 0,
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        31 => return Err(Reason::Encoding.into()),
        _ => return Err(Reason::Malformed.into()),
    };
    let end = 1usize.checked_add(width).ok_or(Reason::Limit)?;
    let mut value = if width == 0 { u64::from(additional) } else { 0 };
    for byte in input.get(1..end).ok_or(Reason::Malformed)? {
        value = (value << 8) | u64::from(*byte);
    }
    if major != 7
        && !(legacy_widths && major == 6)
        && ((width == 1 && value < 24)
            || (width == 2 && value <= 0xff)
            || (width == 4 && value <= 0xffff)
            || (width == 8 && value <= 0xffff_ffff))
    {
        return Err(Reason::Encoding.into());
    }
    Ok((major, additional, value, end))
}

fn scan<'a>(
    input: &'a [u8],
    depth: usize,
    remaining_work: &mut usize,
    legacy_widths: bool,
) -> Result<(Item<'a>, usize), ContainerError> {
    *remaining_work = remaining_work.checked_sub(1).ok_or(Reason::Limit)?;
    if depth > MAX_DEPTH {
        return Err(Reason::Limit.into());
    }
    let (major, additional, argument, start) = head_with_width_policy(input, legacy_widths)?;
    let mut end = start;
    match major {
        2 | 3 => {
            end = start
                .checked_add(usize::try_from(argument).map_err(|_| Reason::Limit)?)
                .ok_or(Reason::Limit)?;
        }
        4..=6 => {
            let count = match major {
                5 => argument.checked_mul(2).ok_or(Reason::Limit)?,
                6 => 1,
                _ => argument,
            };
            for _ in 0..count {
                let (_, size) = scan(
                    input.get(end..).ok_or(Reason::Malformed)?,
                    depth.checked_add(1).ok_or(Reason::Limit)?,
                    remaining_work,
                    legacy_widths,
                )?;
                end = end.checked_add(size).ok_or(Reason::Limit)?;
            }
        }
        _ => {}
    }
    let encoded = input.get(..end).ok_or(Reason::Malformed)?;
    Ok((
        Item {
            encoded,
            data: input.get(start..end).ok_or(Reason::Malformed)?,
            major,
            argument,
            additional,
            legacy_widths,
        },
        end,
    ))
}
