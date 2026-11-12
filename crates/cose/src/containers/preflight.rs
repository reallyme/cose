// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::read_cbor::{head, Cursor, Item, MAX_DEPTH, MAX_SCAN_WORK};
use super::{ContainerError, ContainerErrorReason as Reason};

const MAX_NODES: usize = 65_536;
const MAX_COMPARISONS: usize = 1_048_576;
const MAX_COLLECTION: usize = 1_024;

/// Check definite, preferred RFC 8949 serialization without requiring map order.
///
/// Tags and float widths are checked too. This is a CBOR encoding preflight,
/// not validation of the complete ISO document grammar or application schema.
/// The caller must bound the encoded byte slice for its own boundary.
///
/// # Errors
/// Returns fixed encoding, duplicate, malformed, or resource-limit errors.
pub fn validate_preferred_cbor(encoded: &[u8]) -> Result<(), ContainerError> {
    if encoded.len() > crate::limits::MAX_DETACHED_PAYLOAD_BYTES {
        return Err(Reason::Limit.into());
    }
    let mut work = Work {
        nodes: 0,
        comparisons: 0,
        scans: MAX_SCAN_WORK,
    };
    let consumed = validate(encoded, 0, &mut work)?;
    if consumed != encoded.len() {
        return Err(Reason::Malformed.into());
    }
    Ok(())
}

struct Work {
    nodes: usize,
    comparisons: usize,
    scans: usize,
}

fn validate(input: &[u8], depth: usize, work: &mut Work) -> Result<usize, ContainerError> {
    work.nodes = work.nodes.checked_add(1).ok_or(Reason::Limit)?;
    if depth > MAX_DEPTH || work.nodes > MAX_NODES {
        return Err(Reason::Limit.into());
    }
    let (major, additional, arg, start) = head(input)?;
    let next_depth = depth.checked_add(1).ok_or(Reason::Limit)?;
    match major {
        0 | 1 => Ok(start),
        2 | 3 => {
            let end = start
                .checked_add(usize::try_from(arg).map_err(|_| Reason::Limit)?)
                .ok_or(Reason::Limit)?;
            let data = input.get(start..end).ok_or(Reason::Malformed)?;
            if major == 3 {
                core::str::from_utf8(data).map_err(|_| Reason::Malformed)?;
            }
            Ok(end)
        }
        4..=6 => {
            let count = if major == 6 {
                1
            } else {
                usize::try_from(arg).map_err(|_| Reason::Limit)?
            };
            if count > MAX_COLLECTION {
                return Err(Reason::Limit.into());
            }
            let mut end = start;
            for _ in 0..count {
                let key_start = end;
                let size = validate(input.get(end..).ok_or(Reason::Malformed)?, next_depth, work)?;
                end = end.checked_add(size).ok_or(Reason::Limit)?;
                if major == 5 {
                    let current =
                        Item::from_validated(input.get(key_start..end).ok_or(Reason::Malformed)?)?;
                    let mut previous = Cursor {
                        remaining: input.get(start..key_start).ok_or(Reason::Malformed)?,
                    };
                    while !previous.remaining.is_empty() {
                        if equivalent(previous.next_with_budget(&mut work.scans)?, current, work)? {
                            return Err(Reason::Duplicate.into());
                        }
                        previous.next_with_budget(&mut work.scans)?;
                    }
                    let size =
                        validate(input.get(end..).ok_or(Reason::Malformed)?, next_depth, work)?;
                    end = end.checked_add(size).ok_or(Reason::Limit)?;
                }
            }
            Ok(end)
        }
        7 => {
            validate_simple(additional, arg)?;
            Ok(start)
        }
        _ => Err(Reason::Malformed.into()),
    }
}

// Compound CBOR map keys compare by value, including maps with different order.
// This deliberately has an independent work budget; adversarial nested map keys
// must not turn a bounded message into unbounded duplicate-detection work.
fn equivalent(a: Item<'_>, b: Item<'_>, work: &mut Work) -> Result<bool, ContainerError> {
    let cost = a
        .encoded
        .len()
        .checked_add(b.encoded.len())
        .ok_or(Reason::Limit)?;
    work.comparisons = work.comparisons.checked_add(cost).ok_or(Reason::Limit)?;
    if work.comparisons > MAX_COMPARISONS {
        return Err(Reason::Limit.into());
    }
    if a.encoded == b.encoded {
        return Ok(true);
    }
    if a.major != b.major || a.argument != b.argument {
        return Ok(false);
    }
    if !matches!(a.major, 4..=6) {
        return Ok(false);
    }
    let mut ac = a.cursor();
    if a.major == 5 {
        while !ac.remaining.is_empty() {
            let ak = ac.next_with_budget(&mut work.scans)?;
            let av = ac.next_with_budget(&mut work.scans)?;
            let mut bc = b.cursor();
            let mut found = false;
            while !bc.remaining.is_empty() {
                let bk = bc.next_with_budget(&mut work.scans)?;
                let bv = bc.next_with_budget(&mut work.scans)?;
                if equivalent(ak, bk, work)? && equivalent(av, bv, work)? {
                    found = true;
                    break;
                }
            }
            if !found {
                return Ok(false);
            }
        }
        Ok(true)
    } else {
        let mut bc = b.cursor();
        while !ac.remaining.is_empty() {
            if !equivalent(
                ac.next_with_budget(&mut work.scans)?,
                bc.next_with_budget(&mut work.scans)?,
                work,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn validate_simple(additional: u8, arg: u64) -> Result<(), ContainerError> {
    match additional {
        0..=23 => Ok(()),
        24 if arg >= 32 => Ok(()),
        25 => Ok(()),
        26 => {
            let value = f32::from_bits(u32::try_from(arg).map_err(|_| Reason::Malformed)?);
            if value.is_nan() || half::f16::from_f32(value).to_f32().to_bits() == value.to_bits() {
                return Err(Reason::Encoding.into());
            }
            Ok(())
        }
        27 => {
            let value = f64::from_bits(arg);
            // This cast rounds a float value; it is never a length conversion.
            let shorter = f64::from(value as f32);
            if value.is_nan() || shorter.to_bits() == value.to_bits() {
                return Err(Reason::Encoding.into());
            }
            Ok(())
        }
        _ => Err(Reason::Malformed.into()),
    }
}

impl<'a> Item<'a> {
    pub(super) fn from_validated(encoded: &'a [u8]) -> Result<Self, ContainerError> {
        Cursor { remaining: encoded }.next()
    }
}
