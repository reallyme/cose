// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::read_cbor::Item;
use super::read_headers::{read_headers, Headers};
use super::{ContainerError, ContainerErrorReason as Reason};

pub(super) const COSE_SIGN1_TAG: u64 = 18;

pub(super) struct Envelope<'a> {
    pub tagged: bool,
    pub protected: &'a [u8],
    pub unprotected: &'a [u8],
    pub headers: Headers<'a>,
    pub payload: Option<&'a [u8]>,
    pub signature: &'a [u8],
}

pub(super) fn decode(encoded: &[u8]) -> Result<Envelope<'_>, ContainerError> {
    super::validate_preferred_cbor(encoded)?;
    let mut item = Item::from_validated(encoded)?;
    let tagged = item.major == 6;
    if tagged {
        if item.argument != COSE_SIGN1_TAG {
            return Err(Reason::Profile.into());
        }
        item = item.cursor()?.next()?;
    }
    if item.count(4)? != 4 {
        return Err(Reason::Malformed.into());
    }
    let mut cursor = item.cursor()?;
    let protected = cursor.next()?.bytes()?;
    let unprotected = cursor.next()?;
    let headers = read_headers(protected, unprotected)?;
    let content = cursor.next()?;
    let payload = match (content.major, content.argument) {
        (2, _) => Some(content.bytes()?),
        (7, 22) => None,
        _ => return Err(Reason::Malformed.into()),
    };
    let signature = cursor.next()?.bytes()?;
    Ok(Envelope {
        tagged,
        protected,
        unprotected: unprotected.encoded,
        headers,
        payload,
        signature,
    })
}
