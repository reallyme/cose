// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::read_cbor::Item;
use super::{ContainerError, ContainerErrorReason as Reason};
use crate::limits::{MAX_COSE_X5CHAIN_CERTIFICATES, MAX_COSE_X5CHAIN_TOTAL_BYTES};
use crate::X5ChainHeaderPlacement;

const MAX_HEADERS: usize = 32;
/// Exact SHA-256 registration used by RFC 9360 x5t; never an ES256 selector.
pub const X5T_SHA256_IDENTIFIER: i64 = -16;

/// Borrowed, bounded certificate discovery input, never a trust verdict.
pub struct CertificateHeaders<'a> {
    pub(super) certificates: [&'a [u8]; MAX_COSE_X5CHAIN_CERTIFICATES],
    pub(super) count: usize,
    pub(super) placement: Option<X5ChainHeaderPlacement>,
    pub(super) thumbprint: Option<&'a [u8; 32]>,
}

impl CertificateHeaders<'_> {
    /// End-entity-first exact DER byte slices as received.
    pub fn certificates(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.certificates[..self.count].iter().copied()
    }
    /// Header bucket containing x5chain.
    #[must_use]
    pub const fn placement(&self) -> Option<X5ChainHeaderPlacement> {
        self.placement
    }
    /// Protected SHA-256 thumbprint, if supplied.
    #[must_use]
    pub const fn sha256_thumbprint(&self) -> Option<&[u8; 32]> {
        self.thumbprint
    }
}

pub(super) struct Headers<'a> {
    pub algorithm: i64,
    pub certificates: CertificateHeaders<'a>,
}

pub(super) fn read_headers<'a>(
    protected: &'a [u8],
    unprotected: Item<'a>,
) -> Result<Headers<'a>, ContainerError> {
    super::validate_preferred_cbor(protected)?;
    let protected = Item::from_validated(protected)?;
    let mut labels: [Option<Item<'a>>; MAX_HEADERS * 2] = [None; MAX_HEADERS * 2];
    let mut used: usize = 0;
    let mut algorithm = None;
    let mut certificates = CertificateHeaders {
        certificates: [&[]; MAX_COSE_X5CHAIN_CERTIFICATES],
        count: 0,
        placement: None,
        thumbprint: None,
    };
    for (map, placement) in [
        (protected, X5ChainHeaderPlacement::Protected),
        (unprotected, X5ChainHeaderPlacement::Unprotected),
    ] {
        let count = map.count(5)?;
        if count > MAX_HEADERS {
            return Err(Reason::Limit.into());
        }
        let mut cursor = map.cursor();
        for _ in 0..count {
            let label = cursor.next()?;
            if !matches!(label.major, 0 | 1 | 3) {
                return Err(Reason::Malformed.into());
            }
            if labels[..used]
                .iter()
                .flatten()
                .any(|prior| prior.encoded == label.encoded)
            {
                return Err(Reason::Duplicate.into());
            }
            *labels.get_mut(used).ok_or(Reason::Limit)? = Some(label);
            used = used.checked_add(1).ok_or(Reason::Limit)?;
            let value = cursor.next()?;
            let numeric = if label.major == 3 {
                None
            } else {
                Some(label.integer()?)
            };
            match numeric {
                Some(1) => {
                    if placement != X5ChainHeaderPlacement::Protected {
                        return Err(Reason::Profile.into());
                    }
                    algorithm = Some(value.integer()?);
                }
                Some(2) => return Err(Reason::Critical.into()),
                Some(3) => {
                    if value.major != 3 && value.major != 0 {
                        return Err(Reason::Malformed.into());
                    }
                }
                Some(4) => {
                    value.bytes()?;
                }
                Some(5 | 6 | 7 | 9 | 11 | 12) => return Err(Reason::Profile.into()),
                Some(33) => {
                    read_chain(value, &mut certificates)?;
                    certificates.placement = Some(placement);
                }
                Some(34) => {
                    if placement != X5ChainHeaderPlacement::Protected {
                        return Err(Reason::Profile.into());
                    }
                    if value.count(4)? != 2 {
                        return Err(Reason::Malformed.into());
                    }
                    let mut pair = value.cursor();
                    if pair
                        .next()?
                        .integer()
                        .map_err(|_| Reason::ThumbprintAlgorithm)?
                        != X5T_SHA256_IDENTIFIER
                    {
                        return Err(Reason::ThumbprintAlgorithm.into());
                    }
                    let bytes = pair.next()?.bytes()?;
                    certificates.thumbprint =
                        Some(bytes.try_into().map_err(|_| Reason::ThumbprintLength)?);
                }
                _ => {} // Unknown noncritical values remain available in the exact header spans.
            }
        }
    }
    Ok(Headers {
        algorithm: algorithm.ok_or(Reason::Malformed)?,
        certificates,
    })
}

fn read_chain<'a>(
    value: Item<'a>,
    output: &mut CertificateHeaders<'a>,
) -> Result<(), ContainerError> {
    let mut total: usize = 0;
    if value.major == 2 {
        append_certificate(value.bytes()?, output, &mut total)?;
        return Ok(());
    }
    let count = value.count(4)?;
    if count < 2 {
        return Err(Reason::Malformed.into());
    }
    if count > MAX_COSE_X5CHAIN_CERTIFICATES {
        return Err(Reason::Limit.into());
    }
    let mut cursor = value.cursor();
    for _ in 0..count {
        append_certificate(cursor.next()?.bytes()?, output, &mut total)?;
    }
    Ok(())
}

fn append_certificate<'a>(
    certificate: &'a [u8],
    output: &mut CertificateHeaders<'a>,
    total: &mut usize,
) -> Result<(), ContainerError> {
    // Share the established certificate limits with the existing Sign1 path;
    // this borrowed path avoids allocating its ciborium certificate tree.
    crate::sign1::validate_certificate_size(certificate).map_err(|error| {
        if error == crate::CoseError::ResourceLimitExceeded {
            Reason::Limit
        } else {
            Reason::Malformed
        }
    })?;
    *total = total.checked_add(certificate.len()).ok_or(Reason::Limit)?;
    if *total > MAX_COSE_X5CHAIN_TOTAL_BYTES {
        return Err(Reason::Limit.into());
    }
    *output
        .certificates
        .get_mut(output.count)
        .ok_or(Reason::Limit)? = certificate;
    output.count = output.count.checked_add(1).ok_or(Reason::Limit)?;
    Ok(())
}
