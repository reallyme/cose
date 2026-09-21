// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9596 COSE `typ` protected-header values.

use ciborium::value::Value;
use coset::{Header, Label};

use crate::CoseError;

/// RFC 9596 COSE header label for `typ` (type).
pub(crate) const COSE_TYPE_HEADER_LABEL: i64 =
    coset::iana::HeaderParameter::ObjectContentType as i64;

/// Maximum UTF-8 bytes accepted in a textual COSE `typ` value.
///
/// This implementation limit bounds attacker-controlled metadata retained
/// after verification while comfortably covering registered media types and
/// their parameters. Numeric CoAP Content-Format identifiers are unaffected.
pub const MAX_COSE_TYPE_TEXT_BYTES: usize = 256;

/// Authenticated RFC 9596 type of a complete COSE object.
///
/// Text values carry a media type. Registered values carry an unsigned ID from
/// the IANA CoAP Content-Formats registry.
#[must_use]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoseType {
    /// IANA media type, optionally including media type parameters.
    Text(String),

    /// IANA CoAP Content-Format identifier.
    Registered(u64),
}

impl CoseType {
    pub(super) fn validate(&self) -> Result<(), CoseError> {
        match self {
            Self::Text(text) if text.is_empty() => Err(CoseError::InvalidFormat),
            Self::Text(text) if text.len() > MAX_COSE_TYPE_TEXT_BYTES => {
                Err(CoseError::ResourceLimitExceeded)
            }
            Self::Text(_) | Self::Registered(_) => Ok(()),
        }
    }

    pub(super) fn from_cbor_value(value: &Value) -> Result<Self, CoseError> {
        let cose_type = match value {
            Value::Text(text) => Self::Text(text.clone()),
            Value::Integer(integer) => {
                Self::Registered(u64::try_from(*integer).map_err(|_| CoseError::InvalidFormat)?)
            }
            _ => return Err(CoseError::InvalidFormat),
        };
        cose_type.validate()?;
        Ok(cose_type)
    }

    pub(super) fn to_cbor_value(&self) -> Value {
        match self {
            Self::Text(text) => Value::Text(text.clone()),
            Self::Registered(identifier) => Value::Integer((*identifier).into()),
        }
    }

    pub(super) fn from_protected_header(header: &Header) -> Result<Option<Self>, CoseError> {
        let mut found = None;
        for (label, value) in &header.rest {
            if *label != Label::Int(COSE_TYPE_HEADER_LABEL) {
                continue;
            }
            if found.is_some() {
                return Err(CoseError::DuplicateMapLabel);
            }
            found = Some(Self::from_cbor_value(value)?);
        }
        Ok(found)
    }
}
