// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9596 COSE `typ` protected-header values.

#[cfg(feature = "cose-crypto")]
use ciborium::value::Value;
#[cfg(feature = "cose-crypto")]
use coset::{Header, Label};

use crate::CoseError;

/// RFC 9596 COSE header label for `typ` (type).
#[cfg(feature = "cose-crypto")]
pub(crate) const COSE_TYPE_HEADER_LABEL: i64 =
    coset::iana::HeaderParameter::ObjectContentType as i64;

/// Maximum UTF-8 bytes accepted in a textual COSE `typ` value.
///
/// This implementation limit bounds attacker-controlled metadata retained
/// after verification while comfortably covering registered media types and
/// their parameters. Numeric CoAP Content-Format identifiers are unaffected.
pub use crate::generated_contract::values::MAX_COSE_TYPE_TEXT_BYTES;
const MAX_COAP_CONTENT_FORMAT_IDENTIFIER: u64 = 65_535;

/// Compatibility view of the generated RFC 9596 typ oneof.
pub use reallyme_cose_proto::generated::proto::reallyme::cose::v1::cose_type::Value as CoseType;

pub(crate) trait CoseTypeExt: Sized {
    fn validate(&self) -> Result<(), CoseError>;
    #[cfg(feature = "cose-crypto")]
    fn from_cbor_value(value: &Value) -> Result<Self, CoseError>;
    #[cfg(feature = "cose-crypto")]
    fn to_cbor_value(&self) -> Value;
    #[cfg(feature = "cose-crypto")]
    fn from_protected_header(header: &Header) -> Result<Option<Self>, CoseError>;
}

impl CoseTypeExt for CoseType {
    fn validate(&self) -> Result<(), CoseError> {
        match self {
            Self::MediaType(text) if text.is_empty() => Err(CoseError::InvalidFormat),
            Self::MediaType(text) if text.len() > MAX_COSE_TYPE_TEXT_BYTES => {
                Err(CoseError::ResourceLimitExceeded)
            }
            Self::MediaType(text) if text.chars().any(char::is_control) => {
                Err(CoseError::InvalidFormat)
            }
            Self::ContentFormat(identifier) if *identifier > MAX_COAP_CONTENT_FORMAT_IDENTIFIER => {
                Err(CoseError::InvalidFormat)
            }
            Self::MediaType(_) | Self::ContentFormat(_) => Ok(()),
        }
    }

    #[cfg(feature = "cose-crypto")]
    fn from_cbor_value(value: &Value) -> Result<Self, CoseError> {
        let cose_type = match value {
            Value::Text(text) => Self::MediaType(text.clone().into()),
            Value::Integer(integer) => {
                Self::ContentFormat(u64::try_from(*integer).map_err(|_| CoseError::InvalidFormat)?)
            }
            _ => return Err(CoseError::InvalidFormat),
        };
        cose_type.validate()?;
        Ok(cose_type)
    }

    #[cfg(feature = "cose-crypto")]
    fn to_cbor_value(&self) -> Value {
        match self {
            Self::MediaType(text) => Value::Text(text.as_str().to_owned()),
            Self::ContentFormat(identifier) => Value::Integer((*identifier).into()),
        }
    }

    #[cfg(feature = "cose-crypto")]
    fn from_protected_header(header: &Header) -> Result<Option<Self>, CoseError> {
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
