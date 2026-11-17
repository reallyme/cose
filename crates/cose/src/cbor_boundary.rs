// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One shared codec boundary for COSE's distinct, explicitly selected profiles.

use reallyme_codec::cbor::general::{
    CborError, ErrorReason, Limits, MajorType, NanPolicy, Profile,
};

use crate::CoseError;

#[path = "decode_cbor_value.rs"]
mod decode_value;
pub(crate) use decode_value::decode;

#[cfg(test)]
#[cfg(feature = "cose-crypto")]
#[path = "cbor_boundary_tests.rs"]
mod tests;

pub(crate) const MAX_ITEM_DEPTH: usize = 32;
// Codec counts open containers, whereas COSE's established ceiling admits an
// empty container at item depth 32. Admission walks retain that exact boundary.
const MAX_OPEN_CONTAINERS: usize = 33;
pub(crate) const MAX_COLLECTION_ENTRIES: usize = 1_024;

pub(crate) fn limits() -> Result<Limits, CoseError> {
    Limits::default()
        .with_depth(MAX_OPEN_CONTAINERS)
        .and_then(|limits| limits.with_entries(MAX_COLLECTION_ENTRIES))
        .map_err(error)
}

pub(crate) fn preferred(legacy_widths: bool) -> Result<Profile, CoseError> {
    if legacy_widths {
        // ISO 2021 retains received tag/float widths. Minimum arguments for
        // types 0..5 are checked separately through codec's header receipt.
        return Profile::new(
            reallyme_codec::cbor::general::Serialization::Received,
            reallyme_codec::cbor::general::LengthPolicy::DefiniteOnly,
            reallyme_codec::cbor::general::FloatPolicy::All,
            reallyme_codec::cbor::general::MapOrdering::Received,
        )
        .map_err(error);
    }
    Profile::preferred()
        .with_nan_policy(NanPolicy::Binary16Only)
        .map_err(error)
}

pub(crate) fn error(failure: CborError) -> CoseError {
    match failure.reason() {
        ErrorReason::IndefiniteNotAllowed
        | ErrorReason::NonPreferredArgument
        | ErrorReason::NonPreferredFloat
        | ErrorReason::FloatNotAllowed
        | ErrorReason::MapKeyOrder => CoseError::NonCanonicalCbor,
        ErrorReason::DuplicateMapKey => CoseError::DuplicateMapLabel,
        ErrorReason::InvalidLimit
        | ErrorReason::InputLimit
        | ErrorReason::OutputLimit
        | ErrorReason::DepthLimit
        | ErrorReason::NodeLimit
        | ErrorReason::EntryLimit
        | ErrorReason::ByteStringLimit
        | ErrorReason::TextLimit
        | ErrorReason::WorkLimit
        | ErrorReason::ArithmeticOverflow
        | ErrorReason::AllocationFailure => CoseError::ResourceLimitExceeded,
        _ => CoseError::Cbor,
    }
}

pub(crate) fn primitive_error(failure: CborError, input: &[u8]) -> CoseError {
    // Preserve the primitive API's historical distinction for an overlong
    // root simple value; the shared codec still owns header decoding.
    if failure.reason() == ErrorReason::InvalidSimpleValue
        && matches!(input, [0xf8, value, ..] if *value < 24)
    {
        return CoseError::NonCanonicalCbor;
    }
    error(failure)
}

pub(crate) fn major_code(major: MajorType) -> Result<u8, CoseError> {
    match major {
        MajorType::Unsigned => Ok(0),
        MajorType::Negative => Ok(1),
        MajorType::Bytes => Ok(2),
        MajorType::Text => Ok(3),
        MajorType::Array => Ok(4),
        MajorType::Map => Ok(5),
        MajorType::Tag => Ok(6),
        MajorType::Simple => Ok(7),
        _ => Err(CoseError::Cbor),
    }
}
