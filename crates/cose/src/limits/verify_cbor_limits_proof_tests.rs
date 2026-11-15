// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;

use super::{
    next_depth, validate_cbor_bytes, validate_collection_length, validate_item_depth, CborItemRole,
};
use crate::CoseError;

#[kani::proof]
fn cbor_limits_depth_checks_every_machine_sized_level() {
    let depth: usize = kani::any();
    let expected = if depth <= 32 {
        Ok(())
    } else {
        Err(CoseError::ResourceLimitExceeded)
    };
    assert!(validate_item_depth(depth) == expected);
    let child = next_depth(depth).and_then(validate_item_depth);
    assert!(child.is_ok() == (depth < 32));
    assert!(matches!(child, Err(CoseError::ResourceLimitExceeded)) == (depth >= 32));
    kani::cover!(
        depth == 31 && child.is_ok(),
        "the maximum permitted child depth is admitted"
    );
    kani::cover!(
        depth == 32 && child.is_err(),
        "the next nested item exceeds the depth ceiling"
    );
    kani::cover!(
        depth == usize::MAX && child.is_err(),
        "the depth counter cannot wrap"
    );
}

#[kani::proof]
fn cbor_limits_apply_exact_collection_bounds_to_each_role() {
    use CborItemRole::{
        CoseEncryptBody, CoseEncryptTop, CoseIsoKeyTop, CoseMac0Body, CoseMac0Top, CoseRecipient,
        CoseRecipientList, CoseSign1Body, CoseSign1Top, HeaderMap, ProtectedHeaderMap,
    };
    let role: CborItemRole = kani::any();
    let major: u8 = kani::any();
    let count: usize = kani::any();

    // RFC 9052 uses arrays (major type 4) for the envelopes. The repository
    // profile further bounds a generic collection and each header map,
    // and admits one recipient of exactly three fields for COSE_Encrypt.
    let expected = match role {
        _ if count > 1024 => Err(CoseError::ResourceLimitExceeded),
        HeaderMap | ProtectedHeaderMap | CoseIsoKeyTop if major == 5 && count > 32 => {
            Err(CoseError::ResourceLimitExceeded)
        }
        CoseMac0Top | CoseMac0Body | CoseSign1Top | CoseSign1Body | CoseEncryptTop
        | CoseEncryptBody
            if (major, count) != (4, 4) =>
        {
            Err(CoseError::InvalidFormat)
        }
        CoseRecipientList if (major, count) != (4, 1) => Err(CoseError::InvalidRecipient),
        CoseRecipient if (major, count) != (4, 3) => Err(CoseError::InvalidRecipient),
        _ => Ok(()),
    };
    assert!(validate_collection_length(role, major, count) == expected);
    kani::cover!(
        role == HeaderMap && major == 5 && count == 33,
        "a header map exceeds its work limit"
    );
    kani::cover!(
        major == 4 && count == 1025,
        "an array exceeds the generic collection ceiling"
    );
    kani::cover!(
        role == CoseRecipientList && major == 4 && count == 2,
        "a multi-recipient list is rejected"
    );
    kani::cover!(
        role == CoseSign1Top && major == 4 && count == 4,
        "a Sign1 envelope has four fields"
    );
}

std::thread_local! {
    static PARSED_LENGTH: Cell<Option<usize>> = const { Cell::new(None) };
    static PARSER_CALLED: Cell<bool> = const { Cell::new(false) };
}

#[kani::proof]
#[kani::stub(super::parse_cbor_item, model_item_parser)]
fn cbor_limits_validate_outer_length_before_parsing_and_require_full_consumption() {
    let length = usize::from(kani::any::<u8>());
    let bytes = [0x41; 8];
    kani::assume(length <= bytes.len());
    let ceiling: usize = kani::any();
    let consumed: usize = kani::any();
    PARSED_LENGTH.set(Some(consumed));
    PARSER_CALLED.set(false);

    let result = validate_cbor_bytes(&bytes[..length], ceiling, CborItemRole::Normal);
    assert!(PARSER_CALLED.get() == (length > 0 && length <= ceiling));
    let expected = if length == 0 {
        Err(CoseError::Cbor)
    } else if length > ceiling {
        Err(CoseError::ResourceLimitExceeded)
    } else if consumed == length {
        Ok(())
    } else {
        Err(CoseError::Cbor)
    };
    assert!(result == expected);
    kani::cover!(
        length > ceiling && length > 0,
        "oversized input stops before parsing"
    );
    kani::cover!(
        length > 1 && length <= ceiling && consumed < length,
        "trailing bytes are rejected"
    );
    kani::cover!(result.is_ok(), "an item consumes all permitted input");
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn model_item_parser(
    bytes: &[u8],
    offset: usize,
    depth: usize,
    role: CborItemRole,
) -> Result<usize, CoseError> {
    assert!(offset == 0 && depth == 0 && !bytes.is_empty() && role == CborItemRole::Normal);
    assert!(!PARSER_CALLED.replace(true));
    PARSED_LENGTH.get().ok_or(CoseError::Cbor)
}
