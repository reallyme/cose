// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::cbor::general::{self, ErrorReason, Profile};

use super::{error, limits, preferred};
use crate::{containers::validate_preferred_cbor, CoseError};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn shared_codec_rejects_duplicate_compound_keys_and_float_zero_signs() {
    // Equal map keys with different received entry ordering; byte comparison
    // alone misses this duplicate. Both zero signs also denote the same key.
    for encoded in [
        b"\xa2\xa2\x00\x01\x02\x03\x00\xa2\x02\x03\x00\x01\x01".as_slice(),
        b"\xa2\xf9\x00\x00\x00\xf9\x80\x00\x01".as_slice(),
        b"\xa2\xf9\x7e\x00\x00\xf9\xfe\x00\x01".as_slice(),
    ] {
        assert_eq!(
            validate_preferred_cbor(encoded),
            Err(CoseError::DuplicateMapLabel)
        );
        let codec =
            general::validate_exact(encoded, Profile::preferred(), general::Limits::default());
        assert_eq!(codec.err().map(error), Some(CoseError::DuplicateMapLabel));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn shared_codec_accepts_distinct_nan_significands_and_preserves_unsorted_maps(
) -> Result<(), CoseError> {
    for encoded in [
        b"\xa2\x02\x00\x01\x01".as_slice(),
        b"\xa2\xf9\x7e\x00\x00\xf9\x7e\x01\x01".as_slice(),
    ] {
        validate_preferred_cbor(encoded)?;
        let receipt =
            general::validate_exact(encoded, preferred(false)?, limits()?).map_err(error)?;
        assert_eq!(receipt.frame().received_bytes(), encoded);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn item_depth_limit_preserves_the_empty_container_boundary() {
    for leaf in [0x00, 0x80, 0xa0] {
        let mut encoded = vec![0x81; 32];
        encoded.push(leaf);
        assert_eq!(validate_preferred_cbor(&encoded), Ok(()));
        encoded.insert(0, 0x81);
        assert_eq!(
            validate_preferred_cbor(&encoded),
            Err(CoseError::ResourceLimitExceeded)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn shared_codec_maps_fixed_errors_without_dependency_diagnostics() {
    for (reason, expected) in [
        (ErrorReason::InvalidUtf8, CoseError::Cbor),
        (ErrorReason::TrailingData, CoseError::Cbor),
        (ErrorReason::DuplicateMapKey, CoseError::DuplicateMapLabel),
        (
            ErrorReason::NonPreferredArgument,
            CoseError::NonCanonicalCbor,
        ),
        (ErrorReason::DepthLimit, CoseError::ResourceLimitExceeded),
        (ErrorReason::WorkLimit, CoseError::ResourceLimitExceeded),
        (
            ErrorReason::ArithmeticOverflow,
            CoseError::ResourceLimitExceeded,
        ),
    ] {
        assert_eq!(error(general::CborError::new(reason)), expected);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn truncated_string_extents_have_the_same_fixed_error_on_every_target() -> Result<(), CoseError> {
    const CBOR_64_BIT_LENGTH_HEADER_BYTES: u64 = 9;
    let lengths = [
        u64::from(u32::MAX)
            .checked_add(1)
            .ok_or(CoseError::ResourceLimitExceeded)?,
        u64::MAX
            .checked_sub(CBOR_64_BIT_LENGTH_HEADER_BYTES)
            .ok_or(CoseError::ResourceLimitExceeded)?,
        u64::MAX,
    ];
    // These headers claim a missing body. Codec checks that extent in the CBOR
    // integer domain before any address-width conversion or allocation budget.
    for major in [0x5b, 0x7b] {
        for length in lengths {
            let mut encoded = vec![major];
            encoded.extend_from_slice(&length.to_be_bytes());
            let failure =
                general::validate_exact(&encoded, Profile::preferred(), general::Limits::default())
                    .err();
            assert_eq!(
                failure.map(|error| error.reason()),
                Some(ErrorReason::Truncated)
            );
            assert_eq!(validate_preferred_cbor(&encoded), Err(CoseError::Cbor));
        }
    }
    Ok(())
}
