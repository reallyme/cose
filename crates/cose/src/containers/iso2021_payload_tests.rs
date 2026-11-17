// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{validate_issuer_mso_payload, validate_preferred_cbor};
use crate::containers::{ContainerError, ContainerErrorReason as Reason, ContainerProfile};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn issuer_extension_maps_reject_equal_compound_keys_in_both_iso_profiles() {
    for profile in [ContainerProfile::Iso2021, ContainerProfile::IsoEdition2Dis] {
        // {100: {{0: 1, 2: 3}: null, {2: 3, 0: 1}: false}}
        let duplicate = b"\xa1\x18\x64\xa2\xa2\x00\x01\x02\x03\xf6\xa2\x02\x03\x00\x01\xf4";
        assert_eq!(
            validate_issuer_mso_payload(duplicate, profile),
            Err(Reason::Duplicate.into())
        );
        // The same two-entry shape is permitted when one map value differs.
        let unique = b"\xa1\x18\x64\xa2\xa2\x00\x01\x02\x03\xf6\xa2\x02\x04\x00\x01\xf4";
        assert_eq!(validate_issuer_mso_payload(unique, profile), Ok(()));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_2021_tag_and_float_widths_do_not_relax_draft_or_preferred_input() {
    for bytes in [
        b"\xd9\x00\x18\x41\x00".as_slice(),
        b"\xda\x00\x00\x00\x18\x41\x00".as_slice(),
        b"\xdb\x00\x00\x00\x00\x00\x00\x00\x18\x41\x00".as_slice(),
        b"\xfa\x3f\x80\x00\x00".as_slice(),
        b"\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00".as_slice(),
        // A tagged map key also takes the profile into structural comparison.
        b"\xa1\xd9\x00\x18\x41\x00\x01".as_slice(),
    ] {
        assert_eq!(
            validate_issuer_mso_payload(bytes, ContainerProfile::Iso2021),
            Ok(())
        );
        assert!(validate_issuer_mso_payload(bytes, ContainerProfile::IsoEdition2Dis).is_err());
        assert!(validate_issuer_mso_payload(bytes, ContainerProfile::Rfc9360).is_err());
        assert!(validate_preferred_cbor(bytes).is_err());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn minimum_widths_malformed_data_and_semantic_duplicates_still_reject() {
    for bytes in [
        b"\x18\x01".as_slice(),
        b"\x38\x01".as_slice(),
        b"\x58\x01\x00".as_slice(),
        b"\x78\x01a".as_slice(),
        b"\x98\x01\x00".as_slice(),
        b"\xb8\x01\x00\x01".as_slice(),
        b"\xd9\x00\x18\x58\x01\x00".as_slice(),
        b"\xd9\x00\x18".as_slice(),
        b"\xd9\x00\x18\x41".as_slice(),
        b"\xd9\x00\x18\x41\x00\x00".as_slice(),
        b"\x9f\x00\xff".as_slice(),
        b"\x61\xff".as_slice(),
    ] {
        assert!(validate_issuer_mso_payload(bytes, ContainerProfile::Iso2021).is_err());
    }
    for duplicate in [
        b"\xa2\xf9\x3c\x00\x01\xfa\x3f\x80\x00\x00\x02".as_slice(),
        b"\xa2\xf9\x00\x00\x01\xfb\x80\x00\x00\x00\x00\x00\x00\x00\x02".as_slice(),
    ] {
        assert_eq!(
            validate_issuer_mso_payload(duplicate, ContainerProfile::Iso2021),
            Err(Reason::Duplicate.into())
        );
    }
    let duplicate = b"\xa2\xd8\x18\x41\x00\x01\xd9\x00\x18\x41\x00\x02";
    assert_eq!(
        validate_issuer_mso_payload(duplicate, ContainerProfile::Iso2021),
        Err(Reason::Duplicate.into())
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn received_payload_limits_stay_checked_in_each_profile() -> Result<(), ContainerError> {
    let mut deep = vec![0x81; 40];
    deep.push(0);
    for profile in [ContainerProfile::Iso2021, ContainerProfile::IsoEdition2Dis] {
        assert_eq!(
            validate_issuer_mso_payload(&deep, profile),
            Err(Reason::Limit.into())
        );
        let oversized_size = crate::limits::MAX_DETACHED_PAYLOAD_BYTES
            .checked_add(1)
            .ok_or(Reason::Limit)?;
        let oversized = vec![0; oversized_size];
        assert_eq!(
            validate_issuer_mso_payload(&oversized, profile),
            Err(Reason::Limit.into())
        );
    }
    Ok(())
}
