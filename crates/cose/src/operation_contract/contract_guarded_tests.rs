// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{
    __buffa::oneof::cose_operation_request::Operation, CoseByteLimits,
    CoseKeyFromPrivateBytesRequest, CoseMultikeyToCoseKeyRequest, CoseOperationRequest,
    CoseOperationRequestOwnedView, CoseOperationRequestView, CoseSign1CreateRequest,
    CoseSign1CreateRequestOwnedView, CoseSign1CreateRequestView,
};
use crate::CoseError;
use buffa::{bytes::Buf, DecodeOptions, Message, MessageView};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn native_cleanup_fields_decode_every_fragment_and_preserve_clone_clear() -> Result<(), CoseError> {
    let input = CoseSign1CreateRequest::default()
        .with_private_key(vec![0xa5; 128])
        .with_payload(vec![0x42; 257])
        .with_kid(vec![0xfb, 0xfc]);
    let encoded = zeroize::Zeroizing::new(input.encode_to_vec());
    for split in 0..=encoded.len() {
        let mut chunks = encoded[..split].chain(&encoded[split..]);
        let mut decoded: CoseSign1CreateRequest = DecodeOptions::new()
            .reject_unknown_fields()
            .decode(&mut chunks)
            .map_err(|_| CoseError::Cbor)?;
        assert_eq!(decoded, input);
        let cloned = decoded.clone();
        assert_ne!(decoded.private_key.as_ptr(), cloned.private_key.as_ptr());
        decoded.clear();
        assert!(decoded.private_key.is_empty());
        assert_eq!(cloned, input);
    }
    let text = CoseMultikeyToCoseKeyRequest::default().with_multikey("€".to_owned());
    let encoded = zeroize::Zeroizing::new(text.encode_to_vec());
    for split in 0..=encoded.len() {
        let mut chunks = encoded[..split].chain(&encoded[split..]);
        let decoded: CoseMultikeyToCoseKeyRequest = DecodeOptions::new()
            .reject_unknown_fields()
            .decode(&mut chunks)
            .map_err(|_| CoseError::Cbor)?;
        assert_eq!(decoded, text);
    }
    let mut invalid = (&[0x0a, 2, 0xc3][..]).chain(&[0x28][..]);
    assert_eq!(
        DecodeOptions::new()
            .reject_unknown_fields()
            .decode::<CoseMultikeyToCoseKeyRequest>(&mut invalid)
            .err(),
        Some(buffa::DecodeError::InvalidUtf8)
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn native_cleanup_replaces_fields_across_length_prefix_boundaries() -> Result<(), CoseError> {
    for length in [0, 1, 127, 128, 255, 256, 4096] {
        let first = CoseKeyFromPrivateBytesRequest::default().with_private_key(vec![0xa5; 8192]);
        let mut encoded = zeroize::Zeroizing::new(first.encode_to_vec());
        if length == 0 {
            encoded.extend_from_slice(&[0x12, 0]);
        } else {
            encoded.extend_from_slice(
                &CoseKeyFromPrivateBytesRequest::default()
                    .with_private_key(vec![0x24; length])
                    .encode_to_vec(),
            );
        }
        let decoded: CoseKeyFromPrivateBytesRequest = DecodeOptions::new()
            .reject_unknown_fields()
            .decode_from_slice(&encoded)
            .map_err(|_| CoseError::Cbor)?;
        assert_eq!(decoded.private_key, vec![0x24; length]);
    }
    let first =
        CoseMultikeyToCoseKeyRequest::default().with_multikey("previous identifier".to_owned());
    let mut encoded = zeroize::Zeroizing::new(first.encode_to_vec());
    encoded.extend_from_slice(&[0x0a, 1, b'z']);
    let decoded: CoseMultikeyToCoseKeyRequest = DecodeOptions::new()
        .reject_unknown_fields()
        .decode_from_slice(&encoded)
        .map_err(|_| CoseError::Cbor)?;
    assert_eq!(decoded.multikey, "z");
    encoded.extend_from_slice(&[0x0a, 1, 0xff]);
    assert_eq!(
        DecodeOptions::new()
            .reject_unknown_fields()
            .decode_from_slice::<CoseMultikeyToCoseKeyRequest>(&encoded)
            .err(),
        Some(buffa::DecodeError::InvalidUtf8)
    );
    let mut numbers = CoseByteLimits {
        encoded_bytes: 91,
        payload_bytes: 92,
        external_aad_bytes: 93,
    };
    let cloned = numbers.clone();
    numbers.clear();
    assert_eq!(numbers, CoseByteLimits::default());
    assert_eq!(cloned.encoded_bytes, 91);
    assert!(!format!("{cloned:?}").contains("91"));
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn native_cleanup_keeps_typed_malformed_length_errors() {
    for encoded in [&[][..], &[0x80][..], &[4, b'a'][..], &[0xff; 11][..]] {
        let mut reference = Vec::new();
        let mut remaining = encoded;
        let expected = buffa::types::merge_bytes(&mut reference, &mut remaining).err();
        assert!(expected.is_some());
        let mut field = vec![0x0a];
        field.extend_from_slice(encoded);
        let actual = DecodeOptions::new()
            .reject_unknown_fields()
            .decode_from_slice::<CoseMultikeyToCoseKeyRequest>(&field)
            .err();
        assert_eq!(actual, expected);
        let actual = DecodeOptions::new()
            .reject_unknown_fields()
            .decode_from_slice::<crate::api::contract::CoseOpaqueBytes>(&field)
            .err();
        assert_eq!(actual, expected);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn whole_view_json_is_denied_for_empty_secret_and_containing_views() -> Result<(), CoseError> {
    for input in [
        CoseSign1CreateRequest::default(),
        CoseSign1CreateRequest::default().with_private_key(vec![0xa5; 32]),
    ] {
        let encoded = zeroize::Zeroizing::new(input.encode_to_vec());
        let view = DecodeOptions::new()
            .reject_unknown_fields()
            .decode_view::<CoseSign1CreateRequestView>(&encoded)
            .map_err(|_| CoseError::Cbor)?;
        let owned =
            CoseSign1CreateRequestOwnedView::from_owned(&input).map_err(|_| CoseError::Cbor)?;
        assert!(serde_json::to_string(&view).is_err());
        assert!(serde_json::to_string(&owned).is_err());
        assert!(serde_json::to_string(&input).is_ok());
        assert_eq!(view.to_owned_message().map_err(|_| CoseError::Cbor)?, input);
    }
    let containing = CoseOperationRequest::default();
    let owned =
        CoseOperationRequestOwnedView::from_owned(&containing).map_err(|_| CoseError::Cbor)?;
    let encoded = zeroize::Zeroizing::new(containing.encode_to_vec());
    let eager = DecodeOptions::new()
        .reject_unknown_fields()
        .decode_view::<CoseOperationRequestView>(&encoded)
        .map_err(|_| CoseError::Cbor)?;
    assert!(serde_json::to_string(&owned).is_err());
    assert!(serde_json::to_string(&eager).is_err());

    let containing = CoseOperationRequest {
        operation: Some(Operation::Sign1Create(Box::new(
            CoseSign1CreateRequest::default().with_private_key(vec![0xa5; 32]),
        ))),
    };
    let encoded = zeroize::Zeroizing::new(containing.encode_to_vec());
    let decode = DecodeOptions::new().reject_unknown_fields();
    let eager = decode
        .decode_view::<CoseOperationRequestView>(&encoded)
        .map_err(|_| CoseError::Cbor)?;
    let owned =
        CoseOperationRequestOwnedView::from_owned(&containing).map_err(|_| CoseError::Cbor)?;
    let eager_operation = eager.operation.as_ref().ok_or(CoseError::InvalidFormat)?;
    let owned_operation = owned.operation().ok_or(CoseError::InvalidFormat)?;
    for debug in [
        format!("{eager:?}"),
        format!("{owned:?}"),
        format!("{eager_operation:?}"),
        format!("{owned_operation:?}"),
    ] {
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("165"));
        assert!(!debug.contains("Sign1Create"));
    }
    assert!(serde_json::to_string(&eager).is_err());
    assert!(serde_json::to_string(&owned).is_err());
    Ok(())
}
