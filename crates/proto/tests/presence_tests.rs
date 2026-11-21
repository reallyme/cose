// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit presence survives default values, wire transport and ProtoJSON.

#![cfg(feature = "generated")]
#![allow(clippy::panic)]

use buffa::{sensitive::GuardedOwnedView, DecodeOptions, Message};
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::{
    CoseContainerVerifyResult, CoseIsoSign1VerifyResult, CoseKeyFromPrivateBytesRequest,
    CoseMac0VerifyResult, CoseMlKemDecryptRequest, CoseMlKemEncryptRequest,
    CoseSign1CreateDetachedRequest, CoseSign1CreateRequest, CoseSign1CreateRequestView,
};
use serde::{de::DeserializeOwned, Serialize};

fn byte_presence<M: Message + Serialize + DeserializeOwned>(
    construct: impl Fn(Option<Vec<u8>>) -> M,
    read: impl Fn(&M) -> Option<&[u8]>,
    field_name: &str,
    wire_tag: u8,
) -> Result<(), buffa::DecodeError> {
    for expected in [None, Some(Vec::new()), Some(vec![0xfb, 0xfc])] {
        let value = construct(expected.clone());
        let mut encoded = Vec::new();
        if let Some(bytes) = expected.as_ref() {
            encoded.push(wire_tag);
            encoded.push(u8::try_from(bytes.len()).unwrap_or_else(|_| panic!("fixture length")));
            encoded.extend_from_slice(bytes);
        }
        assert_eq!(value.encode_to_vec(), encoded);
        let decoded = M::decode_from_slice(&encoded)?;
        assert_eq!(read(&decoded), expected.as_deref());
        let json = serde_json::to_value(&value).unwrap_or_else(|_| panic!("fixture JSON"));
        match expected.as_ref() {
            None => assert!(json.get(field_name).is_none()),
            Some(bytes) if bytes.is_empty() => assert_eq!(json[field_name], ""),
            Some(_) => assert_eq!(json[field_name], "+/w="),
        }
        let decoded: M = serde_json::from_value(json).unwrap_or_else(|_| panic!("JSON roundtrip"));
        assert_eq!(read(&decoded), expected.as_deref());
        let mut cleared = value;
        cleared.clear();
        assert_eq!(read(&cleared), None);
    }
    let mut null = serde_json::Map::new();
    null.insert(field_name.to_owned(), serde_json::Value::Null);
    let decoded: M = serde_json::from_value(serde_json::Value::Object(null))
        .unwrap_or_else(|_| panic!("null means absent"));
    assert_eq!(read(&decoded), None);
    Ok(())
}

#[test]
fn every_optional_byte_field_keeps_absent_empty_and_nonempty_distinct(
) -> Result<(), buffa::DecodeError> {
    macro_rules! check {
        ($message:ident, $field:ident, $json:literal, $tag:literal) => {
            byte_presence(
                |value| {
                    let mut result = $message::default();
                    result.$field = value.map(Into::into);
                    result
                },
                |value: &$message| value.$field.as_deref(),
                $json,
                $tag,
            )?;
        };
    }
    check!(CoseSign1CreateRequest, kid, "kid", 0x22);
    check!(CoseSign1CreateDetachedRequest, kid, "kid", 0x22);
    check!(
        CoseKeyFromPrivateBytesRequest,
        public_key,
        "publicKey",
        0x1a
    );
    check!(
        CoseMlKemEncryptRequest,
        supp_priv_info,
        "suppPrivInfo",
        0x3a
    );
    check!(
        CoseMlKemDecryptRequest,
        supp_priv_info,
        "suppPrivInfo",
        0x2a
    );
    check!(CoseMac0VerifyResult, protected_kid, "protectedKid", 0x1a);
    check!(
        CoseIsoSign1VerifyResult,
        protected_kid,
        "protectedKid",
        0x1a
    );
    check!(
        CoseIsoSign1VerifyResult,
        attached_payload,
        "attachedPayload",
        0x2a
    );
    check!(
        CoseContainerVerifyResult,
        certificate_sha256,
        "certificateSha256",
        0x52
    );
    Ok(())
}

#[test]
fn generated_optional_view_builder_and_merge_preserve_presence(
) -> Result<(), buffa::sensitive::GuardedViewError> {
    let absent = CoseSign1CreateRequest::default();
    let present = absent.with_kid(Vec::new());
    let view = GuardedOwnedView::<CoseSign1CreateRequestView<'static>>::from_owned(
        &present,
        &DecodeOptions::new().reject_unknown_fields(),
    )?;
    assert_eq!(view.view().kid, Some(&[][..]));
    let replaced = present.with_kid(vec![0xfb, 0xfc]);
    assert_eq!(replaced.kid.as_deref(), Some(&[0xfb, 0xfc][..]));
    // The last singular occurrence can intentionally replace data with empty.
    let mut encoded = replaced.encode_to_vec();
    encoded.extend_from_slice(&[0x22, 0x00]);
    let decoded = CoseSign1CreateRequest::decode_from_slice(&encoded)?;
    assert_eq!(decoded.kid.as_deref(), Some(&[][..]));
    encoded.extend_from_slice(&[0x22, 0x02, 0xfb]);
    assert!(CoseSign1CreateRequest::decode_from_slice(&encoded).is_err());
    Ok(())
}

#[test]
fn optional_bytes_reject_retired_json_flags_and_late_decode_failures() {
    for json in [
        r#"{"kid":"+/w=","hasKid":true}"#,
        r#"{"kid":"+/w=","has_kid":false}"#,
        r#"{"kid":"+/w=","privateKey":"%%%"}"#,
        r#"{"kid":"+/w=","algorithm":{}}"#,
        r#"{"kid":"+/w=","kid":"AA=="}"#,
        r#"{"kid":null,"kid":"+/w="}"#,
        r#"{"kid":"+/w=","kid":null}"#,
        r#"{"kid":false}"#,
        r#"{"kid":[]}"#,
    ] {
        assert!(serde_json::from_str::<CoseSign1CreateRequest>(json).is_err());
    }
    for json in [
        r#"{"publicKey":null,"public_key":"+/w="}"#,
        r#"{"public_key":"+/w=","publicKey":null}"#,
    ] {
        assert!(serde_json::from_str::<CoseKeyFromPrivateBytesRequest>(json).is_err());
    }
    assert!(serde_json::from_str::<CoseMlKemEncryptRequest>(
        r#"{"suppPrivInfo":null,"supp_priv_info":""}"#,
    )
    .is_err());
    let nonempty = CoseSign1CreateRequest::default().with_kid(vec![0xfb, 0xfc]);
    let debug = format!("{nonempty:?}");
    assert!(!debug.contains("251"));
    assert!(!debug.contains("252"));
}
