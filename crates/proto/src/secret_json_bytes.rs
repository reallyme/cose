// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native ProtoJSON policy: reserve wipe-owned scratch before handling secrets.

use crate::SecretBytes;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde::de::{Error, Visitor};
use zeroize::Zeroizing;

const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_allow_trailing_bits(true)
    .with_decode_padding_mode(DecodePaddingMode::Indifferent);
const STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, CONFIG);
const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, CONFIG);
// Match the executable JSON envelope ceiling. A decoded field may make the
// protobuf envelope too large; the shared typed admission check then reports
// its existing resource-limit reason, rather than misclassifying valid JSON.
pub(crate) const MAX_JSON_FIELD_BYTES: usize = 3 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum JsonErrorReason {
    #[error("invalid encoding in sensitive field")]
    Encoding,
    #[error("sensitive field resource limit")]
    Limit,
}

pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretBytes, D::Error> {
    struct Bytes;
    impl Visitor<'_> for Bytes {
        type Value = SecretBytes;
        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("a base64 string")
        }
        fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.len() > MAX_JSON_FIELD_BYTES {
                return Err(E::custom(JsonErrorReason::Limit));
            }
            let engine = if value.bytes().any(|byte| byte == b'-' || byte == b'_') {
                &URL_SAFE
            } else {
                &STANDARD
            };
            // Output cannot exceed the encoded length. A single reservation
            // prevents partially decoded data from outgrowing its wipe owner.
            let mut decoded = Zeroizing::new(Vec::new());
            decoded
                .try_reserve_exact(value.len())
                .map_err(|_| E::custom(JsonErrorReason::Limit))?;
            decoded.resize(value.len(), 0);
            let length = engine
                .decode_slice(value, &mut decoded)
                .map_err(|_| E::custom(JsonErrorReason::Encoding))?;
            // Keep the allocation, including its zeroed tail, under its owner.
            decoded.truncate(length);
            Ok(core::mem::take(&mut *decoded).into())
        }
        fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
            let encoded = Zeroizing::new(value);
            self.visit_str(&encoded)
        }
    }
    deserializer.deserialize_any(Bytes)
}

pub(crate) fn serialize<S: serde::Serializer>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;
    let length = base64::encoded_len(bytes.len(), true)
        .ok_or_else(|| S::Error::custom(JsonErrorReason::Limit))?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(length)
        .map_err(|_| S::Error::custom(JsonErrorReason::Limit))?;
    encoded.resize(length, 0);
    let count = STANDARD
        .encode_slice(bytes, &mut encoded)
        .map_err(|_| S::Error::custom(JsonErrorReason::Encoding))?;
    let output = encoded
        .get(..count)
        .ok_or_else(|| S::Error::custom(JsonErrorReason::Encoding))?;
    let output =
        core::str::from_utf8(output).map_err(|_| S::Error::custom(JsonErrorReason::Encoding))?;
    serializer.serialize_str(output)
}
