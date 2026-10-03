// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wipe-owned ProtoJSON decoding for fields that carry secret bytes.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde::de::{Error, Visitor};
use serde::Deserializer;
use zeroize::Zeroizing;

const LENIENT_CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_allow_trailing_bits(true)
    .with_decode_padding_mode(DecodePaddingMode::Indifferent);
const STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, LENIENT_CONFIG);
const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT_CONFIG);

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct SecretBytesVisitor;

    impl Visitor<'_> for SecretBytesVisitor {
        type Value = Zeroizing<Vec<u8>>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("a base64 string or null")
        }

        fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
            Ok(Zeroizing::new(Vec::new()))
        }

        fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
            let engine = if value.bytes().any(|byte| byte == b'-' || byte == b'_') {
                &URL_SAFE
            } else {
                &STANDARD
            };
            let mut decoded = Zeroizing::new(Vec::new());
            engine
                .decode_vec(value, &mut decoded)
                .map_err(|_| E::custom("invalid base64 in sensitive field"))?;
            Ok(decoded)
        }
    }

    deserializer.deserialize_any(SecretBytesVisitor)
}
