// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::SecretString;
use serde::de::{Error, Visitor};
use zeroize::Zeroizing;

pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretString, D::Error> {
    struct Text;
    impl Visitor<'_> for Text {
        type Value = SecretString;
        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("a UTF-8 string")
        }
        fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
            let bytes = crate::guarded_decode::copy_with_limit(
                value.as_bytes(),
                crate::secret_json_bytes::MAX_JSON_FIELD_BYTES,
            )
            .map_err(|_| E::custom(crate::secret_json_bytes::JsonErrorReason::Limit))?;
            crate::guarded_decode::text(bytes)
                .map(Into::into)
                .map_err(|_| E::custom(crate::secret_json_bytes::JsonErrorReason::Encoding))
        }
        fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
            let mut owner = Zeroizing::new(value);
            if owner.len() > crate::secret_json_bytes::MAX_JSON_FIELD_BYTES {
                return Err(E::custom(crate::secret_json_bytes::JsonErrorReason::Limit));
            }
            Ok(core::mem::take(&mut *owner).into())
        }
    }
    deserializer.deserialize_any(Text)
}
