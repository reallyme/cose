// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{bytes::Buf, DecodeError, FieldPayload, ProtoString, WirePayload};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Wipe-owned protobuf text; retains and wipes its complete allocation.
pub struct SecretString(SecretBox<String>);
impl SecretString {
    /// Borrow the UTF-8 field without a serialized copy.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.expose_secret()
    }
    /// Transfer the allocation, including spare capacity, to a wipe owner.
    #[must_use]
    pub fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(core::mem::take(self.0.expose_secret_mut()))
    }
}
impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }
}
impl Default for SecretString {
    fn default() -> Self {
        String::new().into()
    }
}
impl Clone for SecretString {
    fn clone(&self) -> Self {
        self.as_str().to_owned().into()
    }
}
impl core::ops::Deref for SecretString {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self
    }
}
impl<T: AsRef<str> + ?Sized> PartialEq<T> for SecretString {
    fn eq(&self, other: &T) -> bool {
        self.as_str() == other.as_ref()
    }
}
impl Eq for SecretString {}
impl core::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretString(<redacted>)")
    }
}
impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for SecretString {}
impl ProtoString for SecretString {
    fn from_wire(payload: WirePayload<'_>) -> Result<Self, DecodeError> {
        crate::guarded_decode::text(crate::guarded_decode::copy(payload.as_slice())?)
            .map(Into::into)
    }
    fn decode_length_delimited(payload: &mut FieldPayload<impl Buf>) -> Result<Self, DecodeError> {
        crate::guarded_decode::text(crate::guarded_decode::read(payload)?).map(Into::into)
    }
}
impl buffa::json_helpers::ProtoStringJson for SecretString {
    fn serialize_json<S: serde::Serializer>(text: &str, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(text)
    }
    fn deserialize_json<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        crate::secret_json_string::deserialize(deserializer)
    }
}
