// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native Buffa byte representation with explicit ownership transfer.

use buffa::{bytes::Buf, DecodeError, FieldPayload, ProtoBytes, WirePayload};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Wipe-owned protobuf bytes. Clones own independent, equally protected copies.
///
/// Construction retains spare capacity; no mutable Vec interface can release
/// an outgrown secret allocation. Equality compares message data and is not a
/// cryptographic authentication primitive.
pub struct SecretBytes(SecretBox<Vec<u8>>);

impl SecretBytes {
    /// Borrow the encoded field without allocating another owner.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Transfer the complete allocation and spare capacity to a wipe owner.
    #[must_use]
    pub fn into_zeroizing(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(self.0.expose_secret_mut()))
    }
}
impl Default for SecretBytes {
    fn default() -> Self {
        Vec::new().into()
    }
}
impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }
}
impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        self.as_slice().to_vec().into()
    }
}
impl core::ops::Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl core::ops::DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.expose_secret_mut().as_mut_slice()
    }
}
impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl<T: AsRef<[u8]> + ?Sized> PartialEq<T> for SecretBytes {
    fn eq(&self, other: &T) -> bool {
        self.as_slice() == other.as_ref()
    }
}
impl Eq for SecretBytes {}
impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}
impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for SecretBytes {}
impl ProtoBytes for SecretBytes {
    fn from_wire(payload: WirePayload<'_>) -> Result<Self, DecodeError> {
        let mut owner = crate::guarded_decode::copy(payload.as_slice())?;
        Ok(core::mem::take(&mut *owner).into())
    }
    fn decode_length_delimited(payload: &mut FieldPayload<impl Buf>) -> Result<Self, DecodeError> {
        let mut owner = crate::guarded_decode::read(payload)?;
        Ok(core::mem::take(&mut *owner).into())
    }
}
impl buffa::json_helpers::ProtoBytesJson for SecretBytes {
    fn serialize_json<S: serde::Serializer>(
        bytes: &[u8],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        crate::secret_json_bytes::serialize(bytes, serializer)
    }
    fn deserialize_json<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        crate::secret_json_bytes::deserialize(deserializer)
    }
}
