// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{Label, RegisteredLabel, RegisteredLabelWithPrivate};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::zeroize_coset::zeroize_value;

/// Owned COSE key whose byte-valued fields are wiped on drop.
///
/// `coset::CoseKey` intentionally models the wire format and stores parameters
/// in ordinary vectors. This wrapper supplies the ownership boundary required
/// by the SDK: private parameters, identifiers, and base-IV material do not
/// remain in allocator-owned buffers after the key is dropped.
///
/// The type deliberately does not implement `Clone`, `Debug`, serialization,
/// or expose the underlying mutable key. Those capabilities could duplicate or
/// disclose private parameters without an auditable lifetime.
#[must_use]
pub struct CoseKey {
    inner: coset::CoseKey,
}

impl CoseKey {
    pub(crate) fn new(inner: coset::CoseKey) -> Self {
        Self { inner }
    }

    pub(crate) fn inner(&self) -> &coset::CoseKey {
        &self.inner
    }

    pub(crate) fn inner_mut(&mut self) -> &mut coset::CoseKey {
        &mut self.inner
    }
}

impl Drop for CoseKey {
    fn drop(&mut self) {
        zeroize_cose_key(&mut self.inner);
    }
}

impl ZeroizeOnDrop for CoseKey {}

fn zeroize_cose_key(key: &mut coset::CoseKey) {
    if let RegisteredLabel::Text(text) = &mut key.kty {
        text.zeroize();
    }
    key.key_id.zeroize();
    if let Some(RegisteredLabelWithPrivate::Text(text)) = &mut key.alg {
        text.zeroize();
    }
    for mut operation in core::mem::take(&mut key.key_ops) {
        if let RegisteredLabel::Text(text) = &mut operation {
            text.zeroize();
        }
    }
    key.base_iv.zeroize();
    for (label, value) in &mut key.params {
        if let Label::Text(text) = label {
            text.zeroize();
        }
        zeroize_value(value);
    }
}

#[cfg(test)]
#[path = "owned_tests.rs"]
mod tests;
