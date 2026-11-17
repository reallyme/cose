// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::cose_type::CoseType;
use crate::generated_contract::X5ChainHeaderPlacement;
use crate::limits::{
    native_limit, portable_limit, MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES,
};
use zeroize::Zeroizing;

/// Native convenience builder over the generated encoding-options message.
#[must_use]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoseSign1EncodeOptions {
    contract: crate::api::contract::CoseSign1Options,
}

impl Default for CoseSign1EncodeOptions {
    fn default() -> Self {
        Self::new()
    }
}
impl CoseSign1EncodeOptions {
    /// Default untagged encoding with protected certificate placement.
    pub fn new() -> Self {
        Self {
            contract: Default::default(),
        }
    }
    /// Emit the registered Sign1 tag 18.
    pub fn tagged() -> Self {
        Self::new().with_tag(true)
    }
    /// The sole generated options owner.
    pub fn contract(&self) -> &crate::api::contract::CoseSign1Options {
        &self.contract
    }
    /// Whether to emit the root tag.
    pub fn tag(&self) -> bool {
        self.contract.tag
    }
    /// Maximum encoded size; absent legacy zero retains the historical default.
    pub fn max_cose_sign1_bytes(&self) -> usize {
        if let Some(limits) = self.contract.limits.as_option() {
            return native_limit(limits.encoded_bytes, usize::MAX);
        }
        if self.contract.max_cose_sign1_bytes == 0 {
            MAX_COSE_SIGN1_BYTES
        } else {
            native_limit(self.contract.max_cose_sign1_bytes, usize::MAX)
        }
    }
    pub(super) fn max_payload_bytes(&self) -> usize {
        self.contract
            .limits
            .as_option()
            .map_or(MAX_DETACHED_PAYLOAD_BYTES, |limits| {
                native_limit(limits.payload_bytes, MAX_DETACHED_PAYLOAD_BYTES)
            })
    }
    pub(super) fn max_external_aad_bytes(&self) -> usize {
        self.contract
            .limits
            .as_option()
            .map_or(MAX_COSE_SIGN1_BYTES, |limits| {
                native_limit(limits.external_aad_bytes, MAX_COSE_SIGN1_BYTES)
            })
    }
    /// Exact end-entity-first discovery chain.
    pub fn x5chain_der(&self) -> &[reallyme_cose_proto::SecretBytes] {
        self.contract
            .x5chain
            .as_option()
            .map_or(&[], |value| &value.certificates_der)
    }
    /// Explicit placement, with the historical protected default.
    pub fn x5chain_header_placement(&self) -> X5ChainHeaderPlacement {
        match X5ChainHeaderPlacement::try_from(self.contract.x5chain_header_placement) {
            Ok(value) => value,
            Err(_) => X5ChainHeaderPlacement::Protected,
        }
    }
    /// Authenticated typ alternative from the generated oneof.
    pub fn protected_type(&self) -> Option<&CoseType> {
        self.contract
            .protected_type
            .as_option()
            .and_then(|value| value.value.as_ref())
    }
    /// Set root-tag emission.
    pub fn with_tag(mut self, value: bool) -> Self {
        self.contract.tag = value;
        self
    }
    /// Select an encoded Sign1 budget; unsupported budgets fail at the operation boundary.
    pub fn with_max_cose_sign1_bytes(mut self, value: usize) -> Self {
        if self.contract.limits.as_option().is_none() {
            self.contract.limits =
                buffa::MessageField::some(crate::api::contract::CoseByteLimits {
                    encoded_bytes: portable_limit(MAX_COSE_SIGN1_BYTES, MAX_COSE_SIGN1_BYTES),
                    payload_bytes: portable_limit(
                        MAX_DETACHED_PAYLOAD_BYTES,
                        MAX_DETACHED_PAYLOAD_BYTES,
                    ),
                    external_aad_bytes: portable_limit(MAX_COSE_SIGN1_BYTES, MAX_COSE_SIGN1_BYTES),
                });
        }
        self.contract.limits.get_or_insert_default().encoded_bytes =
            portable_limit(value, usize::MAX);
        self
    }
    #[cfg(feature = "wire")]
    pub(crate) fn with_limits(
        mut self,
        mut limits: crate::api::contract::CoseByteLimits,
    ) -> Result<Self, crate::CoseError> {
        crate::limits::normalize_byte_limits(&mut limits)?;
        self.contract.limits = buffa::MessageField::some(limits);
        Ok(self)
    }
    /// Move exact discovery certificate owners into the generated options.
    pub fn with_x5chain_der(self, value: Vec<Vec<u8>>) -> Self {
        let mut owner = Zeroizing::new(value);
        self.with_guarded_x5chain(
            owner
                .iter_mut()
                .map(|certificate| core::mem::take(certificate).into())
                .collect(),
        )
    }
    pub(crate) fn with_guarded_x5chain(
        mut self,
        value: buffa::sensitive::List<reallyme_cose_proto::SecretBytes>,
    ) -> Self {
        self.contract.x5chain = buffa::MessageField::some(crate::api::contract::CoseX5Chain {
            certificates_der: value,
        });
        self
    }
    /// Select the certificate header bucket.
    pub fn with_x5chain_header_placement(mut self, value: X5ChainHeaderPlacement) -> Self {
        self.contract.x5chain_header_placement =
            crate::api::contract::CoseX5ChainHeaderPlacement::from(value).into();
        self
    }
    /// Set protected typ without changing its alternative.
    pub fn with_protected_type(mut self, value: CoseType) -> Self {
        self.contract.protected_type =
            buffa::MessageField::some(crate::api::contract::CoseType { value: Some(value) });
        self
    }
}
