// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use super::values;
use crate::CoseError;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseByteLimits as Wire;

/// Checked native view of the sole portable byte-limit message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerLimits {
    /// Schema-defined ceiling for encoded_bytes.
    pub encoded_bytes: usize,
    /// Schema-defined ceiling for payload_bytes.
    pub payload_bytes: usize,
    /// Schema-defined ceiling for external_aad_bytes.
    pub external_aad_bytes: usize,
}
impl Default for ContainerLimits {
    fn default() -> Self {
        Self {
            encoded_bytes: values::MAX_COSE_SIGN1_BYTES,
            payload_bytes: values::MAX_DETACHED_PAYLOAD_BYTES,
            external_aad_bytes: values::MAX_COSE_SIGN1_BYTES,
        }
    }
}
impl TryFrom<&Wire> for ContainerLimits {
    type Error = CoseError;
    fn try_from(value: &Wire) -> Result<Self, Self::Error> {
        if value.encoded_bytes
            > u64::try_from(values::MAX_COSE_SIGN1_ENCODED_BYTES)
                .map_err(|_| CoseError::ResourceLimitExceeded)?
        {
            return Err(CoseError::ResourceLimitExceeded);
        }
        Ok(Self {
            encoded_bytes: usize::try_from(
                value.encoded_bytes.min(
                    u64::try_from(values::MAX_COSE_SIGN1_ENCODED_BYTES)
                        .map_err(|_| CoseError::ResourceLimitExceeded)?,
                ),
            )
            .map_err(|_| CoseError::ResourceLimitExceeded)?,
            payload_bytes: usize::try_from(
                value.payload_bytes.min(
                    u64::try_from(values::MAX_DETACHED_PAYLOAD_BYTES)
                        .map_err(|_| CoseError::ResourceLimitExceeded)?,
                ),
            )
            .map_err(|_| CoseError::ResourceLimitExceeded)?,
            external_aad_bytes: usize::try_from(
                value.external_aad_bytes.min(
                    u64::try_from(values::MAX_COSE_SIGN1_BYTES)
                        .map_err(|_| CoseError::ResourceLimitExceeded)?,
                ),
            )
            .map_err(|_| CoseError::ResourceLimitExceeded)?,
        })
    }
}
