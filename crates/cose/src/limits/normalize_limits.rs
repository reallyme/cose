// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseByteLimits;

use super::profile::{
    check_sign1_limit, native_limit, MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES,
};
use crate::CoseError;

pub(crate) fn normalize_byte_limits(limits: &mut CoseByteLimits) -> Result<(), CoseError> {
    // Encoded budgets retain the caller's exact selection within the absolute
    // ceiling. Payload and AAD retain their existing clamping semantics.
    // Replacing only an already-present message preserves absent vs zero.
    *limits = CoseByteLimits {
        encoded_bytes: u64::try_from(check_sign1_limit(
            usize::try_from(limits.encoded_bytes).map_err(|_| CoseError::ResourceLimitExceeded)?,
        )?)
        .map_err(|_| CoseError::ResourceLimitExceeded)?,
        payload_bytes: u64::try_from(native_limit(
            limits.payload_bytes,
            MAX_DETACHED_PAYLOAD_BYTES,
        ))
        .map_err(|_| CoseError::ResourceLimitExceeded)?,
        external_aad_bytes: u64::try_from(native_limit(
            limits.external_aad_bytes,
            MAX_COSE_SIGN1_BYTES,
        ))
        .map_err(|_| CoseError::ResourceLimitExceeded)?,
    };
    Ok(())
}
