// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseByteLimits;

use super::profile::{native_limit, MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES};
use crate::CoseError;

pub(crate) fn normalize_byte_limits(limits: &mut CoseByteLimits) -> Result<(), CoseError> {
    // Use the schema-derived maxima and the same checked clamping as native
    // accessors. This boundary also works without a cryptographic runtime.
    // Replacing only an already-present message preserves absent vs zero.
    *limits = CoseByteLimits {
        encoded_bytes: u64::try_from(native_limit(limits.encoded_bytes, MAX_COSE_SIGN1_BYTES))
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
