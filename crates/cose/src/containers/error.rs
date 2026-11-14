// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Compatibility name for the shared, schema-defined failure owner.
pub type ContainerError = crate::CoseError;
/// Compatibility name for the sole generated reason enum.
pub use crate::error::CoseErrorReason as ContainerErrorReason;
