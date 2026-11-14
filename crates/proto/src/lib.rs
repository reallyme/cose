// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated protobuf boundary types for the ReallyMe COSE wire contract.

#[cfg(feature = "generated")]
pub mod generated;

#[cfg(feature = "generated")]
mod contract_extensions;
#[cfg(feature = "generated")]
mod guarded_decode;
#[cfg(feature = "generated")]
mod secret_bytes;
#[cfg(feature = "generated")]
mod secret_json_bytes;
#[cfg(feature = "generated")]
mod secret_json_string;
#[cfg(feature = "generated")]
mod secret_string;

#[cfg(feature = "generated")]
pub use secret_bytes::SecretBytes;
#[cfg(feature = "generated")]
pub use secret_string::SecretString;
