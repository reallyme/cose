// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Executable adapters for the generated COSE operation contract.

pub(crate) mod agreement;
pub(crate) mod container_sign;
pub(crate) mod container_verify;
pub(crate) mod encrypt;
pub(crate) mod execute;
pub(crate) mod input;
pub(crate) mod iso_verify;
pub(crate) mod key;
pub(crate) mod mac0;
mod map_failure;
pub(crate) mod map_profile_failure;
pub(crate) mod peer_key;
pub(crate) mod profile_input;
pub(crate) mod profile_response;
pub(crate) mod profile_result;
pub(crate) mod provider_transport;
pub(crate) mod providers;
pub(crate) mod response_v2;
pub(crate) mod sign1;
pub(crate) mod signature;
pub(crate) mod suite;

#[cfg(test)]
mod map_failure_tests;
#[cfg(test)]
mod tests;
