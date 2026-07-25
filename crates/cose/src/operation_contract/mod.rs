// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Executable adapters for the generated COSE operation contract.

pub(crate) mod encrypt;
pub(crate) mod execute;
pub(crate) mod input;
pub(crate) mod key;
mod map_failure;
pub(crate) mod response_v2;
pub(crate) mod sign1;

#[cfg(test)]
mod map_failure_tests;
