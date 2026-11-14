// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared policy validation for borrowed and generated operation entrypoints.

use super::{ContainerError, ContainerErrorReason as Reason, SignatureSuite};
use crate::generated_contract::values::MAX_ALLOWLIST_ENTRIES;

pub(crate) fn container_suites(suites: &[SignatureSuite]) -> Result<(), ContainerError> {
    check_count(suites.len())?;
    for suite in suites {
        SignatureSuite::for_container(suite.registration(), suite.curve())?;
    }
    Ok(())
}

pub(crate) fn iso_suites(suites: &[SignatureSuite]) -> Result<(), ContainerError> {
    check_count(suites.len())?;
    for suite in suites {
        SignatureSuite::new(suite.registration(), suite.curve())?;
    }
    Ok(())
}

fn check_count(count: usize) -> Result<(), ContainerError> {
    if count > MAX_ALLOWLIST_ENTRIES {
        return Err(Reason::Limit.into());
    }
    Ok(())
}
