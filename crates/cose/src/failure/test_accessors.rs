// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{CoseFailure, CoseFailureBranch, CoseFailureOrigin, CoseFailureReason};

impl CoseFailure {
    pub(crate) const fn origin(&self) -> CoseFailureOrigin {
        self.origin
    }

    pub(crate) const fn branch(&self) -> CoseFailureBranch {
        self.branch
    }

    pub(crate) const fn reason(&self) -> CoseFailureReason {
        self.reason
    }
}
