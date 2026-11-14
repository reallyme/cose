// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Compatibility name for the single schema-generated curve selector.
pub use crate::generated_contract::CoseCurve as PeerCurve;

impl PeerCurve {
    /// EC2 coordinate width, or none for OKP.
    #[must_use]
    pub const fn coordinate_bytes(self) -> Option<usize> {
        self.coordinate_length()
    }
    /// Canonical OKP public width, distinct for Ed448 and X448.
    #[must_use]
    pub const fn okp_bytes(self) -> Option<usize> {
        self.okp_public_length()
    }
}
