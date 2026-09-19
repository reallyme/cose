// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit wire-shape policies for public EC2 COSE keys.

/// Encoding used for the EC2 `y` parameter in a public COSE_Key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoseEc2PointEncoding {
    /// RFC 9053 compact form: `y` is the point-parity boolean.
    #[default]
    Compressed,
    /// Full affine form: both `x` and `y` are byte strings.
    FullCoordinates,
}
