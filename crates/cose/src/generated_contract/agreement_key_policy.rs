// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseAgreementKeyPolicy contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgreementKeyPolicy<'a> {
    /// Projection of CoseAgreementKeyPolicy.allowed_curves.
    pub allowed_curves: &'a [super::CoseCurve],
    /// Projection of CoseAgreementKeyPolicy.optional_parameters.
    pub optional_parameters: super::OptionalKeyPolicy,
    /// Projection of CoseAgreementKeyPolicy.ec2_encoding.
    pub ec2_encoding: super::AgreementEc2EncodingPolicy,
}
