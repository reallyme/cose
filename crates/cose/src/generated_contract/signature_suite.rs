// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use super::{CoseCurve, CoseSignatureAlgorithm};
use crate::CoseError;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseSignatureSuite as Wire;

/// Closed compatibility value generated from CoseSignatureSuite.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SignatureSuite {
    /// Schema field registration.
    pub(crate) registration: CoseSignatureAlgorithm,
    /// Schema field curve.
    pub(crate) curve: CoseCurve,
}

impl TryFrom<&Wire> for SignatureSuite {
    type Error = CoseError;
    fn try_from(value: &Wire) -> Result<Self, Self::Error> {
        Ok(Self {
            registration: CoseSignatureAlgorithm::try_from(value.registration)?,
            curve: CoseCurve::try_from(value.curve)?,
        })
    }
}

impl From<SignatureSuite> for Wire {
    fn from(value: SignatureSuite) -> Self {
        Self {registration: reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseSignatureAlgorithm::from(value.registration).into(),curve: reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseNamedCurve::from(value.curve).into()}
    }
}
