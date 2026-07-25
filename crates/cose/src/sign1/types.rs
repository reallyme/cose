// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Operation-specific semantic inputs for COSE_Sign1.

use reallyme_crypto::core::Algorithm;
use zeroize::Zeroizing;

use crate::policy::CosePolicy;

use super::provider::CoseSigner;
use super::sign::CoseSign1EncodeOptions;

pub(super) enum CoseSign1SigningSource<'a> {
    PrivateKey(&'a [u8]),
    Provider(&'a dyn CoseSigner),
}

pub(crate) struct CoseSign1CreateInput<'a> {
    pub(super) algorithm: Algorithm,
    pub(super) payload: &'a [u8],
    pub(super) signing_source: CoseSign1SigningSource<'a>,
    pub(super) kid: Option<&'a [u8]>,
    pub(super) external_aad: &'a [u8],
    pub(super) options: CoseSign1EncodeOptions,
}

impl<'a> CoseSign1CreateInput<'a> {
    pub(crate) const fn new(
        algorithm: Algorithm,
        payload: &'a [u8],
        private_key: &'a [u8],
        kid: Option<&'a [u8]>,
        external_aad: &'a [u8],
        options: CoseSign1EncodeOptions,
    ) -> Self {
        Self {
            algorithm,
            payload,
            signing_source: CoseSign1SigningSource::PrivateKey(private_key),
            kid,
            external_aad,
            options,
        }
    }

    pub(crate) fn with_signer(
        signer: &'a dyn CoseSigner,
        payload: &'a [u8],
        kid: Option<&'a [u8]>,
        external_aad: &'a [u8],
        options: CoseSign1EncodeOptions,
    ) -> Self {
        Self {
            algorithm: signer.algorithm(),
            payload,
            signing_source: CoseSign1SigningSource::Provider(signer),
            kid,
            external_aad,
            options,
        }
    }
}

pub(crate) struct CoseSign1VerifyInput<'a> {
    pub(super) cose_sign1: &'a [u8],
    pub(super) external_aad: &'a [u8],
    pub(super) policy: &'a CosePolicy,
}

impl<'a> CoseSign1VerifyInput<'a> {
    pub(crate) const fn new(
        cose_sign1: &'a [u8],
        external_aad: &'a [u8],
        policy: &'a CosePolicy,
    ) -> Self {
        Self {
            cose_sign1,
            external_aad,
            policy,
        }
    }
}

pub(crate) struct CoseSign1DetachedVerifyInput<'a> {
    pub(super) cose_sign1: &'a [u8],
    pub(super) payload: &'a [u8],
    pub(super) external_aad: &'a [u8],
    pub(super) policy: &'a CosePolicy,
}

impl<'a> CoseSign1DetachedVerifyInput<'a> {
    pub(crate) const fn new(
        cose_sign1: &'a [u8],
        payload: &'a [u8],
        external_aad: &'a [u8],
        policy: &'a CosePolicy,
    ) -> Self {
        Self {
            cose_sign1,
            payload,
            external_aad,
            policy,
        }
    }
}

/// Deliberately typed key-resolution outcome used by verification semantics.
///
/// A resolver receives both the protected-header algorithm and `kid`, then
/// returns an owned zeroizing key so semantic verification never has to clone
/// public-key storage supplied by a generated boundary.
pub(crate) enum CoseSign1KeyResolution {
    Resolved(Zeroizing<Vec<u8>>),
    NotResolved,
    #[cfg(feature = "wire")]
    KidMismatch,
}
