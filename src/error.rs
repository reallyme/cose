// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[cfg(feature = "cose-crypto")]
use reallyme_crypto::dispatch::AlgorithmError;

#[derive(Debug, Error, PartialEq, Eq)]
/// Error type for COSE encoding, signing, verification, key, and policy operations.
pub enum CoseError {
    /// CBOR serialization or parsing failed.
    #[error("cbor encoding/decoding error")]
    Cbor,

    /// The requested algorithm is not supported by the current COSE mapping.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    /// A COSE_Sign1 object did not contain an attached payload where one was required.
    #[error("missing payload")]
    MissingPayload,

    /// Signature verification failed or the signature encoding was invalid.
    #[error("invalid signature")]
    InvalidSignature,

    /// The configured cryptographic backend rejected the operation.
    #[error("crypto error")]
    Crypto,

    /// A Multikey value was malformed or could not be converted safely.
    #[error("invalid multikey")]
    InvalidMultikey,

    /// Required public or private key bytes were absent.
    #[error("missing key material")]
    MissingKeyMaterial,

    /// Key bytes were present but did not match the expected COSE key shape.
    #[error("invalid key material")]
    InvalidKeyMaterial,

    /// A policy required `kid` / key_id but the COSE object did not provide one.
    #[error("missing kid")]
    MissingKid,

    /// A `kid` was present, but the caller's resolver did not return a key.
    #[error("key not resolved")]
    KeyNotResolved,

    /// The COSE object is structurally invalid for the requested operation.
    #[error("invalid COSE format")]
    InvalidFormat,

    /// Encoded input exceeded the crate's deterministic resource limits.
    #[error("resource limit exceeded")]
    ResourceLimitExceeded,

    /// Encoded input used indefinite-length or otherwise non-canonical CBOR.
    #[error("non-canonical CBOR")]
    NonCanonicalCbor,

    /// Encoded input used CBOR tags outside this crate's supported profile.
    #[error("unexpected CBOR tag")]
    UnexpectedCborTag,

    /// Encoded input repeated a CBOR map label where uniqueness is required.
    #[error("duplicate CBOR map label")]
    DuplicateMapLabel,

    /// A critical protected header was present but is not supported.
    #[error("unsupported critical header")]
    UnsupportedCriticalHeader,

    /// An unprotected header carried fields that must be integrity protected.
    #[error("unprotected header not allowed")]
    UnprotectedHeaderNotAllowed,

    /// Private key material was required but absent.
    #[error("missing private key material")]
    MissingPrivateKey,
}

#[cfg(feature = "cose-crypto")]
impl From<AlgorithmError> for CoseError {
    fn from(_: AlgorithmError) -> Self {
        CoseError::Crypto
    }
}
