// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit ISO 2021, pinned edition-2 DIS and strict RFC 9360 containers.
//!
//! Exact authenticated bytes, certificate-bound capabilities, protected owners,
//! independent agreement-key inspection and non-exporting signing contracts.
//! These APIs never implement reader negotiation, payload schemas, certificate
//! trust policy, revocation processing, HPKE or ZKP interpretation.

mod decode;
mod error;
mod inspect_key;
mod measure_envelope;
mod own_bytes;
mod peer_curve;
mod peer_key;
mod policy;
mod preflight;
mod provider;
mod read_cbor;
mod read_headers;
mod receipt;
mod scalar_order;
mod sign;
mod signature;
mod signer;
mod suite;
mod verify;

pub use error::{ContainerError, ContainerErrorReason};
pub use inspect_key::inspect_peer_key;
pub use peer_curve::PeerCurve;
pub use peer_key::{
    CryptoPeerKeyValidator, InspectedPeerKey, OptionalKeyPolicy, PeerKeyUsage, PeerKeyValidator,
    PeerPointEncoding, ValidatedPeerKey,
};
pub use policy::{
    ContainerContent, ContainerLimits, ContainerPolicy, ContainerProfile, ContainerPurpose,
    EnvelopePolicy,
};
pub use preflight::validate_preferred_cbor;
pub use provider::{
    CertificateSelection, CertificateValidator, CryptoVerificationKey, VerificationKey,
    VerificationSource,
};
pub use read_headers::{CertificateHeaders, X5T_SHA256_IDENTIFIER};
pub use receipt::{EndEntityIntegrity, HeaderProvenance, VerifiedContainer};
pub use sign::{sign_container, ContainerSignRequest, SignedContainer, SigningContent};
pub use signature::{
    cose_signature_to_der, signature_to_cose, validate_cose_signature, SignatureEncoding,
};
pub use signer::{ContainerSigner, SigningInput, SigningMode};
pub use suite::{SignatureRegistration, SignatureSuite};
pub use verify::{verify_container, ContainerVerifyRequest};

#[cfg(test)]
mod tests;
