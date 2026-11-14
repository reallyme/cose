// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::own_bytes::{bstr, copy, head, reserve};
use super::read_cbor::Item;
use super::{
    ContainerError, ContainerErrorReason as Reason, ContainerSigner, EnvelopePolicy, SigningInput,
    SigningMode,
};
use crate::build_authentication_structure::{
    build_authentication_structure, AuthenticationContext,
};
use crate::iso18013::Iso18013EcdsaHash;
use reallyme_crypto::operations::hash;
use zeroize::Zeroizing;

/// Explicit attached or detached content for creation.
pub use crate::generated_contract::SigningContent;

/// Finalized headers and explicit creation contract.
pub use crate::generated_contract::ContainerSignRequest;

/// Created bytes, independently verified against the signer's bound public key.
/// Certificate headers remain caller-supplied data, not certificate trust evidence.
pub use crate::generated_contract::SignedContainer;
impl SignedContainer {
    /// Exact encoded Sign1; the owner wipes it on drop.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

/// Sign finalized exact Sig_structure through a non-exporting capability.
///
/// Provider output is strictly converted using its declared encoding and then
/// independently verified under its bound public key before bytes are released.
/// Certificate path/trust checks are a separate verification boundary.
///
/// # Errors
/// Returns fixed framing, policy, identity, signing-input, encoding, provider,
/// allocation or authentication errors. No partially signed result escapes.
pub fn sign_container(
    request: ContainerSignRequest<'_>,
    signer: &dyn ContainerSigner,
) -> Result<SignedContainer, ContainerError> {
    sign_container_operation(request, signer)
}

pub(crate) fn sign_container_operation(
    request: ContainerSignRequest<'_>,
    signer: &dyn ContainerSigner,
) -> Result<SignedContainer, ContainerError> {
    super::validate_allowlists::container_suites(request.allowed_suites)?;
    let key = signer.verification_key();
    let suite = key.suite();
    let (payload, attached) = match request.content {
        SigningContent::Attached(bytes) => (bytes, true),
        SigningContent::Detached(bytes) => (bytes, false),
    };
    let tagged = match request.policy.envelope {
        EnvelopePolicy::Untagged => false,
        EnvelopePolicy::Tagged => true,
        EnvelopePolicy::Either => return Err(Reason::Profile.into()),
    };
    let limit = request
        .limits
        .encoded_bytes
        .min(crate::limits::MAX_COSE_SIGN1_BYTES);
    if request.protected_headers.len() > limit
        || request.unprotected_headers.len() > limit
        || payload.len()
            > request
                .limits
                .payload_bytes
                .min(crate::limits::MAX_DETACHED_PAYLOAD_BYTES)
        || request.external_aad.len()
            > request
                .limits
                .external_aad_bytes
                .min(crate::limits::MAX_COSE_SIGN1_BYTES)
    {
        return Err(Reason::Limit.into());
    }
    if !request.allowed_suites.contains(&suite) {
        return Err(Reason::Algorithm.into());
    }
    let encoded_bytes = super::measure_envelope::measure_envelope(
        request.protected_headers.len(),
        request.unprotected_headers.len(),
        attached.then_some(payload.len()),
        suite.curve().signature_length()?,
        tagged,
    )?;
    if encoded_bytes > limit {
        return Err(Reason::Limit.into());
    }
    request
        .policy
        .check(suite, attached, tagged, request.external_aad)?;
    super::validate_preferred_cbor(request.unprotected_headers)?;
    let headers = super::read_headers::read_headers(
        request.protected_headers,
        Item::from_validated(request.unprotected_headers)?,
    )?;
    if headers.algorithm != suite.registration().identifier() {
        return Err(Reason::KeyAlgorithmMismatch.into());
    }
    super::verify::check_placement(
        request.policy,
        &headers.certificates,
        headers.certificates.placement.is_some() || headers.certificates.thumbprint.is_some(),
    )?;
    if attached && request.policy.profile != super::ContainerProfile::Rfc9360 {
        super::validate_preferred_cbor(payload)?;
    }
    let encoding = signer.signature_encoding();
    encoding.validate_family(suite.curve())?;
    let mode = signer.input_mode();
    if let SigningMode::EcdsaPrehash(selected) = mode {
        if suite.primitive_suite()?.algorithm().ecdsa_hash() != Some(selected) {
            return Err(Reason::SigningInput.into());
        }
    }
    // Reserve the bounded result before any hardware signing operation. A
    // request that cannot be emitted must not consume a signing authorization.
    let mut output = Zeroizing::new(Vec::new());
    reserve(&mut output, encoded_bytes)?;
    let structure = build_authentication_structure(
        AuthenticationContext::Signature1,
        request.protected_headers,
        request.external_aad,
        payload,
    )?;
    let produced = match mode {
        SigningMode::Message => signer.sign(SigningInput::Message(&structure))?,
        SigningMode::EcdsaPrehash(selected) => {
            let digest = hash_structure(selected, &structure)?;
            signer.sign(SigningInput::EcdsaPrehash {
                hash: selected,
                digest: &digest,
            })?
        }
    };
    let signature = super::signature_to_cose(suite.curve(), encoding, &produced)?;
    key.verify(&structure, &signature)?;
    if tagged {
        head(&mut output, 6, super::decode::COSE_SIGN1_TAG)?;
    }
    head(&mut output, 4, 4)?;
    bstr(&mut output, request.protected_headers)?;
    reserve(&mut output, request.unprotected_headers.len())?;
    output.extend_from_slice(request.unprotected_headers);
    if attached {
        bstr(&mut output, payload)?;
    } else {
        reserve(&mut output, 1)?;
        output.push(0xf6);
    }
    bstr(&mut output, &signature)?;
    if output.len() != encoded_bytes {
        return Err(Reason::Backend.into());
    }
    Ok(SignedContainer { encoded: output })
}

fn hash_structure(
    algorithm: Iso18013EcdsaHash,
    structure: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
    match algorithm {
        Iso18013EcdsaHash::Sha256 => {
            copy(&Zeroizing::new(hash::sha2_256(structure).into_bytes())[..])
        }
        Iso18013EcdsaHash::Sha384 => {
            copy(&Zeroizing::new(hash::sha2_384(structure).into_bytes())[..])
        }
        Iso18013EcdsaHash::Sha512 => {
            copy(&Zeroizing::new(hash::sha2_512(structure).into_bytes())[..])
        }
    }
}
