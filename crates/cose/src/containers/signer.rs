// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerError, SignatureEncoding, VerificationKey};
use crate::iso18013::Iso18013EcdsaHash;
use zeroize::Zeroizing;

/// Closed callback view generated from protobuf.
pub use crate::generated_contract::SigningMode;

/// Borrowed finalized input; a prehash never masquerades as an ordinary message.
pub use crate::generated_contract::SigningInput;

/// Opaque non-exporting signing capability with a stable public-key binding.
///
/// No private-key accessor exists. Adapters implement the declared input mode
/// and encoding exactly; errors never include handles or backend diagnostics.
pub trait ContainerSigner {
    /// Validated public key, exact suite and context bound to the private handle.
    fn verification_key(&self) -> &dyn VerificationKey;
    /// Stable message or explicit ECDSA-prehash contract.
    fn input_mode(&self) -> SigningMode;
    /// Stable declared signature encoding, never guessed from length.
    fn signature_encoding(&self) -> SignatureEncoding;
    /// Sign finalized input without exporting the private key.
    ///
    /// # Errors
    /// Returns fixed key, provider, input-mode or backend failures.
    fn sign(&self, input: SigningInput<'_>) -> Result<Zeroizing<Vec<u8>>, ContainerError>;
}

impl
    TryFrom<
        &reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseProviderSignerDescription,
    > for SigningMode
{
    type Error = ContainerError;
    fn try_from(
        value:&reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseProviderSignerDescription,
    ) -> Result<Self, Self::Error> {
        use reallyme_cose_proto::generated::proto::reallyme::cose::v1::{
            CoseHashAlgorithm, CoseSigningMode,
        };
        match value.signing_mode.as_known() {
            Some(CoseSigningMode::Message) if value.prehash == CoseHashAlgorithm::Unspecified => {
                Ok(Self::Message)
            }
            Some(CoseSigningMode::EcdsaPrehash) => Ok(Self::EcdsaPrehash(
                Iso18013EcdsaHash::try_from(value.prehash)
                    .map_err(|_| super::ContainerErrorReason::SigningInput)?,
            )),
            _ => Err(super::ContainerErrorReason::SigningInput.into()),
        }
    }
}
