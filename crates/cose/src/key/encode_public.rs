// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::convert::{
    construct_cose_key_from_public, construct_cose_key_from_signature_public, encode_cose_key,
    extract_cose_key_public, CoseKeyBytesOutput, CoseKeyFromPublicBytesInput, CoseKeyRefInput,
};
use super::profile::{algorithm_for_cose_key, cose_key_signature_algorithm};
use crate::failure::CoseFailure;

pub(crate) fn encode_cose_key_public(
    input: CoseKeyRefInput<'_>,
) -> Result<CoseKeyBytesOutput, CoseFailure> {
    let algorithm = algorithm_for_cose_key(input.key())?;
    let registration = cose_key_signature_algorithm(input.key())?;
    let has_algorithm = input.key().inner().alg.is_some();
    let public = extract_cose_key_public(input)?.into_zeroizing();
    // Reconstruct from validated public material, never clone an input map.
    // An extension named "d" is as opaque as any other unknown parameter and
    // must not enter an encoding advertised as a public identity projection.
    let mut projected = match registration {
        Some(registration) => construct_cose_key_from_signature_public(registration, &public)?,
        None => {
            construct_cose_key_from_public(CoseKeyFromPublicBytesInput::new(algorithm, &public))?
        }
    }
    .into_key();
    if !has_algorithm {
        // Constructors choose modern defaults; projection must not add an
        // algorithm restriction that was absent from the received key.
        projected.inner_mut().alg = None;
    }
    encode_cose_key(CoseKeyRefInput::new(&projected))
}
