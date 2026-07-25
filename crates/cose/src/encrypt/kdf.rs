// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use ciborium::value::{Integer, Value};
use reallyme_crypto::kmac::{derive_kmac256, Kmac256Key};
use zeroize::Zeroizing;

use crate::encode_cbor::encode_cbor_value;
use crate::CoseError;

pub(crate) fn derive_key(
    shared_secret: &[u8],
    algorithm_id: i64,
    output_length: usize,
    recipient_protected: &[u8],
    supp_priv_info: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let output_bits = output_length
        .checked_mul(8)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let output_bits = u64::try_from(output_bits).map_err(|_| CoseError::ResourceLimitExceeded)?;

    // draft-ietf-jose-pqc-kem-06 deliberately removes PartyUInfo and
    // PartyVInfo. Retaining only AlgorithmID, SuppPubInfo, and optional
    // SuppPrivInfo avoids inventing identities while still binding the
    // derived key to the next-layer algorithm and recipient protected header.
    let supp_pub_info = Value::Array(vec![
        Value::Integer(Integer::from(output_bits)),
        Value::Bytes(recipient_protected.to_vec()),
    ]);
    let mut context_items = vec![Value::Integer(Integer::from(algorithm_id)), supp_pub_info];
    if let Some(supp_priv_info) = supp_priv_info {
        context_items.push(Value::Bytes(supp_priv_info.to_vec()));
    }

    let context = encode_cbor_value(Value::Array(context_items))?;

    let key = Kmac256Key::from_slice(shared_secret).map_err(|_| CoseError::Crypto)?;
    let derived =
        derive_kmac256(&key, &context, &[], output_length).map_err(|_| CoseError::Crypto)?;
    Ok(Zeroizing::new(derived.as_bytes().to_vec()))
}

pub(crate) fn enc_structure(
    body_protected: &[u8],
    external_aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let value = Value::Array(vec![
        Value::Text("Encrypt".to_owned()),
        Value::Bytes(body_protected.to_vec()),
        Value::Bytes(external_aad.to_vec()),
    ]);
    encode_cbor_value(value)
}
