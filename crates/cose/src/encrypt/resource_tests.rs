// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::ml_kem_1024::generate_ml_kem_1024_keypair_from_seed;
use zeroize::Zeroizing;

use super::codec::{MAX_EXTERNAL_AAD_BYTES, MAX_PLAINTEXT_BYTES};
use super::{
    cose_decrypt_ml_kem_with_external_aad, cose_encrypt_ml_kem_direct_with_external_aad,
    cose_encrypt_ml_kem_key_wrap_with_external_aad, CoseContentEncryptionAlgorithm,
    CoseMlKemAlgorithm, CoseMlKemDecryptRequest, CoseMlKemEncryptRequest,
};
use crate::key::{cose_key_from_public_bytes, derive_kid_from_cose_key_public};
use crate::{cbor_boundary, limits::MAX_COSE_ENCRYPT_BYTES, Algorithm, CoseError};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn maximum_plaintext_and_aad_round_trip_in_both_recipient_modes() -> Result<(), CoseError> {
    // Public fixture seed; no protobuf message is encoded or decoded here.
    let seed = Zeroizing::new([0x37; 64]);
    let (public, private) =
        generate_ml_kem_1024_keypair_from_seed(&seed).map_err(|_| CoseError::Crypto)?;
    let public = Zeroizing::new(public);
    let key = cose_key_from_public_bytes(Algorithm::MlKem1024, &public)?;
    let kid = Zeroizing::new(derive_kid_from_cose_key_public(&key)?);
    let plaintext = Zeroizing::new(vec![0xa5; MAX_PLAINTEXT_BYTES]);
    let request = CoseMlKemEncryptRequest::new(
        CoseMlKemAlgorithm::MlKem1024,
        CoseContentEncryptionAlgorithm::Aes256Gcm,
        &public,
        &kid,
        &plaintext,
        None,
    );
    let maximum_aad = Zeroizing::new(vec![0x5a; MAX_EXTERNAL_AAD_BYTES]);
    for aad in [b"".as_slice(), maximum_aad.as_slice()] {
        for wrapped in [false, true] {
            let encoded = if wrapped {
                cose_encrypt_ml_kem_key_wrap_with_external_aad(&request, aad)?
            } else {
                cose_encrypt_ml_kem_direct_with_external_aad(&request, aad)?
            };
            assert!(encoded.len() > MAX_PLAINTEXT_BYTES);
            assert!(encoded.len() <= MAX_COSE_ENCRYPT_BYTES);
            let decrypted = cose_decrypt_ml_kem_with_external_aad(
                &CoseMlKemDecryptRequest::new(&encoded, &private, &kid, None),
                aad,
            )?;
            assert_eq!(decrypted.plaintext.as_slice(), plaintext.as_slice());
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn encrypt_framing_preserves_unrelated_resource_limits() -> Result<(), CoseError> {
    let original = cbor_boundary::limits()?;
    // Smaller envelopes retain every existing default. Larger envelopes need
    // only the input and aggregate byte-string budgets to accommodate framing.
    for size in [0, 4_096, MAX_PLAINTEXT_BYTES, MAX_COSE_ENCRYPT_BYTES] {
        let limits = cbor_boundary::encrypt_limits(size)?;
        assert_eq!(limits.input_bytes(), size.max(original.input_bytes()));
        assert_eq!(
            limits.byte_string_bytes(),
            size.max(original.byte_string_bytes())
        );
        assert_eq!(limits.output_bytes(), original.output_bytes());
        assert_eq!(limits.text_bytes(), original.text_bytes());
        assert_eq!(limits.nodes(), original.nodes());
        assert_eq!(limits.depth(), original.depth());
        assert_eq!(limits.entries(), original.entries());
        assert_eq!(limits.work(), original.work());
        assert_eq!(cbor_boundary::limits()?, original);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn encrypt_framing_rejects_unsupported_lengths_before_allocation() -> Result<(), CoseError> {
    let over = MAX_COSE_ENCRYPT_BYTES
        .checked_add(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    for size in [over, usize::MAX] {
        assert_eq!(
            cbor_boundary::encrypt_limits(size),
            Err(CoseError::ResourceLimitExceeded)
        );
    }
    Ok(())
}
