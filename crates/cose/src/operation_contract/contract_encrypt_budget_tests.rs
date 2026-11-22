// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::ml_kem_1024::generate_ml_kem_1024_keypair_from_seed;
use zeroize::Zeroizing;

use super::support::{codec_parity, success};
use crate::api::contract::{
    cose_operation_request::Operation, cose_operation_result::Result as Branch,
    CoseMlKemDecryptRequest as Request,
};
use crate::{
    cose_encrypt_ml_kem_direct_with_external_aad, cose_encrypt_ml_kem_key_wrap_with_external_aad,
    cose_key_from_public_bytes, derive_kid_from_cose_key_public, Algorithm,
    CoseContentEncryptionAlgorithm, CoseError, CoseMlKemAlgorithm, CoseMlKemEncryptRequest,
};

const MAX_PLAINTEXT_BYTES: usize = 1_048_576;
const MAX_EXTERNAL_AAD_BYTES: usize = 1_048_576;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn large_encrypted_envelopes_and_aad_preserve_generated_transport_parity() -> Result<(), CoseError>
{
    let seed = Zeroizing::new([0x37; 64]);
    let (public, private) =
        generate_ml_kem_1024_keypair_from_seed(&seed).map_err(|_| CoseError::Crypto)?;
    let public = Zeroizing::new(public);
    let key = cose_key_from_public_bytes(Algorithm::MlKem1024, &public)?;
    let kid = Zeroizing::new(derive_kid_from_cose_key_public(&key)?);
    // Exercise each field maximum separately. The schema also bounds the
    // complete protobuf transport independently of the semantic field limits.
    for (plaintext_bytes, aad_bytes) in [(MAX_PLAINTEXT_BYTES, 0), (0, MAX_EXTERNAL_AAD_BYTES)] {
        let plaintext = Zeroizing::new(vec![0xa5; plaintext_bytes]);
        let aad = Zeroizing::new(vec![0x5a; aad_bytes]);
        let request = CoseMlKemEncryptRequest::new(
            CoseMlKemAlgorithm::MlKem1024,
            CoseContentEncryptionAlgorithm::Aes256Gcm,
            &public,
            &kid,
            &plaintext,
            None,
        );
        for wrapped in [false, true] {
            let encoded = if wrapped {
                cose_encrypt_ml_kem_key_wrap_with_external_aad(&request, &aad)?
            } else {
                cose_encrypt_ml_kem_direct_with_external_aad(&request, &aad)?
            };
            let request = Request::default()
                .with_cose_encrypt(encoded.to_vec())
                .with_recipient_private_key(private.to_vec())
                .with_expected_recipient_kid(kid.to_vec())
                .with_external_aad(aad.to_vec());
            let response = codec_parity(Operation::MlKemDecrypt(Box::new(request)))?;
            let branch = success(response);
            let Branch::MlKemDecrypt(result) = &branch else {
                return Err(CoseError::InvalidFormat);
            };
            assert_eq!(result.plaintext.as_slice(), plaintext.as_slice());
        }
    }
    Ok(())
}
