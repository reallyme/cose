// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use zeroize::ZeroizeOnDrop;

use crate::build_authentication_structure::{
    build_authentication_structure, AuthenticationContext,
};
use crate::iso18013::{
    cose_verify_iso18013_sign1, Iso18013CryptoVerifier, Iso18013Sign1Content, Iso18013Verifier,
    VerifiedIso18013Sign1,
};
use crate::CoseError;

use super::support::{assert_error, encode, envelope, hex, key, request, suite, vectors};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn independent_openssl_vectors_verify_for_every_builtin_pair_and_role() -> Result<(), CoseError> {
    let mut verified = 0;
    for vector in vectors()? {
        let selected = suite(&vector)?;
        if !selected.has_builtin_provider() {
            continue;
        }
        let verifier = Iso18013CryptoVerifier::new(selected, key(&vector))?;
        let allowed = [selected];
        let attached = hex(&vector.attached_hex);
        let detached = hex(&vector.detached_hex);
        let payload = hex(&vector.payload_hex);
        let result = cose_verify_iso18013_sign1(
            request(&attached, Iso18013Sign1Content::IssuerAttached, &allowed),
            &verifier,
        )?;
        assert_eq!(result.suite(), selected);
        assert_eq!(result.attached_payload(), Some(payload.as_slice()));
        assert_eq!(result.protected_header_bytes(), hex(&vector.protected_hex));
        assert_eq!(result.protected_key_id(), Some(b"iso-fixture".as_slice()));
        for content in [
            Iso18013Sign1Content::DeviceDetached(payload.as_slice()),
            Iso18013Sign1Content::ReaderDetached(payload.as_slice()),
        ] {
            let result =
                cose_verify_iso18013_sign1(request(&detached, content, &allowed), &verifier)?;
            assert_eq!(result.attached_payload(), None);
        }
        let structure = build_authentication_structure(
            AuthenticationContext::Signature1,
            &hex(&vector.protected_hex),
            &[],
            &payload,
        )?;
        assert_eq!(*structure, hex(&vector.sig_structure_hex));
        verified += 1;
    }
    assert_eq!(verified, 4);
    fn wipe_owner<T: ZeroizeOnDrop>() {}
    wipe_owner::<Iso18013CryptoVerifier>();
    wipe_owner::<VerifiedIso18013Sign1>();
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn tampered_content_protected_order_signature_and_aad_are_rejected() -> Result<(), CoseError> {
    for vector in vectors()? {
        let selected = suite(&vector)?;
        if !selected.has_builtin_provider() {
            continue;
        }
        let verifier = Iso18013CryptoVerifier::new(selected, key(&vector))?;
        let allowed = [selected];
        let payload = hex(&vector.payload_hex);
        let protected = hex(&vector.protected_hex);
        let signature = hex(&vector.signature_hex);
        let detached = hex(&vector.detached_hex);
        assert_error(
            cose_verify_iso18013_sign1(
                request(
                    &detached,
                    Iso18013Sign1Content::DeviceDetached(b"changed"),
                    &allowed,
                ),
                &verifier,
            ),
            CoseError::InvalidSignature,
        );
        let reordered = encode(Value::Map(vec![
            (1.into(), vector.algorithm.into()),
            (4.into(), Value::Bytes(b"iso-fixture".to_vec())),
        ]));
        let changed = envelope(&reordered, Value::Map(vec![]), None, &signature);
        assert_error(
            cose_verify_iso18013_sign1(
                request(
                    &changed,
                    Iso18013Sign1Content::DeviceDetached(&payload),
                    &allowed,
                ),
                &verifier,
            ),
            CoseError::InvalidSignature,
        );
        for index in [0, signature.len() - 1] {
            let mut changed_signature = signature.clone();
            changed_signature[index] ^= 1;
            let changed = envelope(&protected, Value::Map(vec![]), None, &changed_signature);
            assert_error(
                cose_verify_iso18013_sign1(
                    request(
                        &changed,
                        Iso18013Sign1Content::ReaderDetached(&payload),
                        &allowed,
                    ),
                    &verifier,
                ),
                CoseError::InvalidSignature,
            );
        }
        // A real signature for the empty-AAD structure must not authenticate
        // the same fields under nonempty AAD. ISO has no AAD override option.
        let wrong_structure = build_authentication_structure(
            AuthenticationContext::Signature1,
            &protected,
            b"aad",
            &payload,
        )?;
        assert_error(
            verifier.verify(&wrong_structure, &signature),
            CoseError::InvalidSignature,
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn wrong_valid_keys_and_modern_default_registration_rejections() -> Result<(), CoseError> {
    for vector in vectors()? {
        let selected = suite(&vector)?;
        let detached = hex(&vector.detached_hex);
        let payload = hex(&vector.payload_hex);
        if vector.algorithm != -7 {
            assert_error(
                crate::cose_verify1_detached(&detached, &payload, |_, _| None),
                CoseError::UnsupportedAlgorithm,
            );
        }
        if !selected.has_builtin_provider() {
            continue;
        }
        let wrong_public = hex(&vector.wrong_public_key_hex);
        let verifier =
            Iso18013CryptoVerifier::new(selected, zeroize::Zeroizing::new(wrong_public))?;
        assert_error(
            cose_verify_iso18013_sign1(
                request(
                    &detached,
                    Iso18013Sign1Content::DeviceDetached(&payload),
                    &[selected],
                ),
                &verifier,
            ),
            CoseError::InvalidSignature,
        );
    }
    Ok(())
}
