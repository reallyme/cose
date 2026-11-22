// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::ManuallyDrop;

use coset::{CoseRecipient, ProtectedHeader, RegisteredLabelWithPrivate};
use zeroize::Zeroizing;

use super::{
    authenticate_after_key_establishment, decapsulate_for_recipient, derive_recipient_content_key,
    suite_from_cose_algorithm, CoseError, CoseMlKemAlgorithm, CoseMlKemMode, MlKemSuite,
};
use crate::Algorithm;

const KID: [u8; 32] = [0x34; 32];
const SEED: [u8; 64] = [0x43; 64];
const PUBLIC: &[u8] = &[0x47];
const SHARED_SECRET: &[u8] = &[0x57];
const FIXTURE_ENCAPSULATION: [u8; 768] = [0x52; 768];
const RECIPIENT_PROTECTED: &[u8] = &[0x58, 0x59];
const SUPP_PRIVATE: &[u8] = &[0x59];
const WRAPPED_KEY: &[u8] = &[0x60];
const DERIVED_KEY: &[u8] = &[0x61];
const UNWRAPPED_KEY: &[u8] = &[0x62];
const PLAINTEXT: &[u8] = &[0x72, 0x73];

std::thread_local! {
    static REQUEST_KID_MATCHES: Cell<bool> = const { Cell::new(false) };
    static DERIVED_KID_MATCHES: Cell<bool> = const { Cell::new(false) };
    static KEY_WRAP: Cell<bool> = const { Cell::new(false) };
    static KDF_ACCEPTS: Cell<bool> = const { Cell::new(false) };
    static UNWRAP_ACCEPTS: Cell<bool> = const { Cell::new(false) };
    static CALLS: Cell<u8> = const { Cell::new(0) };
}

#[kani::proof]
#[kani::stub(
    zeroize::optimization_barrier,
    crate::zeroize_coset::barrier_verification::observe_barrier
)]
#[kani::unwind(36)]
#[kani::stub(reallyme_crypto::operations::constant_time::equal, compare_ids)]
#[kani::stub(super::derive_public_key_from_seed, derive_fixture_public_key)]
#[kani::stub(super::derive_kid_from_ml_kem_public_key, derive_fixture_kid)]
#[kani::stub(super::encapsulated_key, borrow_fixture_encapsulation)]
#[kani::stub(super::decapsulate, decapsulate_fixture)]
fn ml_kem_recipient_identity_requires_both_checks_before_decapsulation() {
    let request_matches: bool = kani::any();
    let seed_matches: bool = kani::any();
    let key_wrap: bool = kani::any();
    let seed = ManuallyDrop::new(Zeroizing::new(SEED));
    REQUEST_KID_MATCHES.set(request_matches);
    DERIVED_KID_MATCHES.set(seed_matches);
    CALLS.set(0);

    let Ok(suite) = fixture_suite(key_wrap) else {
        assert!(false, "the registered suite must be selected");
        return;
    };
    let mut expected = KID;
    if !request_matches {
        expected[0] ^= 1;
    }
    let recipient = ManuallyDrop::new(fixture_recipient(key_wrap));
    let result = decapsulate_for_recipient(&suite, &recipient, &expected, seed.as_slice());
    if !request_matches {
        assert!(CALLS.get() == 0);
        assert!(matches!(result, Err(CoseError::KidMismatch)));
    } else if !seed_matches {
        assert!(CALLS.get() == 2);
        assert!(matches!(result, Err(CoseError::KidMismatch)));
    } else {
        assert!(CALLS.get() == 3);
        assert!(matches!(result, Ok(secret) if secret.as_slice() == SHARED_SECRET));
    }
    kani::cover!(
        !request_matches,
        "an unexpected protected kid stops private key use"
    );
    kani::cover!(
        request_matches && !seed_matches,
        "a seed deriving another kid stops decapsulation"
    );
    kani::cover!(
        request_matches && seed_matches && key_wrap,
        "matching key-wrap identity reaches decapsulation"
    );
    kani::cover!(
        request_matches && seed_matches && !key_wrap,
        "matching direct identity reaches decapsulation"
    );
}

#[kani::proof]
#[kani::stub(
    zeroize::optimization_barrier,
    crate::zeroize_coset::barrier_verification::observe_barrier
)]
#[kani::unwind(14)]
#[kani::stub(super::encode_protected_header, encode_fixture_protected)]
#[kani::stub(super::derive_key, derive_fixture_key)]
#[kani::stub(super::unwrap_content_key, unwrap_fixture_key)]
fn ml_kem_recipient_content_key_requires_the_selected_kdf_and_unwrap() {
    let key_wrap: bool = kani::any();
    let kdf_accepts: bool = kani::any();
    let unwrap_accepts: bool = kani::any();
    KEY_WRAP.set(key_wrap);
    KDF_ACCEPTS.set(kdf_accepts);
    UNWRAP_ACCEPTS.set(unwrap_accepts);
    CALLS.set(0);
    let Ok(suite) = fixture_suite(key_wrap) else {
        assert!(false, "the registered suite must be selected");
        return;
    };
    let recipient = ManuallyDrop::new(fixture_recipient(key_wrap));
    let result =
        derive_recipient_content_key(&suite, &recipient, SHARED_SECRET, 3, 32, Some(SUPP_PRIVATE));
    assert!(CALLS.get() == if key_wrap && kdf_accepts { 2 } else { 1 });
    if !kdf_accepts {
        assert!(matches!(result, Err(CoseError::Crypto)));
    } else if key_wrap && !unwrap_accepts {
        assert!(matches!(result, Err(CoseError::KeyUnwrapFailed)));
    } else {
        let expected = if key_wrap { UNWRAPPED_KEY } else { DERIVED_KEY };
        assert!(matches!(result, Ok(key) if key.as_slice() == expected));
    }
    kani::cover!(!kdf_accepts, "KDF rejection prevents unwrap");
    kani::cover!(
        key_wrap && kdf_accepts && !unwrap_accepts,
        "unwrap integrity failure yields no key"
    );
    kani::cover!(
        key_wrap && kdf_accepts && unwrap_accepts,
        "key wrap yields the unwrapped content key"
    );
    kani::cover!(
        !key_wrap && kdf_accepts,
        "direct mode uses the derived content key"
    );
}

#[kani::proof]
#[kani::stub(
    zeroize::optimization_barrier,
    crate::zeroize_coset::barrier_verification::observe_barrier
)]
#[kani::unwind(12)]
fn ml_kem_plaintext_release_requires_key_establishment_and_aead_success() {
    let key_established: bool = kani::any();
    let authenticated: bool = kani::any();
    let called = Cell::new(false);
    let key = if key_established {
        Ok(Zeroizing::new(DERIVED_KEY.to_vec()))
    } else {
        Err(CoseError::KeyUnwrapFailed)
    };
    let result = authenticate_after_key_establishment(key, |actual_key| {
        assert!(actual_key == DERIVED_KEY);
        assert!(!called.replace(true));
        if authenticated {
            Ok(Zeroizing::new(PLAINTEXT.to_vec()))
        } else {
            Err(CoseError::AuthenticationFailed)
        }
    });
    assert!(called.get() == key_established);
    match (key_established, authenticated, result) {
        (false, _, Err(CoseError::KeyUnwrapFailed))
        | (true, false, Err(CoseError::AuthenticationFailed)) => {}
        (true, true, Ok(plaintext)) => {
            assert!(plaintext.as_slice() == PLAINTEXT);
        }
        _ => {
            assert!(
                false,
                "plaintext requires successful key establishment and authentication"
            );
        }
    }
    kani::cover!(
        !key_established,
        "failure to establish a key stops authentication"
    );
    kani::cover!(
        key_established && !authenticated,
        "a rejected tag yields no plaintext"
    );
    kani::cover!(
        key_established && authenticated,
        "AEAD plaintext reaches the caller"
    );
}

fn fixture_suite(key_wrap: bool) -> Result<MlKemSuite, CoseError> {
    suite_from_cose_algorithm(&RegisteredLabelWithPrivate::PrivateUse(if key_wrap {
        -65_540
    } else {
        -65_537
    }))
}

fn fixture_recipient(key_wrap: bool) -> CoseRecipient {
    CoseRecipient {
        protected: ProtectedHeader {
            original_data: Some(RECIPIENT_PROTECTED.to_vec()),
            header: coset::Header {
                key_id: KID.to_vec(),
                ..coset::Header::default()
            },
        },
        ciphertext: key_wrap.then(|| WRAPPED_KEY.to_vec()),
        ..CoseRecipient::default()
    }
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn compare_ids(left: &[u8], right: &[u8]) -> bool {
    assert!(left.len() == KID.len() && right.len() == KID.len());
    left.chunks_exact(8)
        .zip(right.chunks_exact(8))
        .all(|(a, b)| a == b)
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn derive_fixture_public_key(
    algorithm: CoseMlKemAlgorithm,
    seed: &[u8],
) -> Result<Vec<u8>, CoseError> {
    assert!(REQUEST_KID_MATCHES.get() && CALLS.replace(1) == 0);
    assert!(algorithm == CoseMlKemAlgorithm::MlKem512 && seed.len() == 64);
    assert!(seed.chunks_exact(8).all(|chunk| chunk == [0x43; 8]));
    Ok(PUBLIC.to_vec())
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn derive_fixture_kid(algorithm: Algorithm, public: &[u8]) -> Result<[u8; 32], CoseError> {
    assert!(CALLS.replace(2) == 1);
    assert!(algorithm == Algorithm::MlKem512 && public == PUBLIC);
    let mut kid = KID;
    if !DERIVED_KID_MATCHES.get() {
        kid[0] ^= 1;
    }
    Ok(kid)
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn borrow_fixture_encapsulation(_recipient: &CoseRecipient) -> Result<&[u8], CoseError> {
    assert!(CALLS.get() == 2 && DERIVED_KID_MATCHES.get());
    Ok(&FIXTURE_ENCAPSULATION)
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn decapsulate_fixture(
    algorithm: CoseMlKemAlgorithm,
    encapsulated: &[u8],
    seed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    assert!(CALLS.replace(3) == 2 && DERIVED_KID_MATCHES.get());
    assert!(algorithm == CoseMlKemAlgorithm::MlKem512);
    assert!(core::ptr::eq(
        encapsulated,
        FIXTURE_ENCAPSULATION.as_slice()
    ));
    assert!(seed.len() == SEED.len());
    Ok(Zeroizing::new(SHARED_SECRET.to_vec()))
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn encode_fixture_protected(header: &ProtectedHeader) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    assert!(header.original_data.as_deref() == Some(RECIPIENT_PROTECTED));
    Ok(Zeroizing::new(RECIPIENT_PROTECTED.to_vec()))
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn derive_fixture_key(
    secret: &[u8],
    algorithm: i64,
    output_len: usize,
    protected: &[u8],
    private: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    assert!(CALLS.replace(1) == 0);
    let (expected_alg, expected_len) = if KEY_WRAP.get() { (-3, 16) } else { (3, 32) };
    assert!(algorithm == expected_alg && output_len == expected_len);
    assert!(
        secret == SHARED_SECRET
            && protected == RECIPIENT_PROTECTED
            && private == Some(SUPP_PRIVATE)
    );
    if KDF_ACCEPTS.get() {
        Ok(Zeroizing::new(DERIVED_KEY.to_vec()))
    } else {
        Err(CoseError::Crypto)
    }
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn unwrap_fixture_key(
    suite: &MlKemSuite,
    key: &[u8],
    wrapped: &[u8],
    expected_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    assert!(CALLS.replace(2) == 1 && KDF_ACCEPTS.get() && KEY_WRAP.get());
    assert!(suite.mode == CoseMlKemMode::KeyWrap && suite.kem == CoseMlKemAlgorithm::MlKem512);
    assert!(key == DERIVED_KEY && wrapped == WRAPPED_KEY && expected_len == 32);
    if UNWRAP_ACCEPTS.get() {
        Ok(Zeroizing::new(UNWRAPPED_KEY.to_vec()))
    } else {
        Err(CoseError::KeyUnwrapFailed)
    }
}
