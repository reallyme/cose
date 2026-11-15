// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::ManuallyDrop;

use ciborium::Value;
use coset::{iana, CoseKeyBuilder, Label, RegisteredLabel, RegisteredLabelWithPrivate};
use zeroize::Zeroizing;

use super::ed25519_preimage::hash_ed25519_kid;
use crate::key::profile::{ED25519_PUBLIC_KEY_BYTES, ED25519_SECRET_KEY_BYTES};
use crate::CoseError;

// A deterministic COSE_Key map of kty: OKP, alg: Ed25519 (-19),
// crv: Ed25519 (6), and x: bstr(32), in label order 1, 3, -1, -2.
const PUBLIC_MAP_PREFIX: &[u8] = b"\xa4\x01\x01\x03\x32\x20\x06\x21\x58\x20";

#[derive(Clone, Copy)]
struct ExpectedPublicMap {
    offset: usize,
    byte: u8,
    include_seed: bool,
    explicit_algorithm: bool,
    distinct_seed: bool,
}

std::thread_local! {
    static EXPECTED_MAP: Cell<Option<ExpectedPublicMap>> = const { Cell::new(None) };
}

#[kani::proof]
#[kani::unwind(18)]
#[kani::stub(super::sha2_256_content_hash, observe_public_map)]
fn ed25519_kid_hashes_only_the_canonical_public_map() {
    let x: [u8; ED25519_PUBLIC_KEY_BYTES] = kani::any();
    let seed = ManuallyDrop::new(Zeroizing::new(kani::any::<[u8; ED25519_SECRET_KEY_BYTES]>()));
    let include_seed: bool = kani::any();
    let explicit_algorithm: bool = kani::any();
    let mut params = Vec::with_capacity(3);
    params.push((Label::Int(-1), Value::Integer(6.into())));
    if include_seed {
        params.push((Label::Int(-4), Value::Bytes(seed.to_vec())));
    }
    params.push((Label::Int(-2), Value::Bytes(x.to_vec())));
    // Isolate derivation from recursive CBOR teardown for synthetic fixtures.
    let key = ManuallyDrop::new(coset::CoseKey {
        kty: RegisteredLabel::Assigned(iana::KeyType::OKP),
        alg: explicit_algorithm.then_some(RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::Ed25519,
        )),
        key_id: vec![kani::any()],
        params,
        ..coset::CoseKey::default()
    });

    // An arbitrary in-range offset checks every byte of the symbolic x.
    let offset = usize::from(kani::any::<u8>());
    kani::assume(offset < x.len());
    EXPECTED_MAP.set(Some(ExpectedPublicMap {
        offset,
        byte: x[offset],
        include_seed,
        explicit_algorithm,
        distinct_seed: seed[0] != x[0],
    }));
    let _result = hash_ed25519_kid(&key);
    assert!(false, "a valid Ed25519 key must reach the hash observation");
}

#[kani::proof]
#[kani::unwind(18)]
#[kani::stub(super::sha2_256_content_hash, unexpected_hash)]
fn ed25519_kid_seed_cannot_substitute_for_missing_public_bytes() {
    let seed = ManuallyDrop::new(Zeroizing::new(kani::any::<[u8; ED25519_SECRET_KEY_BYTES]>()));
    let key = ManuallyDrop::new(
        CoseKeyBuilder::new_okp_key()
            .algorithm(iana::Algorithm::Ed25519)
            .param(-1, Value::Integer(6.into()))
            .param(-4, Value::Bytes(seed.to_vec()))
            .build(),
    );
    let result = hash_ed25519_kid(&key);
    assert!(matches!(result, Err(CoseError::MissingKeyMaterial)));
    kani::cover!(
        result.is_err(),
        "the seed-only fixture is rejected before the hash"
    );
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn unexpected_hash(_bytes: &[u8]) -> [u8; ED25519_PUBLIC_KEY_BYTES] {
    assert!(false, "a seed-only key cannot reach SHA-256");
    [0; ED25519_PUBLIC_KEY_BYTES]
}

// Observe the production preimage byte for byte at SHA-256. End the
// successful execution at this boundary, where the property is decided.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn observe_public_map(bytes: &[u8]) -> [u8; ED25519_PUBLIC_KEY_BYTES] {
    let Some(expected) = EXPECTED_MAP.get() else {
        assert!(false, "SHA-256 must receive an Ed25519 public map");
        return [0; ED25519_PUBLIC_KEY_BYTES];
    };
    let Some(public) = bytes.strip_prefix(PUBLIC_MAP_PREFIX) else {
        assert!(
            false,
            "the hash must receive the canonical Ed25519 public map"
        );
        return [0; ED25519_PUBLIC_KEY_BYTES];
    };
    assert!(public.len() == ED25519_PUBLIC_KEY_BYTES);
    assert!(public.get(expected.offset) == Some(&expected.byte));
    kani::cover!(
        expected.include_seed && expected.explicit_algorithm && expected.distinct_seed,
        "an explicit Ed25519 private key with distinct x and d reaches the hash"
    );
    kani::cover!(
        !expected.include_seed && expected.explicit_algorithm,
        "an explicit public key reaches the hash"
    );
    kani::cover!(
        expected.include_seed && !expected.explicit_algorithm,
        "a private key with omitted alg reaches the hash"
    );
    kani::cover!(
        !expected.include_seed && !expected.explicit_algorithm,
        "a public key with omitted alg reaches the hash"
    );
    kani::assume(false);
    [0; ED25519_PUBLIC_KEY_BYTES]
}
