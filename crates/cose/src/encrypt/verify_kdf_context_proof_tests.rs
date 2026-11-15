// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::ManuallyDrop;

use ciborium::Value;
use reallyme_crypto::core::CryptoError;
use reallyme_crypto::kmac::{Kmac256Key, Kmac256Output};
use zeroize::Zeroizing;

use super::{build_kdf_context, derive_key};
use crate::CoseError;

#[kani::proof]
#[kani::unwind(16)]
fn ml_kem_kdf_context_preserves_the_exact_fields() {
    let algorithm: i64 = kani::any();
    let output_len: usize = kani::any();
    let protected: [u8; 3] = kani::any();
    let private: [u8; 3] = kani::any();
    let protected_len = usize::from(kani::any::<u8>());
    let private_len = usize::from(kani::any::<u8>());
    kani::assume(protected_len <= protected.len() && private_len <= private.len());
    let include_private: bool = kani::any();
    let protected = &protected[..protected_len];
    let private = include_private.then_some(&private[..private_len]);

    // Wide arithmetic is independent of the production checked usize
    // multiply and covers every machine-sized byte length.
    let Ok(wide_len) = u128::try_from(output_len) else {
        assert!(false, "a machine-sized length must fit in u128");
        return;
    };
    let Ok(max_usize) = u128::try_from(usize::MAX) else {
        assert!(false, "usize::MAX must fit in u128");
        return;
    };
    let wide_bits = wide_len * 8;
    let width_overflow = wide_bits > max_usize || wide_bits > u128::from(u64::MAX);
    // Recursive teardown of the synthetic CBOR value is outside the check.
    let result = ManuallyDrop::new(build_kdf_context(algorithm, output_len, protected, private));
    if width_overflow {
        assert!(matches!(&*result, Err(CoseError::ResourceLimitExceeded)));
        kani::cover!(
            output_len == usize::MAX,
            "an overflowing bit length is rejected"
        );
        return;
    }

    let Ok(Value::Array(fields)) = &*result else {
        assert!(false, "the context must be a definite array");
        return;
    };
    let (algorithm_value, public_info, private_info) = match fields.as_slice() {
        [algorithm, public] => (algorithm, public, None),
        [algorithm, public, private] => (algorithm, public, Some(private)),
        _ => {
            assert!(false, "the context must have two or three fields");
            return;
        }
    };
    assert!(algorithm_value.as_integer().map(i128::from) == Some(i128::from(algorithm)));
    let Value::Array(public_info) = public_info else {
        assert!(false, "SuppPubInfo must be an array");
        return;
    };
    let [bits, header] = public_info.as_slice() else {
        assert!(
            false,
            "SuppPubInfo must contain only the bit length and protected header"
        );
        return;
    };
    assert!(
        bits.as_integer()
            .and_then(|value| u128::try_from(value).ok())
            == Some(wide_bits)
    );
    assert!(header.as_bytes().map(Vec::as_slice) == Some(protected));
    match (private_info, private) {
        (None, None) => {}
        (Some(actual), Some(expected)) => {
            assert!(actual.as_bytes().map(Vec::as_slice) == Some(expected));
        }
        _ => {
            assert!(false, "SuppPrivInfo presence must be retained");
        }
    }
    kani::cover!(
        algorithm == 1 && output_len == 16 && !include_private,
        "GCM without SuppPrivInfo"
    );
    kani::cover!(
        algorithm == -4 && output_len == 24 && private == Some(&[]),
        "AES-KW with present empty SuppPrivInfo"
    );
    kani::cover!(
        protected_len == 3 && private.is_some_and(|bytes| bytes.len() == 3 && bytes != protected),
        "distinct symbolic byte strings"
    );
}

const SHARED_SECRET: [u8; 32] = [0x35; 32];

#[derive(Clone, Copy)]
struct ExpectedKmac {
    context: [u8; 9],
    context_len: usize,
    output_len: usize,
}

std::thread_local! {
    static EXPECTED_KMAC: Cell<Option<ExpectedKmac>> = const { Cell::new(None) };
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(crate::encode_cbor::encode_cbor_value, encode_fixture_context)]
#[kani::stub(super::derive_kmac256, observe_kmac)]
fn ml_kem_kdf_context_reaches_kmac_with_exact_output_length() {
    let key_wrap: bool = kani::any();
    let include_private: bool = kani::any();
    let header_byte: u8 = kani::any();
    let private_byte: u8 = kani::any();
    let secret = ManuallyDrop::new(Zeroizing::new(SHARED_SECRET));
    let (algorithm, output_len, alg_cbor, bits) = if key_wrap {
        (-4, 24, 0x23, 0xc0)
    } else {
        (1, 16, 0x01, 0x80)
    };
    let context = [
        if include_private { 0x83 } else { 0x82 },
        alg_cbor,
        0x82,
        0x18,
        bits,
        0x41,
        header_byte,
        0x41,
        private_byte,
    ];
    EXPECTED_KMAC.set(Some(ExpectedKmac {
        context,
        context_len: if include_private { 9 } else { 7 },
        output_len,
    }));
    let private = [private_byte];
    let _result = derive_key(
        secret.as_slice(),
        algorithm,
        output_len,
        &[header_byte],
        include_private.then_some(private.as_slice()),
    );
    assert!(false, "the valid context must reach KMAC");
}

// Model CBOR serialization for two profile contexts. Return their exact
// byte layout based on the fields supplied by the real context builder.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn encode_fixture_context(value: Value) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let value = ManuallyDrop::new(value);
    let items = value.as_array().ok_or(CoseError::InvalidFormat)?;
    let (algorithm, public, private) = match items.as_slice() {
        [algorithm, public] => (algorithm, public, None),
        [algorithm, public, private] => (algorithm, public, Some(private)),
        _ => return Err(CoseError::InvalidFormat),
    };
    let fields = public.as_array().ok_or(CoseError::InvalidFormat)?;
    let [bits, header] = fields.as_slice() else {
        return Err(CoseError::InvalidFormat);
    };
    let alg = match algorithm.as_integer().map(i128::from) {
        Some(1) => 0x01,
        Some(-4) => 0x23,
        _ => return Err(CoseError::UnsupportedAlgorithm),
    };
    let bits = match bits.as_integer().map(i128::from) {
        Some(128) => 0x80,
        Some(192) => 0xc0,
        _ => return Err(CoseError::InvalidFormat),
    };
    let header = fixture_byte(header)?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(9));
    encoded.extend_from_slice(&[0x82, alg, 0x82, 0x18, bits, 0x41, header]);
    if let Some(private) = private {
        encoded[0] = 0x83;
        encoded.extend_from_slice(&[0x41, fixture_byte(private)?]);
    }
    Ok(encoded)
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn fixture_byte(value: &Value) -> Result<u8, CoseError> {
    match value.as_bytes().map(Vec::as_slice) {
        Some([byte]) => Ok(*byte),
        _ => Err(CoseError::InvalidFormat),
    }
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn observe_kmac(
    key: &Kmac256Key,
    context: &[u8],
    customization: &[u8],
    output_len: usize,
) -> Result<Kmac256Output, CryptoError> {
    assert!(key.as_bytes().len() == SHARED_SECRET.len());
    assert!(key
        .as_bytes()
        .chunks_exact(8)
        .all(|chunk| chunk == [0x35; 8]));
    assert!(customization.is_empty());
    assert!(EXPECTED_KMAC
        .get()
        .is_some_and(|expected| output_len == expected.output_len
            && context == &expected.context[..expected.context_len]));
    kani::cover!(
        output_len == 16 && context.len() == 7,
        "direct KDF reaches KMAC"
    );
    kani::cover!(
        output_len == 24 && context.len() == 9,
        "key-wrap KDF with private information reaches KMAC"
    );
    kani::assume(false);
    Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
}
