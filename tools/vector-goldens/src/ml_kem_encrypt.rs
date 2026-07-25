// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Deterministic maintenance generator for the ReallyMe ML-KEM COSE profile.
//!
//! Production encryption deliberately obtains ML-KEM randomness, CEKs, and
//! nonces from the operating-system CSPRNG. This unpublished tool supplies
//! fixed inputs only so the committed wire fixtures can be regenerated
//! byte-for-byte and audited by an implementation that does not link COSE.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes192;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use aes_kw::{KwAes128, KwAes192, KwAes256};
use ciborium::value::Value;
use ml_kem::kem::KeyExport;
use ml_kem::{Seed, B32};
use reallyme_cose::{
    cose_key_from_public_bytes, derive_kid_from_cose_key_public, Algorithm,
    REALLYME_COSE_ALG_ML_KEM_1024, REALLYME_COSE_ALG_ML_KEM_1024_A256KW,
    REALLYME_COSE_ALG_ML_KEM_512, REALLYME_COSE_ALG_ML_KEM_512_A128KW,
    REALLYME_COSE_ALG_ML_KEM_768, REALLYME_COSE_ALG_ML_KEM_768_A192KW, REALLYME_COSE_HEADER_EK,
};
use serde::Serialize;
use sha3_kmac::Kmac256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const VECTOR_PATH: &str = "vectors/cose-encrypt-ml-kem.json";
const COSE_ENCRYPT_TAG: u64 = 96;
const COSE_HEADER_ALGORITHM: i64 = 1;
const COSE_HEADER_KID: i64 = 4;
const COSE_HEADER_IV: i64 = 5;
const AES_GCM_A128: i64 = 1;
const AES_GCM_A192: i64 = 2;
const AES_GCM_A256: i64 = 3;
const AES_KW_A128: i64 = -3;
const AES_KW_A192: i64 = -4;
const AES_KW_A256: i64 = -5;
const AES_KW_OVERHEAD: usize = 8;
const BITS_PER_BYTE: usize = 8;

type Aes192Gcm = AesGcm<Aes192, U12>;

#[derive(Debug, Error)]
pub(super) enum GenerateError {
    #[error("ML-KEM vector parameter is invalid")]
    InvalidParameter,
    #[error("ML-KEM vector arithmetic overflowed")]
    LengthOverflow,
    #[error("ML-KEM vector cryptography failed")]
    Crypto,
    #[error("ML-KEM vector CBOR encoding failed")]
    Cbor,
    #[error("ML-KEM vector JSON encoding failed")]
    Json,
    #[error("ML-KEM vector file could not be written")]
    Write,
}

#[derive(Serialize)]
struct Suite {
    schema: &'static str,
    suite: &'static str,
    note: &'static str,
    cases: Vec<Case>,
}

#[derive(Serialize)]
struct Case {
    id: String,
    kem_algorithm: &'static str,
    mode: &'static str,
    content_algorithm: &'static str,
    private_key_seed_hex: String,
    public_key_hex: String,
    recipient_kid_hex: String,
    encapsulation_randomness_hex: String,
    iv_hex: String,
    cek_hex: String,
    plaintext_hex: String,
    external_aad_hex: String,
    supp_priv_info_hex: String,
    cose_encrypt_hex: String,
}

#[derive(Clone, Copy)]
enum Kem {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl Kem {
    const fn name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    const fn algorithm(self) -> Algorithm {
        match self {
            Self::MlKem512 => Algorithm::MlKem512,
            Self::MlKem768 => Algorithm::MlKem768,
            Self::MlKem1024 => Algorithm::MlKem1024,
        }
    }

    const fn direct_algorithm(self) -> i64 {
        match self {
            Self::MlKem512 => REALLYME_COSE_ALG_ML_KEM_512,
            Self::MlKem768 => REALLYME_COSE_ALG_ML_KEM_768,
            Self::MlKem1024 => REALLYME_COSE_ALG_ML_KEM_1024,
        }
    }

    const fn wrapped_algorithm(self) -> i64 {
        match self {
            Self::MlKem512 => REALLYME_COSE_ALG_ML_KEM_512_A128KW,
            Self::MlKem768 => REALLYME_COSE_ALG_ML_KEM_768_A192KW,
            Self::MlKem1024 => REALLYME_COSE_ALG_ML_KEM_1024_A256KW,
        }
    }

    const fn key_wrap_algorithm(self) -> i64 {
        match self {
            Self::MlKem512 => AES_KW_A128,
            Self::MlKem768 => AES_KW_A192,
            Self::MlKem1024 => AES_KW_A256,
        }
    }

    const fn key_length(self) -> usize {
        match self {
            Self::MlKem512 => 16,
            Self::MlKem768 => 24,
            Self::MlKem1024 => 32,
        }
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Direct,
    KeyWrap,
}

struct EncapsulationOutput {
    public_key: Vec<u8>,
    ciphertext: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::KeyWrap => "key_wrap",
        }
    }
}

pub(super) fn regenerate() -> Result<(), GenerateError> {
    let mut cases = Vec::with_capacity(6);
    for kem in [Kem::MlKem512, Kem::MlKem768, Kem::MlKem1024] {
        cases.push(generate_case(kem, Mode::Direct)?);
        cases.push(generate_case(kem, Mode::KeyWrap)?);
    }

    let suite = Suite {
        schema: "reallyme.cose.ml_kem_encrypt.vectors.v1",
        suite: "cose-encrypt-ml-kem",
        note: "Deterministic maintenance fixtures for the ReallyMe pre-IANA COSE ML-KEM profile. Fixed private seeds, encapsulation randomness, CEKs, and nonces are test data only and MUST NOT be used as production key-generation examples.",
        cases,
    };
    let mut output = serde_json::to_vec_pretty(&suite).map_err(|_| GenerateError::Json)?;
    output.push(b'\n');
    fs::write(repository_root().join(VECTOR_PATH), output).map_err(|_| GenerateError::Write)
}

fn generate_case(kem: Kem, mode: Mode) -> Result<Case, GenerateError> {
    let marker = match kem {
        Kem::MlKem512 => 0x51,
        Kem::MlKem768 => 0x76,
        Kem::MlKem1024 => 0xA1,
    };
    let seed = patterned::<64>(marker);
    let randomness = patterned::<32>(marker.wrapping_add(1));
    let iv = patterned::<12>(marker.wrapping_add(2));
    let plaintext = format!(
        "ReallyMe deterministic {} {} COSE vector",
        kem.name(),
        mode.name()
    )
    .into_bytes();
    let external_aad = format!("ReallyMe {} external AAD", kem.name()).into_bytes();
    let supp_priv_info = format!("ReallyMe {} private KDF context", kem.name()).into_bytes();
    let mut encapsulation = deterministic_encapsulation(kem, &seed, &randomness)?;

    let public_cose_key = cose_key_from_public_bytes(kem.algorithm(), &encapsulation.public_key)
        .map_err(|_| GenerateError::Crypto)?;
    let kid =
        derive_kid_from_cose_key_public(&public_cose_key).map_err(|_| GenerateError::Crypto)?;

    let recipient_algorithm = match mode {
        Mode::Direct => kem.direct_algorithm(),
        Mode::KeyWrap => kem.wrapped_algorithm(),
    };
    let recipient_protected = encode_cbor(&Value::Map(vec![
        (
            Value::Integer(COSE_HEADER_ALGORITHM.into()),
            Value::Integer(recipient_algorithm.into()),
        ),
        (
            Value::Integer(COSE_HEADER_KID.into()),
            Value::Bytes(kid.to_vec()),
        ),
    ]))?;
    let content_algorithm = content_algorithm(kem);
    let content_key_length = kem.key_length();
    let mut cek = Zeroizing::new(Vec::new());
    let (content_key, recipient_ciphertext) = match mode {
        Mode::Direct => (
            derive_key(
                &encapsulation.shared_secret,
                content_algorithm,
                content_key_length,
                &recipient_protected,
                &supp_priv_info,
            )?,
            Value::Null,
        ),
        Mode::KeyWrap => {
            let kek = derive_key(
                &encapsulation.shared_secret,
                kem.key_wrap_algorithm(),
                kem.key_length(),
                &recipient_protected,
                &supp_priv_info,
            )?;
            *cek = patterned_vec(content_key_length, marker.wrapping_add(3));
            let wrapped = wrap_key(kem, &kek, &cek)?;
            (Zeroizing::new(cek.to_vec()), Value::Bytes(wrapped))
        }
    };
    encapsulation.shared_secret.zeroize();

    let body_protected = encode_cbor(&Value::Map(vec![(
        Value::Integer(COSE_HEADER_ALGORITHM.into()),
        Value::Integer(content_algorithm.into()),
    )]))?;
    let enc_structure = encode_cbor(&Value::Array(vec![
        Value::Text("Encrypt".to_owned()),
        Value::Bytes(body_protected.clone()),
        Value::Bytes(external_aad.clone()),
    ]))?;
    let ciphertext = encrypt_content(kem, &content_key, &iv, &enc_structure, &plaintext)?;

    let cose_encrypt = encode_cbor(&Value::Tag(
        COSE_ENCRYPT_TAG,
        Box::new(Value::Array(vec![
            Value::Bytes(body_protected),
            Value::Map(vec![(
                Value::Integer(COSE_HEADER_IV.into()),
                Value::Bytes(iv.to_vec()),
            )]),
            Value::Bytes(ciphertext),
            Value::Array(vec![Value::Array(vec![
                Value::Bytes(recipient_protected),
                Value::Map(vec![(
                    Value::Integer(REALLYME_COSE_HEADER_EK.into()),
                    Value::Bytes(encapsulation.ciphertext),
                )]),
                recipient_ciphertext,
            ])]),
        ])),
    ))?;

    Ok(Case {
        id: format!(
            "cose-encrypt-{}-{}",
            kem.name().to_ascii_lowercase(),
            mode.name()
        ),
        kem_algorithm: kem.name(),
        mode: mode.name(),
        content_algorithm: content_algorithm_name(kem),
        private_key_seed_hex: hex::encode(seed),
        public_key_hex: hex::encode(encapsulation.public_key),
        recipient_kid_hex: hex::encode(kid),
        encapsulation_randomness_hex: hex::encode(randomness),
        iv_hex: hex::encode(iv),
        cek_hex: hex::encode(cek.as_slice()),
        plaintext_hex: hex::encode(plaintext),
        external_aad_hex: hex::encode(external_aad),
        supp_priv_info_hex: hex::encode(supp_priv_info),
        cose_encrypt_hex: hex::encode(cose_encrypt),
    })
}

fn deterministic_encapsulation(
    kem: Kem,
    seed: &[u8; 64],
    randomness: &[u8; 32],
) -> Result<EncapsulationOutput, GenerateError> {
    let seed = Seed::try_from(seed.as_slice()).map_err(|_| GenerateError::InvalidParameter)?;
    let message =
        B32::try_from(randomness.as_slice()).map_err(|_| GenerateError::InvalidParameter)?;
    match kem {
        Kem::MlKem512 => {
            let private = ml_kem::ml_kem_512::DecapsulationKey::from_seed(seed);
            let public = private.encapsulation_key();
            let (ciphertext, mut shared) = public.encapsulate_deterministic(&message);
            let output = EncapsulationOutput {
                public_key: public.to_bytes().to_vec(),
                ciphertext: ciphertext.to_vec(),
                shared_secret: Zeroizing::new(shared.to_vec()),
            };
            shared.zeroize();
            Ok(output)
        }
        Kem::MlKem768 => {
            let private = ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed);
            let public = private.encapsulation_key();
            let (ciphertext, mut shared) = public.encapsulate_deterministic(&message);
            let output = EncapsulationOutput {
                public_key: public.to_bytes().to_vec(),
                ciphertext: ciphertext.to_vec(),
                shared_secret: Zeroizing::new(shared.to_vec()),
            };
            shared.zeroize();
            Ok(output)
        }
        Kem::MlKem1024 => {
            let private = ml_kem::ml_kem_1024::DecapsulationKey::from_seed(seed);
            let public = private.encapsulation_key();
            let (ciphertext, mut shared) = public.encapsulate_deterministic(&message);
            let output = EncapsulationOutput {
                public_key: public.to_bytes().to_vec(),
                ciphertext: ciphertext.to_vec(),
                shared_secret: Zeroizing::new(shared.to_vec()),
            };
            shared.zeroize();
            Ok(output)
        }
    }
}

fn derive_key(
    shared_secret: &[u8],
    algorithm: i64,
    output_length: usize,
    recipient_protected: &[u8],
    supp_priv_info: &[u8],
) -> Result<Zeroizing<Vec<u8>>, GenerateError> {
    let output_bits = output_length
        .checked_mul(BITS_PER_BYTE)
        .ok_or(GenerateError::LengthOverflow)?;
    let output_bits = u64::try_from(output_bits).map_err(|_| GenerateError::LengthOverflow)?;
    let context = encode_cbor(&Value::Array(vec![
        Value::Integer(algorithm.into()),
        Value::Array(vec![
            Value::Integer(output_bits.into()),
            Value::Bytes(recipient_protected.to_vec()),
        ]),
        Value::Bytes(supp_priv_info.to_vec()),
    ]))?;
    let mut kmac = Kmac256::new(shared_secret, &[]).map_err(|_| GenerateError::Crypto)?;
    kmac.update(&context);
    let mut output = Zeroizing::new(vec![0_u8; output_length]);
    kmac.finalize_into(&mut output);
    Ok(output)
}

fn wrap_key(kem: Kem, kek: &[u8], cek: &[u8]) -> Result<Vec<u8>, GenerateError> {
    let output_length = cek
        .len()
        .checked_add(AES_KW_OVERHEAD)
        .ok_or(GenerateError::LengthOverflow)?;
    let mut output = vec![0_u8; output_length];
    let wrapped = match kem {
        Kem::MlKem512 => KwAes128::new_from_slice(kek)
            .map_err(|_| GenerateError::Crypto)?
            .wrap_key(cek, &mut output),
        Kem::MlKem768 => KwAes192::new_from_slice(kek)
            .map_err(|_| GenerateError::Crypto)?
            .wrap_key(cek, &mut output),
        Kem::MlKem1024 => KwAes256::new_from_slice(kek)
            .map_err(|_| GenerateError::Crypto)?
            .wrap_key(cek, &mut output),
    }
    .map_err(|_| GenerateError::Crypto)?;
    Ok(wrapped.to_vec())
}

fn encrypt_content(
    kem: Kem,
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, GenerateError> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match kem {
        Kem::MlKem512 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| GenerateError::Crypto)?
            .encrypt(iv.into(), payload),
        Kem::MlKem768 => Aes192Gcm::new_from_slice(key)
            .map_err(|_| GenerateError::Crypto)?
            .encrypt(iv.into(), payload),
        Kem::MlKem1024 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| GenerateError::Crypto)?
            .encrypt(iv.into(), payload),
    }
    .map_err(|_| GenerateError::Crypto)
}

const fn content_algorithm(kem: Kem) -> i64 {
    match kem {
        Kem::MlKem512 => AES_GCM_A128,
        Kem::MlKem768 => AES_GCM_A192,
        Kem::MlKem1024 => AES_GCM_A256,
    }
}

const fn content_algorithm_name(kem: Kem) -> &'static str {
    match kem {
        Kem::MlKem512 => "A128GCM",
        Kem::MlKem768 => "A192GCM",
        Kem::MlKem1024 => "A256GCM",
    }
}

fn patterned<const N: usize>(marker: u8) -> [u8; N] {
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = u8::try_from(index % 251).unwrap_or(0);
        *byte = marker.wrapping_add(offset);
    }
    bytes
}

fn patterned_vec(length: usize, marker: u8) -> Vec<u8> {
    (0..length)
        .map(|index| marker.wrapping_add(u8::try_from(index % 251).unwrap_or(0)))
        .collect()
}

fn encode_cbor(value: &Value) -> Result<Vec<u8>, GenerateError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, Cursor::new(&mut bytes)).map_err(|_| GenerateError::Cbor)?;
    Ok(bytes)
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
