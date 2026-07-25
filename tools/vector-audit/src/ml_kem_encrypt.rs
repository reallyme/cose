// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Independent consumer for committed ReallyMe ML-KEM `COSE_Encrypt` vectors.
//!
//! This module parses the CBOR structure directly, recomputes the AKP key
//! binding, repeats deterministic encapsulation and decapsulation with the
//! upstream ML-KEM crate, derives KMAC256 output, performs RFC 3394 unwrap when
//! required, and authenticates AES-GCM without linking `reallyme-cose`,
//! `reallyme-crypto`, or `reallyme-codec`.

use std::collections::HashSet;
use std::io::Cursor;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes192;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use aes_kw::{KwAes128, KwAes192, KwAes256};
use ciborium::value::Value;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{Seed, B32};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha3_kmac::Kmac256;
use zeroize::{Zeroize, Zeroizing};

use super::{
    attach_case, audit_unique_id, encode_cbor, ensure, general, integer_matches, map_get,
    AuditReason, AuditResult,
};

const COSE_ENCRYPT_TAG: u64 = 96;
const COSE_KEY_TYPE_AKP: i64 = 7;
const COSE_HEADER_ALGORITHM: i64 = 1;
const COSE_HEADER_KID: i64 = 4;
const COSE_HEADER_IV: i64 = 5;
const REALLYME_HEADER_EK: i64 = -65_543;
const AES_GCM_TAG_BYTES: usize = 16;
const AES_KW_OVERHEAD: usize = 8;
const BITS_PER_BYTE: usize = 8;

type Aes192Gcm = AesGcm<Aes192, U12>;

#[derive(Debug, Deserialize)]
pub(super) struct Suite {
    pub(super) cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Case {
    id: String,
    kem_algorithm: String,
    mode: String,
    content_algorithm: String,
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
    fn parse(value: &str) -> AuditResult<Self> {
        match value {
            "ML-KEM-512" => Ok(Self::MlKem512),
            "ML-KEM-768" => Ok(Self::MlKem768),
            "ML-KEM-1024" => Ok(Self::MlKem1024),
            _ => Err(general(AuditReason::UnsupportedAlgorithm)),
        }
    }

    const fn direct_algorithm(self) -> i64 {
        match self {
            Self::MlKem512 => -65_537,
            Self::MlKem768 => -65_538,
            Self::MlKem1024 => -65_539,
        }
    }

    const fn wrapped_algorithm(self) -> i64 {
        match self {
            Self::MlKem512 => -65_540,
            Self::MlKem768 => -65_541,
            Self::MlKem1024 => -65_542,
        }
    }

    const fn key_wrap_algorithm(self) -> i64 {
        match self {
            Self::MlKem512 => -3,
            Self::MlKem768 => -4,
            Self::MlKem1024 => -5,
        }
    }

    const fn content_algorithm(self) -> i64 {
        match self {
            Self::MlKem512 => 1,
            Self::MlKem768 => 2,
            Self::MlKem1024 => 3,
        }
    }

    const fn content_algorithm_name(self) -> &'static str {
        match self {
            Self::MlKem512 => "A128GCM",
            Self::MlKem768 => "A192GCM",
            Self::MlKem1024 => "A256GCM",
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

impl Mode {
    fn parse(value: &str) -> AuditResult<Self> {
        match value {
            "direct" => Ok(Self::Direct),
            "key_wrap" => Ok(Self::KeyWrap),
            _ => Err(general(AuditReason::InvalidKemMode)),
        }
    }
}

struct ParsedEncrypt {
    body_protected: Vec<u8>,
    recipient_protected: Vec<u8>,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    encapsulated_key: Vec<u8>,
    recipient_ciphertext: Option<Vec<u8>>,
}

struct EncapsulationOutput {
    public_key: Vec<u8>,
    ciphertext: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
}

pub(super) fn audit_suite(suite: &Suite, ids: &mut HashSet<String>) -> AuditResult<()> {
    for case in &suite.cases {
        audit_unique_id(ids, &case.id)?;
        audit_case(case).map_err(|error| attach_case(error, &case.id))?;
    }
    Ok(())
}

fn audit_case(case: &Case) -> AuditResult<()> {
    let kem = Kem::parse(&case.kem_algorithm)?;
    let mode = Mode::parse(&case.mode)?;
    ensure(
        case.content_algorithm == kem.content_algorithm_name(),
        AuditReason::KemAlgorithmMismatch,
    )?;

    let seed = decode_hex(&case.private_key_seed_hex)?;
    let public_key = decode_hex(&case.public_key_hex)?;
    let expected_kid = decode_hex(&case.recipient_kid_hex)?;
    let randomness = decode_hex(&case.encapsulation_randomness_hex)?;
    let expected_iv = decode_hex(&case.iv_hex)?;
    let expected_cek = decode_hex(&case.cek_hex)?;
    let expected_plaintext = decode_hex(&case.plaintext_hex)?;
    let external_aad = decode_hex(&case.external_aad_hex)?;
    let supp_priv_info = decode_hex(&case.supp_priv_info_hex)?;
    let encoded = decode_hex(&case.cose_encrypt_hex)?;

    let parsed = parse_encrypt(&encoded, kem, mode, &expected_kid)?;
    ensure(
        parsed.iv == expected_iv,
        AuditReason::EncryptUnprotectedHeader,
    )?;
    ensure(
        parsed.ciphertext.len() >= AES_GCM_TAG_BYTES,
        AuditReason::EncryptShape,
    )?;

    let seed = fixed::<64>(&seed)?;
    let randomness = fixed::<32>(&randomness)?;
    let mut deterministic = deterministic_encapsulation(kem, &seed, &randomness)?;
    ensure(
        deterministic.public_key == public_key
            && deterministic.ciphertext == parsed.encapsulated_key,
        AuditReason::KemDeterministicMismatch,
    )?;
    let mut decapsulated = decapsulate(kem, &seed, &parsed.encapsulated_key)?;
    ensure(
        deterministic.shared_secret.as_slice() == decapsulated.as_slice(),
        AuditReason::KemDecapsulationMismatch,
    )?;
    deterministic.shared_secret.zeroize();

    let derived_kid = derive_kid(kem, &public_key)?;
    ensure(derived_kid == expected_kid, AuditReason::KemKidMismatch)?;

    let content_key = match mode {
        Mode::Direct => {
            ensure(expected_cek.is_empty(), AuditReason::KemAlgorithmMismatch)?;
            ensure(
                parsed.recipient_ciphertext.is_none(),
                AuditReason::RecipientShape,
            )?;
            derive_key(
                &decapsulated,
                kem.content_algorithm(),
                kem.key_length(),
                &parsed.recipient_protected,
                &supp_priv_info,
            )?
        }
        Mode::KeyWrap => {
            let wrapped = parsed
                .recipient_ciphertext
                .as_deref()
                .ok_or_else(|| general(AuditReason::RecipientShape))?;
            let kek = derive_key(
                &decapsulated,
                kem.key_wrap_algorithm(),
                kem.key_length(),
                &parsed.recipient_protected,
                &supp_priv_info,
            )?;
            let unwrapped = unwrap_key(kem, &kek, wrapped)?;
            ensure(
                unwrapped.as_slice() == expected_cek,
                AuditReason::KemKeyWrap,
            )?;
            unwrapped
        }
    };
    decapsulated.zeroize();

    let enc_structure = encode_cbor(&Value::Array(vec![
        Value::Text("Encrypt".to_owned()),
        Value::Bytes(parsed.body_protected),
        Value::Bytes(external_aad),
    ]))?;
    let plaintext = decrypt_content(
        kem,
        &content_key,
        &parsed.iv,
        &enc_structure,
        &parsed.ciphertext,
    )?;
    ensure(
        plaintext.as_slice() == expected_plaintext,
        AuditReason::EncryptPlaintextMismatch,
    )
}

fn parse_encrypt(
    encoded: &[u8],
    kem: Kem,
    mode: Mode,
    expected_kid: &[u8],
) -> AuditResult<ParsedEncrypt> {
    let root: Value = ciborium::de::from_reader(Cursor::new(encoded))
        .map_err(|_| general(AuditReason::CborDecode))?;
    ensure(
        encode_cbor(&root)?.as_slice() == encoded,
        AuditReason::EncryptShape,
    )?;
    let array = match root {
        Value::Tag(COSE_ENCRYPT_TAG, value) => match *value {
            Value::Array(array) => array,
            _ => return Err(general(AuditReason::EncryptShape)),
        },
        _ => return Err(general(AuditReason::EncryptShape)),
    };
    ensure(array.len() == 4, AuditReason::EncryptShape)?;

    let body_protected = bytes_at(&array, 0, AuditReason::EncryptProtectedHeader)?;
    let body_map = decode_map(&body_protected, AuditReason::EncryptProtectedHeader)?;
    ensure(
        body_map.len() == 1
            && matches!(
                map_get(&body_map, COSE_HEADER_ALGORITHM),
                Some(value) if integer_matches(value, kem.content_algorithm())
            ),
        AuditReason::EncryptProtectedHeader,
    )?;
    ensure(
        encode_cbor(&Value::Map(body_map))? == body_protected,
        AuditReason::EncryptProtectedHeader,
    )?;

    let body_unprotected = map_at(&array, 1, AuditReason::EncryptUnprotectedHeader)?;
    ensure(
        body_unprotected.len() == 1,
        AuditReason::EncryptUnprotectedHeader,
    )?;
    let iv = match map_get(&body_unprotected, COSE_HEADER_IV) {
        Some(Value::Bytes(bytes)) if bytes.len() == 12 => bytes.clone(),
        _ => return Err(general(AuditReason::EncryptUnprotectedHeader)),
    };
    let ciphertext = bytes_at(&array, 2, AuditReason::EncryptShape)?;

    let recipients = match array.get(3) {
        Some(Value::Array(recipients)) if recipients.len() == 1 => recipients,
        _ => return Err(general(AuditReason::RecipientShape)),
    };
    let recipient = match recipients.first() {
        Some(Value::Array(recipient)) if recipient.len() == 3 => recipient,
        _ => return Err(general(AuditReason::RecipientShape)),
    };
    let recipient_protected = bytes_at(recipient, 0, AuditReason::RecipientProtectedHeader)?;
    let recipient_map = decode_map(&recipient_protected, AuditReason::RecipientProtectedHeader)?;
    let expected_recipient_algorithm = match mode {
        Mode::Direct => kem.direct_algorithm(),
        Mode::KeyWrap => kem.wrapped_algorithm(),
    };
    ensure(
        recipient_map.len() == 2
            && matches!(
                map_get(&recipient_map, COSE_HEADER_ALGORITHM),
                Some(value) if integer_matches(value, expected_recipient_algorithm)
            )
            && matches!(
                map_get(&recipient_map, COSE_HEADER_KID),
                Some(Value::Bytes(kid)) if kid.as_slice() == expected_kid
            ),
        AuditReason::RecipientProtectedHeader,
    )?;
    ensure(
        encode_cbor(&Value::Map(recipient_map))? == recipient_protected,
        AuditReason::RecipientProtectedHeader,
    )?;

    let recipient_unprotected = map_at(recipient, 1, AuditReason::RecipientUnprotectedHeader)?;
    ensure(
        recipient_unprotected.len() == 1,
        AuditReason::RecipientUnprotectedHeader,
    )?;
    let encapsulated_key = match map_get(&recipient_unprotected, REALLYME_HEADER_EK) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err(general(AuditReason::RecipientUnprotectedHeader)),
    };
    let recipient_ciphertext = match recipient.get(2) {
        Some(Value::Null) => None,
        Some(Value::Bytes(bytes)) => Some(bytes.clone()),
        _ => return Err(general(AuditReason::RecipientShape)),
    };

    Ok(ParsedEncrypt {
        body_protected,
        recipient_protected,
        iv,
        ciphertext,
        encapsulated_key,
        recipient_ciphertext,
    })
}

fn deterministic_encapsulation(
    kem: Kem,
    seed: &[u8; 64],
    randomness: &[u8; 32],
) -> AuditResult<EncapsulationOutput> {
    let seed =
        Seed::try_from(seed.as_slice()).map_err(|_| general(AuditReason::InvalidSeedLength))?;
    let message = B32::try_from(randomness.as_slice())
        .map_err(|_| general(AuditReason::InvalidSeedLength))?;
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

fn decapsulate(kem: Kem, seed: &[u8; 64], ciphertext: &[u8]) -> AuditResult<Zeroizing<Vec<u8>>> {
    let seed =
        Seed::try_from(seed.as_slice()).map_err(|_| general(AuditReason::InvalidSeedLength))?;
    match kem {
        Kem::MlKem512 => {
            let private = ml_kem::ml_kem_512::DecapsulationKey::from_seed(seed);
            let ciphertext = ml_kem::ml_kem_512::Ciphertext::try_from(ciphertext)
                .map_err(|_| general(AuditReason::KemDecapsulationMismatch))?;
            let mut shared = private.decapsulate(&ciphertext);
            let output = Zeroizing::new(shared.to_vec());
            shared.zeroize();
            Ok(output)
        }
        Kem::MlKem768 => {
            let private = ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed);
            let ciphertext = ml_kem::ml_kem_768::Ciphertext::try_from(ciphertext)
                .map_err(|_| general(AuditReason::KemDecapsulationMismatch))?;
            let mut shared = private.decapsulate(&ciphertext);
            let output = Zeroizing::new(shared.to_vec());
            shared.zeroize();
            Ok(output)
        }
        Kem::MlKem1024 => {
            let private = ml_kem::ml_kem_1024::DecapsulationKey::from_seed(seed);
            let ciphertext = ml_kem::ml_kem_1024::Ciphertext::try_from(ciphertext)
                .map_err(|_| general(AuditReason::KemDecapsulationMismatch))?;
            let mut shared = private.decapsulate(&ciphertext);
            let output = Zeroizing::new(shared.to_vec());
            shared.zeroize();
            Ok(output)
        }
    }
}

fn derive_kid(kem: Kem, public_key: &[u8]) -> AuditResult<Vec<u8>> {
    let cose_key = encode_cbor(&Value::Map(vec![
        (
            Value::Integer(1_i64.into()),
            Value::Integer(COSE_KEY_TYPE_AKP.into()),
        ),
        (
            Value::Integer(3_i64.into()),
            Value::Integer(kem.direct_algorithm().into()),
        ),
        (
            Value::Integer((-1_i64).into()),
            Value::Bytes(public_key.to_vec()),
        ),
    ]))?;
    Ok(Sha256::digest(cose_key).to_vec())
}

fn derive_key(
    shared_secret: &[u8],
    algorithm: i64,
    output_length: usize,
    recipient_protected: &[u8],
    supp_priv_info: &[u8],
) -> AuditResult<Zeroizing<Vec<u8>>> {
    let output_bits = output_length
        .checked_mul(BITS_PER_BYTE)
        .ok_or_else(|| general(AuditReason::IntegerConversion))?;
    let output_bits =
        u64::try_from(output_bits).map_err(|_| general(AuditReason::IntegerConversion))?;
    let context = encode_cbor(&Value::Array(vec![
        Value::Integer(algorithm.into()),
        Value::Array(vec![
            Value::Integer(output_bits.into()),
            Value::Bytes(recipient_protected.to_vec()),
        ]),
        Value::Bytes(supp_priv_info.to_vec()),
    ]))?;
    let mut kmac = Kmac256::new(shared_secret, &[]).map_err(|_| general(AuditReason::KemKdf))?;
    kmac.update(&context);
    let mut output = Zeroizing::new(vec![0_u8; output_length]);
    kmac.finalize_into(&mut output);
    Ok(output)
}

fn unwrap_key(kem: Kem, kek: &[u8], wrapped: &[u8]) -> AuditResult<Zeroizing<Vec<u8>>> {
    let expected_length = wrapped
        .len()
        .checked_sub(AES_KW_OVERHEAD)
        .ok_or_else(|| general(AuditReason::KemKeyWrap))?;
    let mut output = Zeroizing::new(vec![0_u8; expected_length]);
    let unwrapped = match kem {
        Kem::MlKem512 => KwAes128::new_from_slice(kek)
            .map_err(|_| general(AuditReason::KemKeyWrap))?
            .unwrap_key(wrapped, &mut output),
        Kem::MlKem768 => KwAes192::new_from_slice(kek)
            .map_err(|_| general(AuditReason::KemKeyWrap))?
            .unwrap_key(wrapped, &mut output),
        Kem::MlKem1024 => KwAes256::new_from_slice(kek)
            .map_err(|_| general(AuditReason::KemKeyWrap))?
            .unwrap_key(wrapped, &mut output),
    }
    .map_err(|_| general(AuditReason::KemKeyWrap))?;
    ensure(unwrapped.len() == expected_length, AuditReason::KemKeyWrap)?;
    Ok(output)
}

fn decrypt_content(
    kem: Kem,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> AuditResult<Zeroizing<Vec<u8>>> {
    let iv =
        <[u8; 12]>::try_from(iv).map_err(|_| general(AuditReason::EncryptUnprotectedHeader))?;
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let plaintext = match kem {
        Kem::MlKem512 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| general(AuditReason::EncryptAuthentication))?
            .decrypt((&iv).into(), payload),
        Kem::MlKem768 => Aes192Gcm::new_from_slice(key)
            .map_err(|_| general(AuditReason::EncryptAuthentication))?
            .decrypt((&iv).into(), payload),
        Kem::MlKem1024 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| general(AuditReason::EncryptAuthentication))?
            .decrypt((&iv).into(), payload),
    }
    .map_err(|_| general(AuditReason::EncryptAuthentication))?;
    Ok(Zeroizing::new(plaintext))
}

fn decode_map(bytes: &[u8], reason: AuditReason) -> AuditResult<Vec<(Value, Value)>> {
    match ciborium::de::from_reader::<Value, _>(Cursor::new(bytes)) {
        Ok(Value::Map(map)) => Ok(map),
        Ok(_) | Err(_) => Err(general(reason)),
    }
}

fn bytes_at(array: &[Value], index: usize, reason: AuditReason) -> AuditResult<Vec<u8>> {
    match array.get(index) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        _ => Err(general(reason)),
    }
}

fn map_at(array: &[Value], index: usize, reason: AuditReason) -> AuditResult<Vec<(Value, Value)>> {
    match array.get(index) {
        Some(Value::Map(map)) => Ok(map.clone()),
        _ => Err(general(reason)),
    }
}

fn decode_hex(value: &str) -> AuditResult<Vec<u8>> {
    hex::decode(value).map_err(|_| general(AuditReason::Hex))
}

fn fixed<const N: usize>(bytes: &[u8]) -> AuditResult<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| general(AuditReason::InvalidSeedLength))
}
