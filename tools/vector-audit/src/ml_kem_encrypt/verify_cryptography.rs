// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
