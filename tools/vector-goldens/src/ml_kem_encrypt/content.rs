// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes192;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};

use super::{GenerateError, Kem, AES_GCM_A128, AES_GCM_A192, AES_GCM_A256};

type Aes192Gcm = AesGcm<Aes192, U12>;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Content {
    Aes128,
    Aes192,
    Aes256,
}

impl Content {
    pub(super) const fn id(self) -> i64 {
        match self {
            Self::Aes128 => AES_GCM_A128,
            Self::Aes192 => AES_GCM_A192,
            Self::Aes256 => AES_GCM_A256,
        }
    }

    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Aes128 => "A128GCM",
            Self::Aes192 => "A192GCM",
            Self::Aes256 => "A256GCM",
        }
    }

    pub(super) const fn key_length(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    pub(super) const fn for_kem(kem: Kem) -> Self {
        match kem {
            Kem::MlKem512 => Self::Aes128,
            Kem::MlKem768 => Self::Aes192,
            Kem::MlKem1024 => Self::Aes256,
        }
    }
}

pub(super) fn encrypt_content(
    content: Content,
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, GenerateError> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match content {
        Content::Aes128 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| GenerateError::Crypto)?
            .encrypt(iv.into(), payload),
        Content::Aes192 => Aes192Gcm::new_from_slice(key)
            .map_err(|_| GenerateError::Crypto)?
            .encrypt(iv.into(), payload),
        Content::Aes256 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| GenerateError::Crypto)?
            .encrypt(iv.into(), payload),
    }
    .map_err(|_| GenerateError::Crypto)
}
