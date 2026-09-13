// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! COSE-layer audit for committed conformance vectors.
//!
//! This binary intentionally does not depend on `reallyme-cose`,
//! `reallyme-crypto`, or `reallyme-codec`. Its CBOR parsing, COSE structure,
//! KDF, key-wrap, and Multikey checks are independent from production. Direct
//! RustCrypto dependencies provide the primitive oracle; primitive ACVP and
//! adversarial conformance remain owned by `reallyme-crypto`.

use std::collections::HashSet;
use std::fmt::{Display, Formatter, Write};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ciborium::value::Value;
use ciborium::{de::from_reader, ser::into_writer};
use serde::Deserialize;
use thiserror::Error;

mod ml_kem_encrypt;
mod pq;
mod verify_manifest;

const CASE_ID_BYTES: usize = 96;
const CASE_ID_BYTES_U8: u8 = 96;
const SIGN1_FILE: &str = "vectors/cose-sign1.json";
const KEY_FILE: &str = "vectors/cose-key.json";
const ML_KEM_ENCRYPT_FILE: &str = "vectors/cose-encrypt-ml-kem.json";
const MANIFEST_FILE: &str = "vectors/manifest.json";

include!("audit_types.rs");
include!("run_audit.rs");
include!("verify_signatures.rs");
include!("audit_utilities.rs");
