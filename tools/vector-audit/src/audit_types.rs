// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Error)]
#[error("{context}: {reason}")]
struct AuditError {
    context: AuditContext,
    reason: AuditReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditContext {
    General,
    Manifest,
    Case(CaseId),
}

impl Display for AuditContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditContext::General => f.write_str("vector audit"),
            AuditContext::Manifest => f.write_str("manifest"),
            AuditContext::Case(case_id) => Display::fmt(case_id, f),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaseId {
    bytes: [u8; CASE_ID_BYTES],
    len: u8,
}

impl CaseId {
    fn from_str(value: &str) -> Self {
        let mut bytes = [0_u8; CASE_ID_BYTES];
        let source = value.as_bytes();
        let copy_len = source.len().min(CASE_ID_BYTES);
        bytes[..copy_len].copy_from_slice(&source[..copy_len]);
        Self {
            bytes,
            len: u8::try_from(copy_len).unwrap_or(CASE_ID_BYTES_U8),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl Display for CaseId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for byte in self.as_bytes() {
            if byte.is_ascii_graphic() || *byte == b' ' {
                f.write_char(char::from(*byte))?;
            } else {
                f.write_str("?")?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
enum AuditReason {
    #[error("could not determine repository root")]
    CurrentDirectory,
    #[error("could not read vector file")]
    ReadFile,
    #[error("JSON decoding failed")]
    Json,
    #[error("hex decoding failed")]
    Hex,
    #[error("CBOR decoding failed")]
    CborDecode,
    #[error("CBOR encoding failed")]
    CborEncode,
    #[error("unsupported algorithm name")]
    UnsupportedAlgorithm,
    #[error("unsupported operation")]
    UnsupportedOperation,
    #[error("unsupported expected error")]
    UnsupportedExpectedError,
    #[error("seed length is invalid")]
    InvalidSeedLength,
    #[error("public key length is invalid")]
    InvalidPublicKeyLength,
    #[error("private seed does not derive the stated public key")]
    SeedPublicMismatch,
    #[error("external classical COSE_Sign1 vector is missing")]
    ExternalSign1VectorMissing,
    #[error("COSE_Sign1 root is not an array")]
    Sign1RootNotArray,
    #[error("COSE_Sign1 array length is invalid")]
    Sign1ArrayLength,
    #[error("COSE_Sign1 protected header is not a byte string")]
    Sign1ProtectedNotBytes,
    #[error("COSE_Sign1 protected header is not a map")]
    Sign1ProtectedNotMap,
    #[error("COSE_Sign1 unprotected header is not a map")]
    Sign1UnprotectedNotMap,
    #[error("COSE_Sign1 payload is not byte string or null")]
    Sign1PayloadShape,
    #[error("COSE_Sign1 signature is not a byte string")]
    Sign1SignatureShape,
    #[error("attached vector does not carry an attached payload")]
    AttachedPayloadMissing,
    #[error("detached vector carries an attached payload")]
    DetachedPayloadPresent,
    #[error("happy-path vector failed independent signature verification")]
    SignatureDidNotVerify,
    #[error("negative signature vector verified independently")]
    InvalidSignatureVerified,
    #[error("signature width does not match the selected algorithm")]
    SignatureWidth,
    #[error("invalid-encoding vector unexpectedly has the valid signature width")]
    InvalidSignatureEncodingWidth,
    #[error("protected algorithm label mismatch")]
    ProtectedAlgorithmMismatch,
    #[error("protected kid mismatch")]
    ProtectedKidMismatch,
    #[error("missing protected kid")]
    ProtectedKidMissing,
    #[error("key-resolution negative vector has matching resolver kid")]
    ResolverKidUnexpectedlyMatches,
    #[error("key-resolution negative vector signature is invalid")]
    ResolverNegativeSignatureInvalid,
    #[error("unsupported-algorithm vector uses a supported algorithm")]
    UnsupportedAlgorithmVectorInvalid,
    #[error("critical-header vector has no critical header")]
    CriticalHeaderMissing,
    #[error("unprotected-header vector has no integrity-sensitive unprotected label")]
    UnprotectedIntegrityFieldMissing,
    #[error("structural negative vector is not otherwise signed")]
    StructuralNegativeSignatureInvalid,
    #[error("COSE_Key root is not a map")]
    CoseKeyRootNotMap,
    #[error("COSE_Key kty mismatch")]
    CoseKeyTypeMismatch,
    #[error("COSE_Key crv mismatch")]
    CoseKeyCurveMismatch,
    #[error("COSE_Key alg mismatch")]
    CoseKeyAlgorithmMismatch,
    #[error("COSE_Key unexpected alg")]
    CoseKeyUnexpectedAlgorithm,
    #[error("COSE_Key leaks private d parameter")]
    CoseKeyPrivateMaterial,
    #[error("COSE_Key missing public x parameter")]
    CoseKeyMissingX,
    #[error("OKP public key mismatch")]
    OkpPublicMismatch,
    #[error("OKP public key width mismatch")]
    OkpPublicWidth,
    #[error("Ed25519 public key rejected by independent implementation")]
    Ed25519PublicRejected,
    #[error("EC2 y parameter missing")]
    Ec2MissingY,
    #[error("EC2 SEC1 public key mismatch")]
    Ec2PublicMismatch,
    #[error("EC2 public key rejected by independent implementation")]
    Ec2PointRejected,
    #[error("multikey is not base58btc")]
    MultikeyBase58Prefix,
    #[error("base58 decoding failed")]
    Base58,
    #[error("multicodec prefix mismatch")]
    MulticodecPrefix,
    #[error("multikey key bytes mismatch")]
    MultikeyBytes,
    #[error("manifest case count mismatch")]
    ManifestCaseCount,
    #[error("manifest suite set is incomplete or duplicated")]
    ManifestSuiteSet,
    #[error("manifest suite path mismatch")]
    ManifestPath,
    #[error("manifest suite digest encoding is invalid")]
    ManifestDigestEncoding,
    #[error("manifest suite digest mismatch")]
    ManifestDigest,
    #[error("duplicate vector id")]
    DuplicateCaseId,
    #[error("integer conversion failed")]
    IntegerConversion,
    #[error("COSE_Encrypt root tag or array shape is invalid")]
    EncryptShape,
    #[error("COSE_Encrypt protected header is invalid")]
    EncryptProtectedHeader,
    #[error("COSE_Encrypt unprotected header is invalid")]
    EncryptUnprotectedHeader,
    #[error("COSE_Recipient shape is invalid")]
    RecipientShape,
    #[error("COSE_Recipient protected header is invalid")]
    RecipientProtectedHeader,
    #[error("COSE_Recipient unprotected header is invalid")]
    RecipientUnprotectedHeader,
    #[error("ML-KEM vector mode is invalid")]
    InvalidKemMode,
    #[error("ML-KEM vector algorithm metadata is inconsistent")]
    KemAlgorithmMismatch,
    #[error("ML-KEM vector deterministic key or encapsulation mismatch")]
    KemDeterministicMismatch,
    #[error("ML-KEM vector decapsulation mismatch")]
    KemDecapsulationMismatch,
    #[error("ML-KEM vector kid does not bind the public COSE_Key")]
    KemKidMismatch,
    #[error("ML-KEM vector KDF failed")]
    KemKdf,
    #[error("ML-KEM vector AES-KW failed")]
    KemKeyWrap,
    #[error("ML-KEM vector content authentication failed")]
    EncryptAuthentication,
    #[error("ML-KEM vector plaintext mismatch")]
    EncryptPlaintextMismatch,
}

type AuditResult<T> = Result<T, AuditError>;

#[derive(Debug, Deserialize)]
struct Sign1Suite {
    cases: Vec<Sign1Case>,
}

#[derive(Debug, Deserialize)]
struct Sign1Case {
    id: String,
    operation: String,
    algorithm: String,
    kid_hex: String,
    public_key_hex: String,
    private_key_seed_hex: String,
    payload_hex: String,
    cose_sign1_hex: String,
    expected_error: Option<String>,
    provenance: Option<Provenance>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Provenance {
    NodeOpenSslRfc8032,
}

#[derive(Debug, Deserialize)]
struct KeySuite {
    cases: Vec<KeyCase>,
}

#[derive(Debug, Deserialize)]
struct KeyCase {
    id: String,
    algorithm: String,
    public_key_hex: String,
    cose_key_hex: String,
    multikey: String,
}

#[derive(Clone, Copy)]
enum Algorithm {
    Ed25519,
    Es256,
    P256,
    P384,
    P521,
    Secp256k1,
    X25519,
}

impl Algorithm {
    fn parse(name: &str) -> AuditResult<Self> {
        match name {
            "Ed25519" => Ok(Self::Ed25519),
            "ES256" => Ok(Self::Es256),
            "P256" => Ok(Self::P256),
            "P384" => Ok(Self::P384),
            "P521" => Ok(Self::P521),
            "Secp256k1" => Ok(Self::Secp256k1),
            "X25519" => Ok(Self::X25519),
            _ => Err(general(AuditReason::UnsupportedAlgorithm)),
        }
    }

    fn cose_alg(self) -> AuditResult<i64> {
        match self {
            Self::Ed25519 => Ok(-19),
            Self::Es256 => Ok(-7),
            Self::P256 => Ok(-9),
            Self::P384 => Ok(-51),
            Self::P521 => Ok(-52),
            Self::Secp256k1 => Ok(-47),
            Self::X25519 => Err(general(AuditReason::UnsupportedAlgorithm)),
        }
    }

    fn signature_width(self) -> AuditResult<usize> {
        match self {
            Self::Ed25519 | Self::Es256 | Self::P256 | Self::Secp256k1 => Ok(64),
            Self::P384 => Ok(96),
            Self::P521 => Ok(132),
            Self::X25519 => Err(general(AuditReason::UnsupportedAlgorithm)),
        }
    }
}

struct ParsedSign1 {
    protected_bytes: Vec<u8>,
    protected_map: Vec<(Value, Value)>,
    unprotected_map: Vec<(Value, Value)>,
    payload: Option<Vec<u8>>,
    signature: Vec<u8>,
}

struct CoseKeyProfile {
    kty: i64,
    crv: i64,
    alg: Option<i64>,
    multicodec: u64,
}
