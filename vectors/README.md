<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# COSE Conformance Vectors

These suites pin ReallyMe's supported COSE encodings and exercise parsing,
protected-header handling, Sig_structure construction, COSE_Key profiles,
Multikey conversion, ML-KEM recipient processing, KDF inputs, AES Key Wrap, and
authenticated decryption.

`reallyme-cose-vector-audit` is independent at the COSE layer: it does not
depend on `reallyme-cose`, `reallyme-crypto`, or `reallyme-codec`. It uses direct
RustCrypto dependencies as primitive oracles, so it is not an independent
cryptographic implementation. Each suite file is bound into `manifest.json` by
its exact SHA-256 digest and case count.

Primitive conformance belongs to the pinned `reallyme-crypto` dependency. Its
external-vector audit covers NIST ACVP ML-DSA key generation and signature
verification, NIST ACVP ML-KEM key generation and encapsulation, and additional
CCTV and Wycheproof adversarial corpora. Keeping those large primitive suites at
the primitive boundary avoids duplicating them here while COSE tests verify that
their typed rejection behavior survives the protocol wrapper.

The classical COSE examples in RFC 9052 and RFC 9053 use generic algorithm
identifiers that this profile deliberately rejects. They therefore cannot serve
as positive interoperability fixtures for the fully specified algorithm IDs
accepted by this crate. The `cose-sign1-ed25519-node-openssl` case instead uses
RFC 8032 test-vector key material and a signature produced by Node's
OpenSSL-backed Ed25519 implementation over a COSE Sig_structure containing the
profile's fully specified Ed25519 identifier. The golden generator deliberately
preserves those bytes rather than recreating the signature with production code.
