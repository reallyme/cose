#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Independent test-only COSE/RSA signatures; no production crypto dependency.

OpenSSL signs literal RFC 9052/RFC 9338 structures encoded here independently
of COSE's Rust builders. Temporary test private keys are never committed.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def head(major, number):
    if number < 24:
        return bytes([(major << 5) | number])
    for width, selector in [(1, 24), (2, 25), (4, 26), (8, 27)]:
        if number < (1 << (width * 8)):
            return bytes([(major << 5) | selector]) + number.to_bytes(width, "big")
    raise ValueError("test fixture length exceeds CBOR range")


def cbor(value):
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise ValueError("unsupported fixture type")


def generate(openssl, directory):
    def run(*args, data=None):
        return subprocess.run([openssl, *args], input=data, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def key(name, bits):
        private = directory / (name + ".pem")
        public = directory / (name + "-public.pem")
        run("genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}", "-out", str(private))
        run("pkey", "-in", str(private), "-pubout", "-out", str(public))
        der = run("pkey", "-in", str(private), "-pubout", "-outform", "DER")
        return private, public, der

    private, public, spki = key("main", 2048)
    _, _, wrong = key("wrong", 2048)
    _, _, weak = key("weak", 1024)
    _, _, below_minimum = key("below-minimum", 2047)
    pkcs1 = run("rsa", "-in", str(private), "-RSAPublicKey_out", "-outform", "DER")
    payload = b"Independent RSA COSE payload"
    aad = bytes.fromhex("010203")
    body = cbor({4: b"body"})
    target_protected = cbor({1: -7})
    primary_signature = bytes([0x55]) * 64
    target = b"\xd2" + cbor([target_protected, {}, payload, primary_signature])

    def sign(message, digest, pss, bad_mgf=False, bad_salt=False):
        options = []
        if pss:
            salt = "0" if bad_salt else str(digest // 8)
            mgf = 384 if digest == 256 else 256
            mgf = mgf if bad_mgf else digest
            options = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", f"rsa_pss_saltlen:{salt}",
                       "-sigopt", f"rsa_mgf1_md:sha{mgf}"]
        signature = run("dgst", f"-sha{digest}", "-sign", str(private), *options, data=message)
        signature_file = directory / "signature.bin"
        signature_file.write_bytes(signature)
        run("dgst", f"-sha{digest}", "-verify", str(public), "-signature", str(signature_file),
            *options, data=message)
        return signature

    cases = []
    for name, registration, digest, pss in [
        ("PS256", -37, 256, True), ("PS384", -38, 384, True), ("PS512", -39, 512, True),
        ("RS256", -257, 256, False), ("RS384", -258, 384, False), ("RS512", -259, 512, False),
    ]:
        # Deliberately retain kid-before-alg order inside authenticated bytes.
        protected = cbor({4: b"rsa", 1: registration})
        sign1_structure = cbor(["Signature1", protected, aad, payload])
        sign_structure = cbor(["Signature", body, protected, aad, payload])
        full_structure = cbor(["CounterSignatureV2", target_protected, protected, aad, payload, [primary_signature]])
        abbreviated_structure = cbor(["CounterSignature0V2", target_protected, aad, payload, [primary_signature]])
        sign1_signature = sign(sign1_structure, digest, pss)
        sign_signature = sign(sign_structure, digest, pss)
        full_signature = sign(full_structure, digest, pss)
        abbreviated_signature = sign(abbreviated_structure, digest, pss)
        cases.append({
            "id": name, "registration": registration, "protected": protected.hex(),
            "signature": sign1_signature.hex(), "sign1_structure": sign1_structure.hex(),
            "sign1": (b"\xd2" + cbor([protected, {}, payload, sign1_signature])).hex(),
            "sign1_detached": (b"\xd2" + cbor([protected, {}, None, sign1_signature])).hex(),
            "empty_aad_sign1": (b"\xd2" + cbor([protected, {}, payload, sign(cbor(["Signature1", protected, b"", payload]), digest, pss)])).hex(),
            "empty_payload_detached": (b"\xd2" + cbor([protected, {}, None, sign(cbor(["Signature1", protected, aad, b""]), digest, pss)])).hex(),
            "sign": (b"\xd8\x62" + cbor([body, {}, payload, [[protected, {}, sign_signature]]])).hex(),
            "sign_structure": sign_structure.hex(),
            "counter": cbor([protected, {}, full_signature]).hex(),
            "counter_structure": full_structure.hex(),
            "counter0": cbor(abbreviated_signature).hex(),
            "counter0_structure": abbreviated_structure.hex(),
            "wrong_mgf_signature": sign(sign1_structure, digest, pss, bad_mgf=True).hex() if pss else None,
            "wrong_salt_signature": sign(sign1_structure, digest, pss, bad_salt=True).hex() if pss else None,
        })
    max_protected = cbor({4: b"rsa", 1: -37})
    # Replace an empty one-byte bstr header with a five-byte header at 1 MiB.
    overhead = len(b"\xd2" + cbor([max_protected, {}, b"", bytes(256)])) - 1 + 5
    max_payload_bytes = 1_048_576 - overhead
    maximum_payload = bytes([0x5A]) * max_payload_bytes
    maximum_signature = sign(cbor(["Signature1", max_protected, aad, maximum_payload]), 256, True)
    assert len(b"\xd2" + cbor([max_protected, {}, maximum_payload, maximum_signature])) == 1_048_576
    return {
        "schema": "reallyme.cose.rsa.v1",
        "source": run("version").decode("utf-8").strip(),
        "standards": ["RFC 8230 section 2", "RFC 8812 section 2", "RFC 9052 section 4.4", "RFC 9338 section 3"],
        "public_spki": spki.hex(), "public_pkcs1": pkcs1.hex(), "wrong_public_spki": wrong.hex(),
        "weak_public_spki": weak.hex(), "below_minimum_public_spki": below_minimum.hex(),
        "payload": payload.hex(), "aad": aad.hex(), "body_protected": body.hex(),
        "counter_target": target.hex(), "cases": cases,
        "max_payload_bytes": max_payload_bytes, "max_signature": maximum_signature.hex(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    # The directory and OpenSSL output files are private even on shared hosts.
    previous = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="cose-rsa-vectors-") as temporary:
            vectors = generate(args.openssl, Path(temporary))
    finally:
        os.umask(previous)
    target = Path(__file__).resolve().parent.parent / "crates/cose/tests/fixtures/rsa.json"
    target.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
