// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

const ADAPTER_ROOT = "crates/cose/src/operation_contract/";
const NATIVE_ROOT = "crates/cose/src/";

export const OPERATION_CONTRACT_ROUTES = Object.freeze([
  route(
    "Sign1Create",
    "sign1/create.rs",
    "attached_result",
    "create_cose_sign1",
    "created_attached",
    "sign1/sign.rs",
    "cose_sign1_with_options_and_external_aad",
  ),
  route(
    "Sign1CreateDetached",
    "sign1/create.rs",
    "detached_result",
    "create_detached_cose_sign1",
    "created_detached",
    "sign1/sign.rs",
    "cose_sign1_detached_with_options_and_external_aad",
  ),
  route(
    "Sign1Verify",
    "sign1/verify.rs",
    "attached_result",
    "verify_cose_sign1",
    "verified_attached",
    "sign1/verify.rs",
    "cose_verify1_with_policy_and_external_aad",
  ),
  route(
    "Sign1VerifyDetached",
    "sign1/verify.rs",
    "detached_result",
    "verify_detached_cose_sign1",
    "verified_detached",
    "sign1/verify.rs",
    "cose_verify1_detached_with_policy_and_external_aad",
  ),
  route(
    "KeyFromPublicBytes",
    "key/convert.rs",
    "from_public_bytes_result",
    "construct_cose_key_from_public",
    "from_public_key",
    "key/convert.rs",
    "cose_key_from_public_bytes",
  ),
  route(
    "KeyFromPrivateBytes",
    "key/convert.rs",
    "from_private_bytes_result",
    "construct_cose_key_from_private",
    "from_private_key",
    "key/convert.rs",
    "cose_key_from_private_bytes",
  ),
  route(
    "KeyParse",
    "key/parse.rs",
    "result",
    "parse_cose_key",
    "parsed_key",
    "key/parse.rs",
    "cose_key_from_slice",
  ),
  route(
    "KeyToPublicBytes",
    "key/convert.rs",
    "to_public_bytes_result",
    "extract_cose_key_public",
    "public_key_bytes",
    "key/convert.rs",
    "cose_key_to_public_bytes",
  ),
  route(
    "KeyToPrivateBytes",
    "key/convert.rs",
    "to_private_bytes_result",
    "extract_cose_key_private",
    "private_key_bytes",
    "key/convert.rs",
    "cose_key_to_private_bytes",
  ),
  route(
    "KeyDerivePublicKid",
    "key/convert.rs",
    "derive_public_kid_result",
    "derive_cose_key_public_kid",
    "key_identifier",
    "key/derive_kid.rs",
    "derive_kid_from_cose_key_public",
  ),
  route(
    "KeyToMultikey",
    "key/convert.rs",
    "to_multikey_result",
    "convert_cose_key_to_multikey",
    "multikey",
    "multikey/convert.rs",
    "cose_key_to_multikey",
  ),
  route(
    "MultikeyToCoseKey",
    "key/convert.rs",
    "multikey_to_key_result",
    "convert_multikey_to_cose_key",
    "from_multikey_key",
    "multikey/convert.rs",
    "multikey_to_cose_key",
  ),
  indirectEncryptRoute(
    "MlKemEncryptDirect",
    "direct_result",
    "encrypt_cose_ml_kem_direct",
    "encrypted_direct",
    "cose_encrypt_ml_kem_direct_with_external_aad",
  ),
  indirectEncryptRoute(
    "MlKemEncryptKeyWrap",
    "key_wrap_result",
    "encrypt_cose_ml_kem_key_wrap",
    "encrypted_key_wrap",
    "cose_encrypt_ml_kem_key_wrap_with_external_aad",
  ),
  route(
    "MlKemDecrypt",
    "encrypt/decrypt.rs",
    "result",
    "decrypt_cose_ml_kem",
    "decrypted",
    "encrypt/decrypt.rs",
    "cose_decrypt_ml_kem_with_external_aad",
  ),
]);

function route(
  variant,
  adapterRelativePath,
  adapterFunction,
  semanticFunction,
  resultFunction,
  nativeRelativePath,
  nativeFunction,
) {
  return Object.freeze({
    variant,
    adapterPath: `${ADAPTER_ROOT}${adapterRelativePath}`,
    adapterFunction,
    semanticFunction,
    resultFunction,
    nativePath: `${NATIVE_ROOT}${nativeRelativePath}`,
    nativeFunction,
    indirect: false,
  });
}

function indirectEncryptRoute(
  variant,
  adapterFunction,
  semanticFunction,
  resultFunction,
  nativeFunction,
) {
  return Object.freeze({
    variant,
    adapterPath: `${ADAPTER_ROOT}encrypt/create.rs`,
    adapterFunction,
    semanticFunction,
    resultFunction,
    nativePath: `${NATIVE_ROOT}encrypt/create.rs`,
    nativeFunction,
    indirect: true,
  });
}
