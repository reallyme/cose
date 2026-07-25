#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[path = "cose_suite/support.rs"]
mod support;

#[cfg(feature = "cose-crypto")]
#[path = "cose_suite/concurrency_tests.rs"]
mod concurrency_tests;
#[path = "cose_suite/conformance_vector_tests.rs"]
mod conformance_vector_tests;
#[path = "cose_suite/cose_key_tests.rs"]
mod cose_key_tests;
#[path = "cose_suite/cose_private_key_tests.rs"]
mod cose_private_key_tests;
#[path = "cose_suite/detached_reject_wrong_payload_tests.rs"]
mod detached_reject_wrong_payload_tests;
#[path = "cose_suite/detached_roundtrip_tests.rs"]
mod detached_roundtrip_tests;
#[cfg(all(feature = "cose-crypto", feature = "wire"))]
#[path = "cose_suite/encrypt_semantic_tests.rs"]
mod encrypt_semantic_tests;
#[path = "cose_suite/external_aad_tests.rs"]
mod external_aad_tests;
#[path = "cose_suite/interop_verify_tests.rs"]
mod interop_verify_tests;
#[cfg(feature = "wire")]
#[path = "cose_suite/key_parse_adapter_tests.rs"]
mod key_parse_adapter_tests;
#[cfg(all(feature = "cose-crypto", feature = "wire"))]
#[path = "cose_suite/key_parse_differential_tests.rs"]
mod key_parse_differential_tests;
#[cfg(all(feature = "cose-crypto", feature = "wire"))]
#[path = "cose_suite/operation_response_v2_tests.rs"]
mod operation_response_v2_tests;

#[cfg(all(feature = "cose-crypto", feature = "wire"))]
#[path = "cose_suite/key_family_semantic_tests.rs"]
mod key_family_semantic_tests;
#[path = "cose_suite/kid_derive_tests.rs"]
mod kid_derive_tests;
#[path = "cose_suite/kid_tests.rs"]
mod kid_tests;
#[path = "cose_suite/malicious_cbor_tests.rs"]
mod malicious_cbor_tests;
#[path = "cose_suite/ml_kem_encrypt_tests.rs"]
mod ml_kem_encrypt_tests;
#[path = "cose_suite/multikey_tests.rs"]
mod multikey_tests;
#[path = "cose_suite/multikey_to_cose_tests.rs"]
mod multikey_to_cose_tests;
#[path = "cose_suite/platform_consumer_tests.rs"]
mod platform_consumer_tests;
#[path = "cose_suite/platform_signer_tests.rs"]
mod platform_signer_tests;
#[path = "cose_suite/rfc9052_9053_profile_tests.rs"]
mod rfc9052_9053_profile_tests;
#[path = "cose_suite/roundtrip_eddsa_tests.rs"]
mod roundtrip_eddsa_tests;
#[path = "cose_suite/roundtrip_es256k_tests.rs"]
mod roundtrip_es256k_tests;
#[path = "cose_suite/roundtrip_p256_tests.rs"]
mod roundtrip_p256_tests;
#[cfg(all(feature = "cose-crypto", feature = "wire"))]
#[path = "cose_suite/sign1_semantic_tests.rs"]
mod sign1_semantic_tests;
#[path = "cose_suite/signing_algorithm_coverage_tests.rs"]
mod signing_algorithm_coverage_tests;
#[path = "cose_suite/tamper_reject_tests.rs"]
mod tamper_reject_tests;
#[cfg(feature = "wire")]
#[path = "cose_suite/wire_tests.rs"]
mod wire_tests;
