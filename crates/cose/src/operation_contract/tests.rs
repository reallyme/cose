// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "contract_boundary_tests.rs"]
mod boundary;
#[path = "contract_container_tests.rs"]
mod container;
#[path = "contract_guarded_tests.rs"]
mod guarded;
#[path = "contract_key_tests.rs"]
mod key;
#[path = "contract_key_set_tests.rs"]
mod key_set;
#[path = "contract_limit_tests.rs"]
mod limits;
#[path = "contract_mac_tests.rs"]
mod mac;
#[path = "contract_modern_tests.rs"]
mod modern;
#[path = "contract_peer_base_iv_tests.rs"]
mod peer_base_iv;
#[path = "contract_peer_policy_tests.rs"]
mod peer_policy;
#[path = "contract_private_key_ops_tests.rs"]
mod private_key_ops;
#[path = "contract_public_key_vec_tests.rs"]
mod public_key_vec;
#[path = "contract_recipient_ciphertext_tests.rs"]
mod recipient_ciphertext;
#[path = "contract_secp256k1_provider_tests.rs"]
mod secp256k1_provider;
#[path = "contract_signature_tests.rs"]
mod signature;
#[path = "contract_signature_structure_tests.rs"]
mod signature_structure;
#[path = "contract_supp_priv_info_tests.rs"]
mod supp_priv_info;
#[path = "contract_support_tests.rs"]
mod support;
#[path = "contract_x5chain_provider_tests.rs"]
mod x5chain_provider;

#[path = "contract_provider_tests.rs"]
mod provider;
#[path = "contract_provider_negative_tests.rs"]
mod provider_negative;
#[path = "contract_provider_support_tests.rs"]
mod provider_support;

#[path = "contract_type_tests.rs"]
mod types;

#[path = "contract_presence_tests.rs"]
mod presence;

#[path = "contract_allowlist_tests.rs"]
mod allowlists;

#[path = "contract_sign_message_tests.rs"]
mod sign_message;

#[path = "contract_encrypt0_tests.rs"]
mod encrypt0;

#[path = "contract_mac_message_tests.rs"]
mod mac_message;

#[path = "contract_counter_tests.rs"]
mod counter;
