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
#[path = "contract_limit_tests.rs"]
mod limits;
#[path = "contract_mac_tests.rs"]
mod mac;
#[path = "contract_modern_tests.rs"]
mod modern;
#[path = "contract_peer_base_iv_tests.rs"]
mod peer_base_iv;
#[path = "contract_signature_tests.rs"]
mod signature;
#[path = "contract_support_tests.rs"]
mod support;

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
