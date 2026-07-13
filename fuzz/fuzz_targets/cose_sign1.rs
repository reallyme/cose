// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // An unresolvable kid exercises the early fail-closed path; a resolver
    // that echoes attacker-controlled bytes as the public key drives the
    // full pipeline: header policy, signature re-encoding, backend verify.
    let _ = reallyme_cose::cose_verify1(data, |_| None);
    let _ = reallyme_cose::cose_verify1(data, |kid| Some(kid.to_vec()));

    if let Some((split_byte, rest)) = data.split_first() {
        let split = usize::from(*split_byte) % rest.len().saturating_add(1);
        let (cose_bytes, payload) = rest.split_at(split);
        let _ = reallyme_cose::cose_verify1_detached(cose_bytes, payload, |_| None);
        let _ = reallyme_cose::cose_verify1_detached(cose_bytes, payload, |kid| Some(kid.to_vec()));
    }
});
