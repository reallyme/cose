// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = reallyme_cose::cose_key_from_slice(data) {
        let _ = reallyme_cose::cose_key_to_vec(&key);
        let _ = reallyme_cose::cose_key_to_public_bytes(&key);
        let _ = reallyme_cose::cose_key_to_private_bytes(&key);
        let _ = reallyme_cose::derive_kid_from_cose_key_public(&key);
        let _ = reallyme_cose::cose_key_to_multikey(&key);
    }
});
