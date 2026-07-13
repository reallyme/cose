// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(multikey) = core::str::from_utf8(data) {
        if let Ok(key) = reallyme_cose::multikey_to_cose_key(multikey) {
            let _ = reallyme_cose::cose_key_to_vec(&key);
            let _ = reallyme_cose::derive_kid_from_cose_key_public(&key);
        }
    }
});
