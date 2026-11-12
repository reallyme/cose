// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

const MAX_MEDIA_TYPE_NAME_BYTES: usize = 127;

pub(crate) fn valid_media_type(text: &str) -> bool {
    // RFC 9052 uses RFC 6838's restricted type/subtype syntax. These profiles
    // accept bare media types; MIME parameters and wildcards are not inferred.
    let Some((kind, subtype)) = text.split_once('/') else {
        return false;
    };
    [kind, subtype].into_iter().all(|name| {
        !name.is_empty()
            && name.len() <= MAX_MEDIA_TYPE_NAME_BYTES
            && name
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+'
                    )
            })
    })
}
