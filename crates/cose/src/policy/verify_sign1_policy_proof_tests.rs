// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{EnumValue, Enumeration};

use super::{require_exact_signature_registration, ContractAlgorithm};
use crate::generated_contract::values::MAX_ALLOWLIST_ENTRIES;
use crate::{CoseError, CoseSignatureAlgorithm};

#[kani::proof]
#[kani::unwind(3)]
fn sign1_restricted_policy_requires_exact_registration() {
    use CoseSignatureAlgorithm::{Es256, Esp256};

    let registrations = CoseSignatureAlgorithm::ALL;
    let selected: usize = kani::any();
    let first: usize = kani::any();
    let second: usize = kani::any();
    kani::assume(selected < registrations.len());
    kani::assume(first < registrations.len());
    kani::assume(second < registrations.len());

    // Two entries exercise first and later matches as well as duplicates.
    // A symbolic prefix covers the singleton and empty policies as well.
    let allowlist_len: usize = kani::any();
    kani::assume(allowlist_len <= 2);
    let choices = [registrations[first], registrations[second]];
    let allowlist = choices.map(|value| ContractAlgorithm::from(value).into());
    let selected_enabled =
        (allowlist_len >= 1 && first == selected) || (allowlist_len == 2 && second == selected);
    let accepted =
        require_exact_signature_registration(&allowlist[..allowlist_len], registrations[selected]);
    let expected = if selected_enabled {
        Ok(())
    } else {
        Err(CoseError::UnsupportedAlgorithm)
    };
    assert!(accepted == expected);
    kani::cover!(
        accepted.is_ok(),
        "the selected exact registration is enabled"
    );
    kani::cover!(
        registrations[selected] == Es256
            && choices[0] == Esp256
            && allowlist_len == 1
            && accepted.is_err(),
        "the other P-256 registration cannot satisfy the allowlist"
    );
    kani::cover!(
        allowlist_len == 0 && accepted.is_err(),
        "an empty allowlist rejects the selected registration"
    );
}

#[kani::proof]
#[kani::unwind(34)]
fn sign1_full_allowlist_admits_only_exact_registrations() {
    let registrations = CoseSignatureAlgorithm::ALL;
    let selected = usize::from(kani::any::<u8>());
    kani::assume(selected < registrations.len());
    let algorithm = registrations[selected];
    let length = usize::from(kani::any::<u8>());
    kani::assume(length <= MAX_ALLOWLIST_ENTRIES);
    let selectors: [i32; MAX_ALLOWLIST_ENTRIES] = kani::any();
    let allowlist = selectors.map(EnumValue::<ContractAlgorithm>::from);

    let canonical = ContractAlgorithm::from(algorithm).to_i32();
    // Compare original schema numbers independently of the production
    // selector-to-registration conversion. The deprecated selectors still
    // denote their corresponding fully specified ECDSA registrations.
    let alias = legacy_selector(algorithm);
    // Scan every slot in the reference so its result does not depend on the
    // production iterator's early exit. Only positions in the prefix count.
    let expected = selectors
        .iter()
        .enumerate()
        .fold(false, |found, (position, &raw)| {
            let matches = (raw == canonical) | (alias == Some(raw));
            found | ((position < length) & matches)
        });
    let result = require_exact_signature_registration(&allowlist[..length], algorithm);
    assert!(result == admission(expected));
    kani::cover!(length == 0 && result.is_err(), "empty restricted allowlist");
    kani::cover!(
        length == MAX_ALLOWLIST_ENTRIES && result.is_ok(),
        "full allowlist with an exact match"
    );
    kani::cover!(
        length == MAX_ALLOWLIST_ENTRIES && result.is_err(),
        "full allowlist without an exact match"
    );
}

#[allow(deprecated, reason = "The reference checks supported schema aliases")]
fn legacy_selector(algorithm: CoseSignatureAlgorithm) -> Option<i32> {
    let selector = match algorithm {
        CoseSignatureAlgorithm::Esp256 => ContractAlgorithm::EcdsaP256Sha256,
        CoseSignatureAlgorithm::Esp384 => ContractAlgorithm::EcdsaP384Sha384,
        CoseSignatureAlgorithm::Esp512 => ContractAlgorithm::EcdsaP521Sha512,
        _ => return None,
    };
    Some(selector.to_i32())
}

#[kani::proof]
#[kani::unwind(34)]
fn sign1_full_allowlist_separates_es256_and_esp256_at_every_position() {
    let es256: bool = kani::any();
    let exact_entry: bool = kani::any();
    let length: usize = kani::any();
    kani::assume((1..=MAX_ALLOWLIST_ENTRIES).contains(&length));
    let position: usize = kani::any();
    kani::assume(position < length);

    // Use the schema variants directly so a faulty conversion between the
    // two registrations cannot also change the proof's expected input.
    let (algorithm, exact, other) = if es256 {
        (
            CoseSignatureAlgorithm::Es256,
            ContractAlgorithm::Es256,
            ContractAlgorithm::Esp256,
        )
    } else {
        (
            CoseSignatureAlgorithm::Esp256,
            ContractAlgorithm::Esp256,
            ContractAlgorithm::Es256,
        )
    };
    let mut allowlist = [EnumValue::Known(ContractAlgorithm::Ed25519); MAX_ALLOWLIST_ENTRIES];
    allowlist[position] = EnumValue::Known(if exact_entry { exact } else { other });
    let result = require_exact_signature_registration(&allowlist[..length], algorithm);
    assert!(result == admission(exact_entry));
    kani::cover!(
        es256 && !exact_entry && result.is_err(),
        "ESP256 cannot admit ES256"
    );
    kani::cover!(
        !es256 && !exact_entry && result.is_err(),
        "ES256 cannot admit ESP256"
    );
    kani::cover!(
        length == MAX_ALLOWLIST_ENTRIES && position == length - 1 && result.is_ok(),
        "exact match in the last slot of a full allowlist"
    );
    kani::cover!(
        length == MAX_ALLOWLIST_ENTRIES && position == length - 1 && result.is_err(),
        "other registration in the last slot of a full allowlist"
    );
}

fn admission(enabled: bool) -> Result<(), CoseError> {
    if enabled {
        Ok(())
    } else {
        Err(CoseError::UnsupportedAlgorithm)
    }
}
