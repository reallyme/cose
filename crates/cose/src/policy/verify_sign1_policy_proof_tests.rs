// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{require_exact_signature_registration, ContractAlgorithm};
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
