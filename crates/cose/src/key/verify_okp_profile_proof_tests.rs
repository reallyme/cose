// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use coset::iana;

use super::okp_profile;
use crate::CoseError;

#[kani::proof]
fn okp_default_profile_depends_only_on_the_exact_curve_registration() {
    let curve: i64 = kani::any();
    match (curve, okp_profile(curve)) {
        (4, Ok(profile)) => {
            assert!(profile.coordinate_len == 32 && profile.alg.is_none());
        }
        (6, Ok(profile)) => {
            assert!(profile.coordinate_len == 32 && profile.alg == Some(iana::Algorithm::Ed25519));
            assert!(profile.alg.map(|alg| alg as i64) == Some(-19));
        }
        (other, Err(error)) => {
            assert!(other != 4 && other != 6 && error == CoseError::UnsupportedAlgorithm);
        }
        _ => {
            assert!(
                false,
                "each supported OKP curve must have its exact default"
            );
        }
    }
    kani::cover!(
        curve == 4,
        "X25519 retains an absent signature registration"
    );
    kani::cover!(
        curve == 6,
        "Ed25519 retains its fully specified registration"
    );
    kani::cover!(curve == 1, "an EC2 curve cannot select an OKP profile");
}
