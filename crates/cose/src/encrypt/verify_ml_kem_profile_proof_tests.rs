// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use coset::RegisteredLabelWithPrivate;

use super::{suite_for, suite_from_cose_algorithm, CoseMlKemAlgorithm, CoseMlKemMode};
use crate::{CoseError, CoseMlKemProfile};

#[kani::proof]
fn ml_kem_recipient_registration_binds_mode_parameter_set_and_lengths() {
    use CoseMlKemAlgorithm::{MlKem1024, MlKem512, MlKem768};
    use CoseMlKemMode::{Direct, KeyWrap};

    // This table comes from the documented ReallyMe V1 profile, with the
    // parameter-set sizes from FIPS 203 and AES-KW IDs from the COSE registry.
    let identifier: i64 = kani::any();
    let expected = match identifier {
        -65_537 => Some((MlKem512, Direct, 800, 768, None)),
        -65_538 => Some((MlKem768, Direct, 1_184, 1_088, None)),
        -65_539 => Some((MlKem1024, Direct, 1_568, 1_568, None)),
        -65_540 => Some((MlKem512, KeyWrap, 800, 768, Some((16, -3)))),
        -65_541 => Some((MlKem768, KeyWrap, 1_184, 1_088, Some((24, -4)))),
        -65_542 => Some((MlKem1024, KeyWrap, 1_568, 1_568, Some((32, -5)))),
        _ => None,
    };
    let decoded = suite_from_cose_algorithm(&RegisteredLabelWithPrivate::PrivateUse(identifier));
    if let Some((kem, mode, public_key_length, ciphertext_length, key_wrap)) = expected {
        let encoded = suite_for(kem, mode);
        for result in [decoded, encoded] {
            assert!(result.is_ok());
            if let Ok(suite) = result {
                assert!(suite.profile == CoseMlKemProfile::ReallyMeV1);
                assert!(
                    suite.cose_algorithm == identifier && suite.kem == kem && suite.mode == mode
                );
                assert!(suite.public_key_length == public_key_length);
                assert!(suite.encapsulated_key_length == ciphertext_length);
                assert!(suite.kek_length == key_wrap.map(|(bytes, _)| bytes));
                assert!(suite.key_wrap_algorithm_id == key_wrap.map(|(_, alg)| alg));
            }
        }
    } else {
        assert!(matches!(decoded, Err(CoseError::UnsupportedAlgorithm)));
    }
    kani::cover!(identifier == -65_537, "direct ML-KEM profile is reached");
    kani::cover!(identifier == -65_542, "key-wrap ML-KEM profile is reached");
    kani::cover!(
        identifier == -65_543,
        "unknown private-use recipient ID is reached"
    );
}
