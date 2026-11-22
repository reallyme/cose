// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use coset::{iana, iana::EnumI64, RegisteredLabelWithPrivate};

use super::CoseSignatureAlgorithm;
use crate::{Algorithm, CoseError};

#[kani::proof]
fn registered_identifier_selects_exact_signature_algorithm() {
    use CoseSignatureAlgorithm::{
        Ed25519, EdDsa, Es256, Es256K, Es384, Es512, Esp256, Esp384, Esp512, MlDsa44, MlDsa65,
        MlDsa87, Ps256, Ps384, Ps512, Rs256, Rs384, Rs512,
    };

    // Use the IANA wire IDs directly so a self-consistent renumbering of both
    // generated conversions still violates the proof obligation.
    let identifier: i64 = kani::any();
    let expected = match identifier {
        -7 => Some((Es256, Some(Algorithm::P256))),
        -8 => Some((EdDsa, None)),
        -9 => Some((Esp256, Some(Algorithm::P256))),
        -19 => Some((Ed25519, Some(Algorithm::Ed25519))),
        -35 => Some((Es384, None)),
        -36 => Some((Es512, None)),
        -37 => Some((Ps256, None)),
        -38 => Some((Ps384, None)),
        -39 => Some((Ps512, None)),
        -47 => Some((Es256K, Some(Algorithm::Secp256k1))),
        -48 => Some((MlDsa44, Some(Algorithm::MlDsa44))),
        -49 => Some((MlDsa65, Some(Algorithm::MlDsa65))),
        -50 => Some((MlDsa87, Some(Algorithm::MlDsa87))),
        -51 => Some((Esp384, Some(Algorithm::P384))),
        -52 => Some((Esp512, Some(Algorithm::P521))),
        -257 => Some((Rs256, None)),
        -258 => Some((Rs384, None)),
        -259 => Some((Rs512, None)),
        _ => None,
    };
    let registration = CoseSignatureAlgorithm::from_identifier(identifier);
    assert!(
        registration
            == expected
                .map(|(exact, _)| exact)
                .ok_or(CoseError::UnsupportedAlgorithm)
    );
    if let Ok(exact) = registration {
        assert!(exact.identifier() == identifier);
    }

    // Non-private, unassigned integers fail before an algorithm label is made.
    let label = match iana::Algorithm::from_i64(identifier) {
        Some(assigned) => Some(RegisteredLabelWithPrivate::Assigned(assigned)),
        None if identifier < -65_536 => Some(RegisteredLabelWithPrivate::PrivateUse(identifier)),
        None => None,
    };
    let modern = label
        .as_ref()
        .map_or(Err(CoseError::UnsupportedAlgorithm), |label| {
            CoseSignatureAlgorithm::from_registered(label)
        });
    assert!(
        modern
            == expected
                .and_then(|(exact, primitive)| primitive.map(|_| exact))
                .ok_or(CoseError::UnsupportedAlgorithm)
    );
    if let Ok(exact) = modern {
        assert!(exact.crypto_algorithm().ok() == expected.and_then(|(_, primitive)| primitive));
    }

    kani::cover!(
        identifier == -7 && modern == Ok(Es256),
        "ES256 selects its exact registration"
    );
    kani::cover!(
        identifier == -9 && modern == Ok(Esp256),
        "ESP256 selects its exact registration"
    );
    kani::cover!(
        identifier == -35 && modern.is_err(),
        "legacy curve-dependent registration is rejected"
    );
    kani::cover!(
        identifier < -65_536 && modern.is_err(),
        "private-use signature ID is rejected"
    );
    kani::cover!(
        identifier == -37 && registration == Ok(Ps256) && modern.is_err(),
        "RSA-PSS registration remains distinct from primitive dispatch"
    );
    kani::cover!(
        identifier == -257 && registration == Ok(Rs256) && modern.is_err(),
        "RSA PKCS1 registration remains distinct from primitive dispatch"
    );
    kani::cover!(label.is_none(), "unassigned numeric ID is reached");
}
