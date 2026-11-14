// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_cose::api::contract;
use reallyme_cose::containers::{
    inspect_peer_key, signature_to_cose, validate_preferred_cbor, verify_container,
    AgreementEc2EncodingPolicy, AgreementKey, AgreementKeyPolicy, ContainerContent,
    ContainerLimits, ContainerPolicy, ContainerPurpose, ContainerVerifyRequest,
    CryptoAgreementKeyProvider, CryptoVerificationKey, OptionalKeyPolicy, PeerCurve, PeerKeyUsage,
    PeerPointEncoding, SignatureEncoding, SignatureSuite, VerificationSource,
};
use reallyme_cose::iso18013::{Iso18013SignatureAlgorithm, Iso18013SignatureCurve};
use zeroize::Zeroizing;

// Public scalar-one P-256 generator, exclusively synthetic fuzz material.
const PUBLIC_KEY: [u8; 33] = [
    0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96,
];

fuzz_target!(|data: &[u8]| {
    let _ = validate_preferred_cbor(data);
    let _ = inspect_peer_key(data, PeerKeyUsage::Agreement, OptionalKeyPolicy::Cose);
    for encoding in [
        AgreementEc2EncodingPolicy::FullCoordinatesOnly,
        AgreementEc2EncodingPolicy::FullOrCompressed,
    ] {
        let policy = AgreementKeyPolicy {
            allowed_curves: &[PeerCurve::P256, PeerCurve::X25519],
            optional_parameters: OptionalKeyPolicy::Cose,
            ec2_encoding: encoding,
        };
        let _ = AgreementKey::from_slice(data, policy, &CryptoAgreementKeyProvider);
        let _ = AgreementKey::from_public_key(
            PeerCurve::P256,
            data,
            PeerPointEncoding::Ec2YSign,
            policy,
            &CryptoAgreementKeyProvider,
        );
    }
    let _ = inspect_peer_key(
        data,
        PeerKeyUsage::HpkeRecipient,
        OptionalKeyPolicy::IsoPeer,
    );
    for curve in [
        Iso18013SignatureCurve::P521,
        Iso18013SignatureCurve::BrainpoolP320r1,
        Iso18013SignatureCurve::Ed448,
    ] {
        let _ = signature_to_cose(curve, SignatureEncoding::EcdsaDer, data);
    }
    let Ok(suite) = SignatureSuite::iso(
        Iso18013SignatureAlgorithm::Es256,
        Iso18013SignatureCurve::P256,
    ) else {
        return;
    };
    let Ok(key) = CryptoVerificationKey::new(suite, Zeroizing::new(PUBLIC_KEY.to_vec()), [0; 32])
    else {
        return;
    };
    for (purpose, content) in [
        (ContainerPurpose::IssuerMso, ContainerContent::Attached),
        (
            ContainerPurpose::ReaderAuthenticationAll,
            ContainerContent::Detached(data),
        ),
        (ContainerPurpose::MsoRevocation, ContainerContent::Attached),
        (ContainerPurpose::Vical, ContainerContent::Attached),
        (ContainerPurpose::Rical, ContainerContent::Attached),
    ] {
        let Ok(policy) = ContainerPolicy::try_from(&contract::CoseContainerPolicy {
            profile: contract::CoseContainerProfile::IsoEdition2Dis.into(),
            purpose: contract::CoseContainerPurpose::from(purpose).into(),
            envelope: contract::CoseEnvelopePolicy::Untagged.into(),
        }) else {
            return;
        };
        let _ = verify_container(
            ContainerVerifyRequest {
                encoded: data,
                content,
                external_aad: &[],
                policy,
                allowed_suites: &[suite],
                limits: ContainerLimits::default(),
            },
            VerificationSource::Key(&key),
        );
    }
});
