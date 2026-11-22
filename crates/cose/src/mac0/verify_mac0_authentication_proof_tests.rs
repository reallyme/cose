// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;

use zeroize::Zeroizing;

use super::super::decode::DecodedMac0;
use super::super::{CoseMac0Limits, CoseMacAlgorithm, CoseMacVerifier};
use super::{
    authorize_tag, verify_mac0_operation, CoseMac0Error, CoseMac0ErrorReason,
    CoseMac0VerifyRequest, VerifiedDetachedCoseMac0,
};

#[derive(Clone, Copy)]
struct Registration {
    algorithm: CoseMacAlgorithm,
    id: u8,
    tag_len: usize,
}

const HMAC: [Registration; 4] = [
    Registration {
        algorithm: CoseMacAlgorithm::Hmac256_64,
        id: 4,
        tag_len: 8,
    },
    Registration {
        algorithm: CoseMacAlgorithm::Hmac256_256,
        id: 5,
        tag_len: 32,
    },
    Registration {
        algorithm: CoseMacAlgorithm::Hmac384_384,
        id: 6,
        tag_len: 48,
    },
    Registration {
        algorithm: CoseMacAlgorithm::Hmac512_512,
        id: 7,
        tag_len: 64,
    },
];

#[derive(Clone, Copy)]
struct Fixture {
    registration: Registration,
    tag_len: usize,
    tag: Option<*const [u8]>,
}

std::thread_local! {
    static FIXTURE: Cell<Option<Fixture>> = const { Cell::new(None) };
}

struct Observer {
    algorithm: CoseMacAlgorithm,
    expected_structure: [u8; 14],
    accepts: bool,
    called: Cell<bool>,
}

impl CoseMacVerifier for Observer {
    fn algorithm(&self) -> CoseMacAlgorithm {
        self.algorithm
    }

    fn verify(&self, message: &[u8], tag: &[u8]) -> Result<(), CoseMac0Error> {
        let fixture = FIXTURE.get().ok_or(CoseMac0ErrorReason::InvalidStructure)?;
        assert!(!self.called.replace(true));
        assert!(core::ptr::eq(
            fixture.tag.ok_or(CoseMac0ErrorReason::InvalidStructure)?,
            tag
        ));
        assert!(tag.len() == fixture.registration.tag_len);
        assert!(message == self.expected_structure);
        if self.accepts {
            Ok(())
        } else {
            Err(CoseMac0ErrorReason::AuthenticationFailed.into())
        }
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn mac0_policy_binds_each_registration_and_exact_tag_length() {
    let registered = select_registration();
    let allowed = [select_registration().algorithm];
    let empty_allowlist: bool = kani::any();
    let allowed = if empty_allowlist {
        &[][..]
    } else {
        &allowed[..]
    };
    let key = select_registration();
    let tag_len: usize = kani::any();
    let key_queried = Cell::new(false);
    let result = authorize_tag(
        registered.algorithm,
        allowed,
        || {
            key_queried.set(true);
            key.algorithm
        },
        tag_len,
    );
    let authorized = allowed == [registered.algorithm];
    let key_matches = key.id == registered.id;
    let length_matches = tag_len == registered.tag_len;
    assert!(key_queried.get() == authorized);
    let expected = if !authorized {
        Some(CoseMac0ErrorReason::UnsupportedAlgorithm)
    } else if !key_matches {
        Some(CoseMac0ErrorReason::KeyAlgorithmMismatch)
    } else if !length_matches {
        Some(CoseMac0ErrorReason::InvalidTagLength)
    } else {
        None
    };
    assert!(result.err().map(|error| error.reason()) == expected);
    kani::cover!(
        authorized && key_matches && !length_matches,
        "wrong tag width fails before verification"
    );
    kani::cover!(
        !authorized && key_matches,
        "policy rejects a different registration"
    );
    kani::cover!(
        authorized && !key_matches && registered.id == 4 && key.id == 5,
        "the full SHA-256 registration cannot authorize its truncated sibling"
    );
    kani::cover!(
        authorized && !key_matches && registered.id == 5 && key.id == 4,
        "the truncated SHA-256 registration cannot authorize its full-width sibling"
    );
    kani::cover!(
        expected.is_none() && registered.id == 7,
        "the full SHA-512 tag is authorized"
    );
}

#[kani::proof]
#[kani::stub(
    zeroize::optimization_barrier,
    crate::verify_zeroize_barrier_proof_tests::observe_barrier
)]
#[kani::unwind(18)]
#[kani::stub(super::decode, decode_fixture)]
#[kani::stub(super::build_authentication_structure, model_mac_structure)]
fn mac0_verification_passes_exact_authenticated_bytes_and_gates_metadata() {
    let registered = HMAC[0];
    let allowed = [registered.algorithm];
    let aad: u8 = kani::any();
    let payload: u8 = kani::any();
    let accepts: bool = kani::any();
    FIXTURE.set(Some(Fixture {
        registration: registered,
        tag_len: registered.tag_len,
        tag: None,
    }));
    let request = CoseMac0VerifyRequest {
        encoded: &[0x41],
        detached_payload: &[payload],
        external_aad: &[aad],
        allowed_algorithms: &allowed,
        limits: CoseMac0Limits::default(),
    };
    let observer = Observer {
        algorithm: registered.algorithm,
        expected_structure: [
            0x84,
            0x64,
            b'M',
            b'A',
            b'C',
            b'0',
            0x43,
            0xa1,
            0x01,
            registered.id,
            0x41,
            aad,
            0x41,
            payload,
        ],
        accepts,
        called: Cell::new(false),
    };
    let result = verify_mac0_operation(request, &observer);
    assert!(observer.called.get());
    match (result, accepts) {
        (Err(error), false) => {
            assert!(error.reason() == CoseMac0ErrorReason::AuthenticationFailed);
        }
        (Ok(metadata), true) => {
            assert!(metadata.algorithm == registered.algorithm);
            assert!(metadata.protected_bytes.as_slice() == [0xa1, 0x01, registered.id]);
        }
        _ => {
            assert!(false, "only backend acceptance releases Mac0 metadata");
        }
    }
    kani::cover!(
        observer.called.get() && accepts,
        "HMAC acceptance releases the authenticated metadata"
    );
    kani::cover!(
        observer.called.get() && !accepts,
        "authentication failure propagates"
    );
}

fn select_registration() -> Registration {
    let index = usize::from(kani::any::<u8>());
    kani::assume(index < HMAC.len());
    HMAC[index]
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn decode_fixture(encoded: &[u8], max_len: usize) -> Result<DecodedMac0, CoseMac0Error> {
    assert!(encoded == [0x41] && encoded.len() <= max_len);
    let mut fixture = FIXTURE.get().ok_or(CoseMac0ErrorReason::InvalidStructure)?;
    let tag = Zeroizing::new(vec![0x72; fixture.tag_len]);
    fixture.tag = Some(tag.as_slice());
    FIXTURE.set(Some(fixture));
    Ok(DecodedMac0 {
        metadata: VerifiedDetachedCoseMac0 {
            algorithm: fixture.registration.algorithm,
            protected_bytes: Zeroizing::new(vec![0xa1, 0x01, fixture.registration.id]),
            protected_kid: None,
        },
        tag,
    })
}

// Model the small MAC_structure while checking the exact production
// inputs. Native CBOR vectors exercise the shared serializer.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn model_mac_structure(
    context: super::AuthenticationContext,
    protected: &[u8],
    aad: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, crate::CoseError> {
    assert!(matches!(context, super::AuthenticationContext::Mac0));
    let [0xa1, 0x01, algorithm] = protected else {
        return Err(crate::CoseError::InvalidFormat);
    };
    let ([aad], [payload]) = (aad, payload) else {
        return Err(crate::CoseError::InvalidFormat);
    };
    Ok(Zeroizing::new(vec![
        0x84, 0x64, b'M', b'A', b'C', b'0', 0x43, 0xa1, 0x01, *algorithm, 0x41, *aad, 0x41,
        *payload,
    ]))
}
