// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::Message;

use super::{from_result, validate_for_request};
use crate::wire::{
    cose_operation_request::Operation, CoseOperationRequest, CoseOperationResult,
    CoseOperationResultBranch as ResultBranch,
};

// The matches are exhaustive over both generated oneofs. Each case builds
// its own zero-value messages because this check concerns the routing tags.
macro_rules! routing_fixtures {
    ($($field:literal => $route:ident),+ $(,)?) => {
        fn fixture_pairs() -> [(u32, Operation, ResultBranch); [$($field),+].len()] {
            [$(($field, Operation::$route(Box::default()), ResultBranch::$route(Box::default()))),+]
        }

        fn request_field(operation: &Operation) -> u32 {
            match operation { $(Operation::$route(_) => $field),+ }
        }

        fn result_field(result: &ResultBranch) -> u32 {
            match result { $(ResultBranch::$route(_) => $field),+ }
        }
    };
}

// Allocated request and result fields from the protobuf contract.
routing_fixtures! {
    1000 => Sign1Create,
    1001 => Sign1CreateDetached,
    1002 => Sign1Verify,
    1003 => Sign1VerifyDetached,
    1004 => IsoSign1Verify,
    1005 => ContainerVerify,
    1006 => ContainerSign,
    1010 => SignatureToCose,
    1011 => SignatureToDer,
    1012 => SignatureValidate,
    1013 => SignatureSuiteInfo,
    1014 => Sign1CreateProfile,
    1015 => Sign1CreateDetachedProfile,
    1016 => Sign1VerifyProfile,
    1017 => Sign1VerifyX5chain,
    1018 => Sign1SignatureStructure,
    2000 => KeyFromPublicBytes,
    2001 => KeyFromPrivateBytes,
    2002 => KeyParse,
    2003 => KeyToPublicBytes,
    2004 => KeyToPrivateBytes,
    2005 => KeyDerivePublicKid,
    2006 => KeyToMultikey,
    2007 => MultikeyToCoseKey,
    2008 => AgreementKeyCreate,
    2009 => AgreementKeyParse,
    2010 => PeerKeyInspect,
    2011 => PeerKeyValidate,
    2012 => VerificationKeyImport,
    3000 => MlKemEncryptDirect,
    3001 => MlKemEncryptKeyWrap,
    3002 => MlKemDecrypt,
    4000 => Mac0VerifyDetached,
    5000 => PreferredCborValidate,
    5001 => ContractInfo,
}

#[test]
fn successful_response_requires_the_matching_protobuf_variant_for_every_route() {
    let pairs = fixture_pairs();
    for (id, request, result) in &pairs {
        assert_eq!(request_field(request), *id);
        assert_eq!(result_field(result), *id);
        let input = CoseOperationRequest {
            operation: Some(request.clone()),
        };
        let output = CoseOperationResult {
            result: Some(result.clone()),
        };
        assert_eq!(encoded_field_number(&input.encode_to_vec()), Some(*id));
        assert_eq!(encoded_field_number(&output.encode_to_vec()), Some(*id));
    }

    for (request_id, request, _) in &pairs {
        let request = CoseOperationRequest {
            operation: Some(request.clone()),
        };
        for (result_id, _, result) in &pairs {
            let encoded_result = CoseOperationResult {
                result: Some(result.clone()),
            };
            let actual = validate_for_request(&request, &from_result(Ok(encoded_result)));
            assert_eq!(
                actual.is_ok(),
                request_id == result_id,
                "request {request_id} and result {result_id}"
            );
        }
        assert!(
            validate_for_request(&request, &from_result(Ok(CoseOperationResult::default())))
                .is_err()
        );
    }
    for (_, _, result) in pairs {
        let response = from_result(Ok(CoseOperationResult {
            result: Some(result),
        }));
        assert!(validate_for_request(&CoseOperationRequest::default(), &response).is_err());
    }
}

// Decode the first protobuf key independently of the generated oneof code.
// Every message branch uses wire type 2 for its length-delimited payload.
fn encoded_field_number(bytes: &[u8]) -> Option<u32> {
    let mut key = 0_u32;
    for (byte, shift) in bytes.iter().zip([0, 7, 14, 21, 28]) {
        key |= u32::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return (key & 7 == 2).then_some(key >> 3);
        }
    }
    None
}
