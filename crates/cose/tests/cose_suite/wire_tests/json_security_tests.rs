// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{assert_error_branch_and_reason, execute_operation_json, ExpectedErrorBranch};
use reallyme_cose::wire::CoseErrorReason;

#[test]
fn proto_json_rejects_escaped_strings_before_secret_decoding() {
    let output = execute_operation_json(r#"{"sign1Create":{"payload":"\\u0051"}}"#);
    assert_error_branch_and_reason(
        &output,
        ExpectedErrorBranch::Primitive,
        CoseErrorReason::CommonMalformedJson,
    );
}
