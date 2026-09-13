// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

fn sig_structure(protected: &[u8], payload: &[u8]) -> AuditResult<Vec<u8>> {
    encode_cbor(&Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

fn encode_cbor(value: &Value) -> AuditResult<Vec<u8>> {
    let mut out = Vec::new();
    into_writer(value, Cursor::new(&mut out)).map_err(|_| general(AuditReason::CborEncode))?;
    Ok(out)
}

fn map_get(map: &[(Value, Value)], label: i64) -> Option<&Value> {
    map.iter()
        .find(|(key, _)| matches!(key, Value::Integer(integer) if integer_eq(*integer, label)))
        .map(|(_, value)| value)
}

fn integer_matches(value: &Value, expected: i64) -> bool {
    matches!(value, Value::Integer(integer) if integer_eq(*integer, expected))
}

fn integer_eq(integer: ciborium::value::Integer, expected: i64) -> bool {
    i128::from(integer) == i128::from(expected)
}

fn decode_hex(input: &str) -> AuditResult<Vec<u8>> {
    hex::decode(input).map_err(|_| general(AuditReason::Hex))
}

fn fixed_32(bytes: &[u8], reason: AuditReason) -> AuditResult<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).map_err(|_| general(reason))
}

fn multicodec_varint(code: u64) -> AuditResult<Vec<u8>> {
    let mut value = code;
    let mut out = Vec::new();
    loop {
        let low = value & 0x7f;
        let mut byte = u8::try_from(low).map_err(|_| general(AuditReason::IntegerConversion))?;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return Ok(out);
        }
    }
}

fn ensure(condition: bool, reason: AuditReason) -> AuditResult<()> {
    if condition {
        Ok(())
    } else {
        Err(general(reason))
    }
}

fn general(reason: AuditReason) -> AuditError {
    AuditError {
        context: AuditContext::General,
        reason,
    }
}

fn manifest_error(reason: AuditReason) -> AuditError {
    AuditError {
        context: AuditContext::Manifest,
        reason,
    }
}

fn attach_case(error: AuditError, id: &str) -> AuditError {
    AuditError {
        context: match error.context {
            AuditContext::Manifest => AuditContext::Manifest,
            AuditContext::General | AuditContext::Case(_) => {
                AuditContext::Case(CaseId::from_str(id))
            }
        },
        reason: error.reason,
    }
}

#[cfg(test)]
mod verify_signature_tests;
