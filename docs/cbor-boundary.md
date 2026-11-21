# CBOR encoding and limits

Incoming CBOR is framed by `reallyme-codec`. COSE applies the selected message
or key grammar to those bytes. Protected-header contents are authenticated
exactly as received; decoding and re-encoding them changes the signed input.
Encoded byte strings and tag-24 contents require their own format validation.

| Boundary | Encoding rules |
| --- | --- |
| Generic signing COSE_Key | Definite lengths, preferred widths and recursively sorted maps |
| Peer/agreement COSE_Key | Definite lengths, preferred widths and unique maps in received order |
| Strict containers | Definite lengths and preferred integer, length, tag and float widths; maps need not be sorted |
| ISO 2021 issuer payload | Minimum argument widths for major types 0–5; received tag and float widths retained |

Primitive Sign1, Mac0, encryption and generic-key profiles reject floating-point
extensions and simple values other than Boolean or null. A float's raw bits
cannot stand in for a null payload or an EC2 Boolean selector.

Shared ceilings are 1 MiB encoded input, item depth 32, 1,024 entries per
collection, 65,536 structural nodes and 16,777,216 validation work credits.
Individual operations can impose smaller limits. Tags, containers and their
contents count toward the node limit. Compound map keys are compared by CBOR
basic-model equality, including unordered map entries; complex comparisons can
exhaust the work budget before the other ceilings. Resource exhaustion returns
a fixed limit reason.

The standalone `validate_preferred_cbor` operation checks encoding and complete
consumption. It does not validate an ISO message schema or embedded CBOR.

The `build_sign1_signature_structure` helper accepts an explicit output budget
beyond the verifier's encoded-input ceiling. Output serializers preserve that
separate contract; callers must select a budget for the complete structure.
