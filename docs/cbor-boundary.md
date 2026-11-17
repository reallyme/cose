# CBOR ownership and profiles

ReallyMe Codec 0.4.3 owns incoming CBOR framing, UTF-8 validation, equivalent
map-key detection, preferred argument and floating-point encoding, and bounded
traversal. COSE uses borrowed receipts from
`reallyme_codec::cbor::general`. The same implementation admits primitive
Sign1, Mac0, encryption and key inputs, and signed-container inputs.

COSE selects the profile and validates its grammar. Protected-header byte
strings remain opaque until their designated header-map admission step.
Authentication always uses their exact received contents. Unsorted unique
maps remain in received order. Tags and embedded byte strings never authorize
implicit decoding or reconstruction of authenticated content.

The primitive profile rejects floating-point extension values and simple
values outside booleans and null because the internal COSE model cannot
represent every general-CBOR value safely. Canonical COSE_Key admission
requires recursive bytewise map ordering. Public peer and agreement key
inspection accepts unsorted unique maps while retaining its algorithm,
purpose, public-material and encoding restrictions.

Strict container preflight uses preferred widths and definite lengths without
sorting maps. ISO 18013-5:2021 issuer content retains received tag and float
widths while requiring minimum argument widths for major types 0 through 5.
Both profiles use codec's basic-model map-key equality, including unordered
compound map keys, equivalent float zero signs, and NaN significands.
Container grammar retains codec's optional typed argument: floating-point
payload bits cannot represent a detached-content null or an EC2 Boolean selector.
Depth remains bounded at item depth 32, including an empty container at the
boundary. Collection admission remains bounded at 1,024 entries. Codec's
aggregate ceilings apply independently: 1 MiB of encoded input, 65,536
structural nodes and 16,777,216 validation work credits. Tags and containers
count as nodes as well as their contents. These checks precede copying into
the compatibility tree; the byte ceiling alone cannot bound its heap cost.

Map uniqueness does not require received map order or compare only key bytes.
Codec sorts a bounded index of key offsets for ordinary scalar keys, avoiding
an all-pairs comparison limit for wide text-key maps. Compound keys retain
recursive basic-model equality, including unordered map entries, as specified
in [RFC 8949 §5.6.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-5.6.1).
Complex compound-key comparisons may exhaust the independent work ceiling
before reaching an entry or node ceiling; this fails with the fixed resource
limit reason rather than disabling semantic duplicate detection.

Codec errors map into fixed protobuf-defined COSE reasons. Internal `coset`
objects and `ciborium::Value` trees are compatibility data models; incoming
bytes are decoded by codec. Every copied tree is held by a recursive wiping
owner, including partial construction and failure paths.

Native and WASM regressions cover reordered compound keys inside protected
and unprotected Mac0 extensions and both ISO payload profiles; the exact
65,536-node boundary; and unique text-key maps at 299, 300, 301 and 1,024
entries, including binary protobuf and ProtoJSON parity. A dense 1 MiB
encryption envelope exceeds the node ceiling and is rejected before an owned
tree is constructed. Native allocation counters assert that this rejection
allocates neither tree nor error storage.

## Remaining output migration prerequisite

The output side still uses the guarded `ciborium` serializer and fixed COSE
structure encoders. Replacing those requires a published codec encoder API
with a typed value-model adapter and fallible writes into a caller-owned,
pre-sized output buffer. It must preserve exact embedded spans and permit the
caller's complete output budget independently of transport admission limits.

Codec 0.4.3 exposes an owned encoder result capped at 1 MiB. COSE's public
Signature1 structure helper supports larger outputs for SSI and checks their
complete size before its sole fallible reservation. Migrating through the
current owned result would add an output allocation and impose a smaller
ceiling. The remaining serializer migration therefore depends on codec API
coverage; the architecture finding remains open for output encoding.
