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
Depth remains bounded at item depth 32, including an empty container at the
boundary. Collection admission remains bounded at 1,024 entries. Codec's
aggregate byte, node and work ceilings apply independently.

Codec errors map into fixed protobuf-defined COSE reasons. Internal `coset`
objects and `ciborium::Value` trees are compatibility data models; incoming
bytes are decoded by codec. Every copied tree is held by a recursive wiping
owner, including partial construction and failure paths.

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
