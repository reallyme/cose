# Public key export

Use `cose_key_to_public_vec` (protobuf `key_to_public_vec`) when publishing a
validated `CoseKey`. It emits the supported key family's public parameters and
optional exact algorithm. EC2 points use the compact representation. Omitted
`alg` stays omitted.

Private parameters, opaque extensions, `kid`, `key_ops` and Base IV are excluded.
The result represents public identity; it does not preserve key-use restrictions
or establish authorization. Retain those restrictions separately.

`cose_key_to_vec` serializes the complete owner, including private and extension
parameters. Treat its output as sensitive key storage, not a public export.
Opaque extensions can contain secrets even when the standard key parameters
are public.

Neither export replaces received authenticated bytes or transcript inputs.
