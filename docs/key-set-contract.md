# COSE_KeySet

`key_set_parse` and `key_set_create` process the nonempty key array defined by
RFC 9052 section 7. Supply a projection and an explicit key-type allowlist.
Limits are 64 members, 16 KiB per member, 32 parameters per map and 1 MiB per
encoded set. Input must use definite lengths and contain no trailing data.

Parsing returns each member's source index and either its key or a fixed
`CoseErrorReason`. A bad member does not hide accepted neighbours. Creation
requires every supplied member to be accepted.

`SENSITIVE_STORAGE` retains each accepted map exactly, including unsorted order,
private parameters and extensions. Treat the result as sensitive.
`PUBLIC_PARAMETERS` emits only public parameters and an optional algorithm,
removing private material, extensions, `kid`, `key_ops` and Base IV. Symmetric
keys have no public projection. Retain usage restrictions separately.

KeySet validates the structure of OKP, EC2, RSA, symmetric and AKP keys. It does
not validate mathematical key properties, trust or authorization. Import each
selected key through its operation-specific validation API before use.
