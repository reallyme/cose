# ML-KEM private context limit

The ReallyMe ML-KEM profile accepts at most 65,483 bytes of `SuppPrivInfo`.
This is independent of plaintext and AAD limits and applies to direct and
key-wrap encryption and decryption. Larger values return
`COMMON_RESOURCE_LIMIT_EXCEEDED` before KEM processing.

The bound leaves 53 bytes for the encoded KDF context within crypto's
65,536-byte KMAC context ceiling. Absent and present-empty `SuppPrivInfo`
produce distinct contexts; supply the same presence and bytes for decryption.
The KDF uses the exact recipient protected-header bytes.
