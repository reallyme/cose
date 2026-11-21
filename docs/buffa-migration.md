# Protobuf generation

The checked-in bindings are generated from `cose.proto` with Buf and ReallyMe
Buffa. `buf.gen.yaml` configures cleanup, guarded byte/string fields, strict
JSON and native enum adapters. Do not edit generated Rust.

| Tool or dependency | Current pin |
| --- | --- |
| Rust | 1.100.0 |
| Buf | 1.75.0 |
| Buffa runtime | 0.1.3 |
| Buffa generator and packaging plugins | 0.1.3 |

Cleanup-enabled messages use `GuardedOwnedView::<FooView<'static>>` with explicit
`DecodeOptions`, accessing fields through `owner.view()`. The owner wipes its
backing storage on drop.

After installing the pinned generators, run from the repository root:

```sh
node scripts/generate_cose_contract.mjs
node scripts/run_pinned_release_readiness.mjs --generated-freshness
```

The driver formats Buffa output and places native enum adapters in the core
crate. Separate schema-derived companions supply native record projections,
checked limits, constants and compatibility aliases. They do not patch Buffa's
cleanup or JSON implementations.

Generated cleanup does not erase caller input, JSON parser storage or serialized
copies. Keep sensitive transport buffers under explicit wipe owners. Use
`GuardedOwnedView` when a view needs private backing storage that wipes on drop.
