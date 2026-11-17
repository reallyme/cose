// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Read destinations only. Buffa validates the typed options and generates all
// enum bodies, conversions and callback alternatives from the descriptors.
export function nativeAdapterBindings(schema) {
  const bindings = [...schema.matchAll(/^  (selectors|payloads|borrowed) \{\n    file: "([a-z0-9_]+\.rs)"\n    name: "(\w+)"/gmu)].map(([, kind, file, name]) => {
    const declaration = new RegExp(`// Rust (?:closed enum|payload enum): ${name}\\nenum \\w+ \\{([\\s\\S]*?)\\n\\}`, "u").exec(schema);
    const borrowed = new RegExp(`// Rust borrowed view: ([a-z0-9_/]+\\.rs)#${name}\\b`, "u").exec(schema);
    if ((kind === "borrowed" ? borrowed : declaration) === null) throw new TypeError("native adapter needs its schema binding");
    return {kind, file, name, module: file.slice(0, -3), path: borrowed?.[1], core: declaration?.[1].includes("Rust availability: core") ?? false};
  });
  const count = [...schema.matchAll(/^  (?:selectors|payloads|borrowed) \{/gmu)].length;
  if (count === 0 || count !== bindings.length || new Set(bindings.map(value => value.file)).size !== count) throw new TypeError("incomplete native adapter destinations");
  return bindings;
}
