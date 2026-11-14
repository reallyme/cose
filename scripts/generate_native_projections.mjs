// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Buffa owns the portable messages. These declarations retain the existing
// borrowed signatures and protected receipt fields without a second field list
// in Rust. Every source field must be projected or explicitly supplied elsewhere.
export function nativeProjections(schema) {
  const messages = new Map([...schema.matchAll(/message (\w+) \{([\s\S]*?)\n\}/gu)].map(([, name, body]) => [name, new Map([...body.matchAll(/^\s*(?:(optional|repeated) )?(\w+) (\w+) = \d+;/gmu)].map(([, cardinality, type, field]) => [field, {cardinality, type}]))]));
  const types = new Map([...schema.matchAll(/\/\/ Rust (?:closed enum|closed value|payload enum|byte limits): (\w+)\n(?:message|enum) (\w+) /gu)].map(([, native, wire]) => [wire, native]));
  const projections = [];
  for (const [, json] of schema.matchAll(/^\/\/ Rust projection: (.+)$/gmu)) {
    const projection = JSON.parse(json);
    if (!/^[a-z0-9_/]+\.rs#\w+$/u.test(projection.binding) || !messages.has(projection.message)) throw new TypeError("invalid native projection binding");
    const [path, name] = projection.binding.split("#");
    const used = new Set();
    const fieldAt = (source) => {
      let message = projection.message;
      const parts = source.split(".");
      for (const [index, part] of parts.entries()) {
        const field = messages.get(message)?.get(part);
        if (field === undefined) throw new TypeError(`missing projection field ${source}`);
        if (index === parts.length - 1) return field;
        if (field.cardinality !== undefined) throw new TypeError("cannot flatten a repeated or optional message");
        message = field.type;
      }
      throw new TypeError("empty projection field");
    };
    const claim = (source) => {
      fieldAt(source);
      if ([...used].some((value) => value === source || value.startsWith(`${source}.`) || source.startsWith(`${value}.`))) throw new TypeError("duplicate projection field");
      used.add(source);
    };
    const declarations = projection.fields.map((entry) => {
      if (!/^\w+$/u.test(entry.name) || !["public", "internal"].includes(entry.visibility)) throw new TypeError("invalid projection field declaration");
      const sources = entry.sources ?? [entry.source];
      sources.forEach(claim);
      const field = fieldAt(sources[0]);
      let type;
      if (entry.view !== undefined) {
        const view = projections.find((value) => value.name === entry.view);
        const borrowed = new RegExp(`// Rust borrowed view: [a-z0-9_/]+\\.rs#${entry.view}\\b`, "u").test(schema);
        // A compound projection can only reuse a schema-declared view. Verify
        // its complete source tuple, rather than accepting an arbitrary type.
        if (view !== undefined) {
          const expected = [...view.sources].sort();
          if (projection.message !== view.message || sources.toSorted().join() !== expected.join()) throw new TypeError("projection group differs from canonical fields");
          type = `super::${entry.view}`;
        } else if (borrowed) {
          if (!projection.borrowed) throw new TypeError("borrowed projection needs a lifetime");
          type = `crate::${entry.view === "Iso18013Sign1Content" ? "iso18013" : "containers"}::${entry.view}<'a>`;
        } else if (entry.view === "PeerKeyUsage" && field.type === "CosePeerKeyPurpose" && sources.length === 2 && fieldAt(sources[1]).type === "CoseSignatureSuite") {
          type = "super::PeerKeyUsage";
        } else throw new TypeError("unknown compound projection view");
      } else {
        if (sources.length !== 1) throw new TypeError("scalar projection needs one field");
        if (entry.representation === "crypto") {
          if (field.type !== "CoseSignatureAlgorithm" || field.cardinality !== undefined) throw new TypeError("invalid primitive compatibility projection");
          type = "reallyme_crypto::core::Algorithm";
        } else if (field.type === "CoseType") {
          type = "Option<crate::policy::typ::CoseType>";
        } else if (field.type === "bytes") {
          if (entry.width !== undefined && (!Number.isSafeInteger(entry.width) || entry.width < 1 || field.cardinality === "repeated")) throw new TypeError("invalid fixed projection width");
          if (entry.width !== undefined && !schema.includes(`// Rust fixed bytes: ${projection.message}.${entry.source} = ${entry.width}`)) throw new TypeError("fixed width must be declared by the schema");
          type = projection.borrowed ? "&'a [u8]" : `zeroize::Zeroizing<${entry.width === undefined ? "Vec<u8>" : `[u8; ${entry.width}]`}>`;
          if (field.cardinality === "repeated") type = projection.borrowed ? "&'a [Vec<u8>]" : "zeroize::Zeroizing<Vec<Vec<u8>>>";
          if (field.cardinality === "optional") type = `Option<${type}>`;
        } else {
          type = field.type === "bool" ? "bool" : types.has(field.type) ? `super::${types.get(field.type)}` : undefined;
          if (type === undefined) throw new TypeError(`unmapped projection type ${field.type}`);
          if (entry.representation === "optional") {
            if (!/enum \w+ /u.test(schema) || !new RegExp(`enum ${field.type} \\{`, "u").test(schema)) throw new TypeError("optional selector projection requires an enum");
            type = `Option<${type}>`;
          } else if (entry.representation !== undefined) throw new TypeError("unknown projection representation");
          if (field.cardinality === "repeated") {
            if (!projection.borrowed) throw new TypeError("owned repeated selector requires a generated message owner");
            type = `&'a [${type}]`;
          } else if (field.cardinality !== undefined) throw new TypeError("unsupported projection cardinality");
        }
      }
      return `    /// Projection of ${projection.message}.${sources.join(", ")}.
    ${entry.visibility === "public" ? "pub" : "pub(crate)"} ${entry.name}: ${type},`;
    });
    for (const omission of projection.omit ?? []) {
      if (!omission.reason || !["argument", "proof", "detached", "group"].includes(omission.reason)) throw new TypeError("projection omission needs a contract reason");
      omission.fields.forEach(claim);
    }
    const covered = (message, prefix = "") => {
      for (const [name, field] of messages.get(message)) {
        const source = prefix + name;
        if (used.has(source)) continue;
        if ([...used].some((value) => value.startsWith(`${source}.`)) && messages.has(field.type)) covered(field.type, `${source}.`);
        else throw new TypeError(`uncovered projection field ${projection.message}.${source}`);
      }
    };
    covered(projection.message);
    if (new Set(projection.fields.map((entry) => entry.name)).size !== projection.fields.length) throw new TypeError("duplicate native projection name");
    if (projection.copy && projection.fields.some((entry) => fieldAt((entry.sources ?? [entry.source])[0]).type === "bytes")) throw new TypeError("byte owners cannot derive Copy or Debug");
    const module = name.replace(/([a-z0-9])([A-Z])/gu, "$1_$2").toLowerCase();
    const attributes = projection.copy ? "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n" : "";
    const source = `/// Native compatibility projection of the Buffa ${projection.message} contract.
${projection.non_exhaustive ? "#[must_use]\n#[non_exhaustive]\n" : ""}${attributes}pub struct ${name}${projection.borrowed ? "<'a>" : ""} {
${declarations.join("\n")}
}
${!projection.borrowed && !projection.copy ? `\nimpl zeroize::ZeroizeOnDrop for ${name} {}\n` : ""}
`;
    projections.push({name, path, module, source, message: projection.message, sources: projection.fields.flatMap((entry) => entry.sources ?? [entry.source])});
  }
  if (new Set(projections.map((value) => value.name)).size !== projections.length) throw new TypeError("duplicate native projection binding");
  return projections;
}

// Enum arms are borrowed views of canonical selector cases or oneof fields.
// Payloads may only reference declared schema fields or schema-defined ports.
export function nativeBorrowedProjections(schema) {
  const selectors = new Map([...schema.matchAll(/enum (\w+) \{([\s\S]*?)\n\}/gu)].map(([, name, body]) => [name, [...body.matchAll(/^\s*(\w+) = (-?\d+);/gmu)].filter(([, , number]) => number !== "0").map(([, value]) => value)]));
  const messages = new Map([...schema.matchAll(/message (\w+) \{([\s\S]*?)\n\}/gu)].map(([, name, body]) => [name, new Map([...body.matchAll(/^\s*(\w+) (\w+) = \d+;/gmu)].map(([, type, name]) => [name, type]))]));
  const closed = new Map([...schema.matchAll(/\/\/ Rust closed enum: (\w+)\nenum (\w+) /gu)].map(([, native, wire]) => [wire, native]));
  const ports = new Map([...schema.matchAll(/\/\/ Rust port: ([a-z0-9_/]+)\.rs#(\w+)/gu)].map(([, path, name]) => [name, path.split("/").slice(0, -1).join("::")]));
  const fieldType = (source) => {
    const [message, ...parts] = source.split(".");
    let type = message;
    for (const part of parts) {
      type = messages.get(type)?.get(part);
      if (type === undefined) throw new TypeError("missing borrowed projection field");
    }
    if (type === "bytes") return "&'a [u8]";
    if (closed.has(type)) return `super::${closed.get(type)}`;
    throw new TypeError("unsupported borrowed projection payload");
  };
  return [...schema.matchAll(/^\/\/ Rust borrowed projection: (.+)$/gmu)].map(([, json]) => {
    const projection = JSON.parse(json);
    const [path, name] = projection.binding.split("#");
    const cases = selectors.get(projection.wire) ?? [...(messages.get(projection.wire)?.keys() ?? [])];
    if (cases.length === 0 || !/^[a-z0-9_/]+\.rs#\w+$/u.test(projection.binding)) throw new TypeError("missing borrowed projection selector");
    const used = projection.variants.flatMap((value) => value.cases);
    if (new Set(used).size !== used.length || cases.toSorted().join() !== used.toSorted().join()) throw new TypeError("borrowed projection must cover every canonical alternative exactly once");
    const arms = projection.variants.map((variant) => {
      if (!/^\w+$/u.test(variant.name)) throw new TypeError("invalid borrowed variant name");
      let payload = "";
      if (variant.field !== undefined) payload = `(${fieldType(variant.field)})`;
      if (variant.port !== undefined) {
        if (!ports.has(variant.port) || payload !== "") throw new TypeError("unknown borrowed capability port");
        payload = `(&'a dyn crate::${ports.get(variant.port)}::${variant.port})`;
      }
      if (variant.fields !== undefined) {
        if (payload !== "") throw new TypeError("ambiguous borrowed projection payload");
        payload = ` {${variant.fields.map((field) => {
          if (!/^\w+$/u.test(field.name)) throw new TypeError("invalid borrowed projection field name");
          return `\n        /// Canonical ${field.source} field.\n        ${field.name}: ${fieldType(field.source)},`;
        }).join("")}\n    }`;
      }
      if (messages.has(projection.wire)) {
        const fields=variant.fields?.map((field)=>field.source) ?? [variant.field];
        const covered=(message,prefix)=>{
          for(const [name,type] of messages.get(message)) {
            const source=`${prefix}.${name}`;
            if(fields.includes(source)) continue;
            if(messages.has(type) && fields.some((field)=>field?.startsWith(`${source}.`))) covered(type,source);
            else throw new TypeError("borrowed oneof projection has an uncovered payload field");
          }
        };
        for(const name of variant.cases) {
          const source=`${projection.wire}.${name}`;
          const type=messages.get(projection.wire).get(name);
          if(fields.includes(source)) continue;
          if(messages.has(type)) covered(type,source);
          else throw new TypeError("borrowed oneof projection has an uncovered alternative");
        }
      }
      return `    /// Canonical ${projection.wire} alternative: ${variant.cases.join(", ")}.
    ${variant.name}${payload},`;
    });
    return {path, name, module: name.replace(/([a-z0-9])([A-Z])/gu, "$1_$2").toLowerCase(), source: `/// Borrowed compatibility view of the Buffa ${projection.wire} contract.
pub enum ${name}<'a> {
${arms.join("\n")}
}
`};
  });
}
