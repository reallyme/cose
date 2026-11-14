// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Ownership classification is declared once at the field, beside its meaning.
// Unknown classifications fail the release check instead of defaulting public.
export function schemaScalarClassifications(schema) {
  const result = [];
  for (const [, message, body] of schema.matchAll(/message\s+(\w+)\s*\{([\s\S]*?)^\}/gmu)) {
    let comments = [];
    for (const line of body.split("\n")) {
      const field = /^\s*(?:(?:repeated|optional)\s+)?(bytes|string)\s+(\w+)\s*=/u.exec(line);
      if (field !== null) {
        const sensitivity = comments.some((comment) => comment.includes("SENSITIVE:")) ? "sensitive"
          : comments.some((comment) => comment.includes("PUBLIC:")) ? "public" : undefined;
        if (sensitivity === undefined) throw new TypeError("protobuf scalar ownership classification missing");
        result.push({ message, field: field[2], kind: field[1], sensitivity });
      }
      if (line.trimStart().startsWith("//")) comments.push(line);
      else if (line.trim() !== "") comments = [];
    }
  }
  return result;
}

// Buffa derives PartialEq conservatively. Preserve native Eq only where the
// complete schema subtree contains equality-safe scalar/message alternatives.
export function equalityExtensions(schema) {
  let text = "";
  const messages=new Map([...schema.matchAll(/message (\w+) \{([\s\S]*?)\n\}/gu)].map(([,name,body])=>[name,body]));
  const check=(name,seen=new Set())=>{
    if (seen.has(name)) return;
    seen.add(name);
    const body=messages.get(name);
    if (body===undefined) return;
    for (const [,type] of body.matchAll(/^\s*(?:(?:repeated|optional)\s+)?(\w+) \w+ = \d+/gmu)) {
      if (type==="float" || type==="double") throw new TypeError("Eq requires an equality-safe schema subtree");
      check(type,seen);
    }
  };
  for (const [,name] of schema.matchAll(/\/\/ Rust equality: (\w+)/gu)) {
    check(name);
    text+=`\nimpl ::core::cmp::Eq for ${name} {}\n`;
  }
  check("CoseType");
  return text + "\nimpl Eq for CoseType {}\nimpl Eq for cose_type::Value {}\n";
}
