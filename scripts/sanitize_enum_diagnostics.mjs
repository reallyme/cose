// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Published ReallyMe Buffa 0.1.0 fixes cleanup-message enum policies but still
// formats numeric input in standalone enum serde errors. Preserve the existing
// fixed-diagnostic contract until the generator has an equivalent native option.
// This guard changes no fields, codecs, ownership or export implementations.
export function sanitizeEnumDiagnostics(source) {
  let replacements=0;
  const result=source.replace(
    /::serde::de::Error::custom\(\s*::buffa::alloc::format!\("(enum value \{v\} out of i32 range|unknown enum value \{v32\})"\),\s*\)/gu,
    (_,diagnostic)=>{
      replacements+=1;
      return `::serde::de::Error::custom("${diagnostic.startsWith("enum")?"enum value out of i32 range":"unknown enum value"}")`;
    },
  );
  if(replacements===0 || result.includes("::buffa::alloc::format!(")) throw new TypeError("standalone enum diagnostic guard differs from the published generator");
  return result;
}
