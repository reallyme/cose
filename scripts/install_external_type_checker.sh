#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

upstream_commit="61d284da26e8bbaca386a5b9f34bee30e82aaa0e"
upstream_version="0.5.0"

if [[ $# -ne 1 || -z "$1" ]]; then
  printf '%s\n' 'usage: install_external_type_checker.sh INSTALL_ROOT' >&2
  exit 2
fi
if [[ "${CARGO_CHECK_EXTERNAL_TYPES_VERSION:-$upstream_version}" != "$upstream_version" ]]; then
  printf '%s\n' 'external-type checker version does not match the reviewed source' >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "$script_dir/.." && pwd -P)"
patch_path="$repository_root/tools/external-type-checker-rustdoc61.patch"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-external-types.XXXXXXXX")"
trap 'rm -rf -- "$temporary_root"' EXIT

# The published 0.5.0 checker understands rustdoc JSON 57. This reviewed patch
# updates its schema to JSON 61 while retaining the upstream exposure analysis.
git clone --quiet --depth 1 --branch "v$upstream_version" \
  https://github.com/awslabs/cargo-check-external-types.git "$temporary_root/source"
actual_commit="$(git -C "$temporary_root/source" rev-parse HEAD)"
if [[ "$actual_commit" != "$upstream_commit" ]]; then
  printf '%s\n' 'external-type checker source does not match the reviewed commit' >&2
  exit 1
fi
git -C "$temporary_root/source" apply --unidiff-zero --check "$patch_path"
git -C "$temporary_root/source" apply --unidiff-zero "$patch_path"
cargo +1.99.0 install --locked --force --path "$temporary_root/source" --root "$1"
