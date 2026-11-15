#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

cargo fetch --locked
sha256sum Cargo.lock > "$RUNNER_TEMP/workspace-lock.sha256"
results="$RUNNER_TEMP/verification.json"
CARGO_NET_OFFLINE=true cargo kani --package reallyme-cose --lib --no-default-features --features native \
  --output-format terse -Z stubbing -Z unstable-options --harness-timeout 360s --export-json "$results" \
  2>&1 | tee "$RUNNER_TEMP/verification.log"
sha256sum --check --strict "$RUNNER_TEMP/workspace-lock.sha256"

# Kani can succeed with unreachable cover goals. Require the scenarios
# declared by every harness so a vacuous proof fails the CI lane.
jq --exit-status '
  .verification_results.results as $results
  | ($results | length > 0) and all($results[];
      .status == "Success"
      and ([.checks[] | select(.category == "cover")] as $covers
        | ($covers | length > 0) and all($covers[]; .status == "Satisfied")))
' "$results"
