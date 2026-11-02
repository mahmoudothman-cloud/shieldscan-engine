#!/usr/bin/env bash
# check-toolchain.sh — fail if this box's Go or golangci-lint differs
# from what CI runs.
#
# The pins are read from .github/workflows/engine.yml, not from a copy
# kept here. CI is the thing local results are compared against, so CI's
# own pins are the right source, and reading them means this script
# cannot drift from them.
#
# Why this exists: on 2026-11-02 a snap auto-refresh moved the box from
# Go 1.26.2 / golangci-lint v2.11.4 to 1.27.3 / 2.15.0, with no commit
# anywhere. Every test and lint result after that came from a toolchain
# CI does not use, and it surfaced only because a version string
# happened to be read (DRIFT-LOG 2026-11-02). scripts/verify-versions.sh
# (api repo) compares pins against UPSTREAM releases; nothing compared
# them against what is INSTALLED. This does.
#
# Usage: scripts/check-toolchain.sh   (from the engine repo root)
# Exit:  0 all match, 1 mismatch or tool missing, 2 cannot read pins
set -euo pipefail

cd "$(dirname "$0")/.."
ci=.github/workflows/engine.yml

want_go=$(sed -nE "s/^[[:space:]]*go-version:[[:space:]]*'([^']+)'.*/\1/p" "$ci")
want_lint=$(sed -nE "s/^[[:space:]]*version:[[:space:]]*'v?([^']+)'.*/\1/p" "$ci")
want_mod=$(sed -nE 's/^go ([0-9.]+)$/\1/p' go.mod)

if [[ -z "$want_go" || -z "$want_lint" || -z "$want_mod" ]]; then
  echo "cannot read pins (go-version='$want_go' lint='$want_lint' go.mod='$want_mod')" >&2
  exit 2
fi

fail=0
report() { # name want have
  if [[ "$2" == "$3" ]]; then
    printf 'ok    %-14s %s\n' "$1" "$3"
  else
    printf 'FAIL  %-14s want %s, have %s\n' "$1" "$2" "${3:-<not installed>}"
    fail=1
  fi
}

# go.mod's go line is a MINIMUM, and a newer installed Go silently uses
# itself (GOTOOLCHAIN only ever upgrades). So go.mod cannot pin the
# compiler; it can only be kept in step with CI, which is checked here.
report "go.mod" "$want_go" "$want_mod"

have_go=$(go env GOVERSION 2>/dev/null | sed 's/^go//' || true)
report "go" "$want_go" "$have_go"

have_lint=$(golangci-lint --version 2>/dev/null | sed -nE 's/.*version v?([0-9][0-9.]*).*/\1/p' | head -1 || true)
report "golangci-lint" "$want_lint" "$have_lint"

if [[ $fail -ne 0 ]]; then
  echo
  echo "Toolchain differs from CI; test and lint results from this box are not comparable to CI's."
  echo "Install per REBUILD-RUNBOOK §3.1 rather than upgrading CI to match the box."
fi
exit $fail
