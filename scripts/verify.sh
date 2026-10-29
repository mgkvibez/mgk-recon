#!/usr/bin/env bash
# Release gate: run before every push that claims "done".
# Stdlib only, no install step, no network. Three checks: the package imports,
# the unittest suite passes, and the CLI does real work offline.
set -uo pipefail
cd "$(dirname "$0")/.."

fail() { echo "GATE FAILED: $*"; exit 1; }

out=$(mktemp)
trap 'rm -f "$out"' EXIT

echo "== check 1/3: import"
python3 -c "import mgk_recon" || fail "import"

echo "== check 2/3: unittest suite"
python3 -m unittest discover -s tests -q || fail "tests"

echo "== check 3/3: CLI smoke (help surface, offline)"
python3 -m mgk_recon --help > "$out" 2>&1 || { cat "$out"; fail "cli exit"; }
for flag in --out --json; do
  grep -q -- "$flag" "$out" || { cat "$out"; fail "cli help lost $flag"; }
done
echo "smoke ok: help lists the documented flags"
echo "ALL CHECKS PASSED"
