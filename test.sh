#!/usr/bin/env bash
# Unified test runner for qkms-sdk.
#
# Usage:
#   ./test.sh          — run all tests
#   ./test.sh sigv4    — run only SigV4 unit tests
#   ./test.sh wasm     — run only wasm protocol smoke tests
#   ./test.sh build    — verify all packages compile

set -euo pipefail
cd "$(dirname "$0")"

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

pass=0
fail=0

run_section() {
  echo -e "\n${BOLD}━━━ $1 ━━━${RESET}"
}

run_test() {
  local label="$1"
  shift
  echo -n "  $label ... "
  if "$@" >/dev/null 2>&1; then
    echo -e "${GREEN}PASS${RESET}"
    pass=$((pass + 1))
  else
    echo -e "${RED}FAIL${RESET}"
    # Re-run to show output
    "$@" 2>&1 | tail -20
    fail=$((fail + 1))
  fi
}

# ---- Determine what to run ----
target="${1:-all}"

if [[ "$target" == "all" || "$target" == "build" ]]; then
  run_section "Build verification"
  run_test "pnpm build (all packages)" pnpm build
fi

if [[ "$target" == "all" || "$target" == "sigv4" ]]; then
  run_section "Unit tests: SigV4"
  run_test "SigV4 signer (AWS test vectors)" npx tsx --test packages/core/src/sigv4.test.ts
fi

if [[ "$target" == "all" || "$target" == "wasm" ]]; then
  run_section "Protocol smoke tests (wasm)"
  pushd wasm/mpc-wasm >/dev/null
  run_test "FROST EdDSA (2-of-3 DKG + sign)" node smoke-test.mjs
  run_test "BLS48-581 (2-of-3 DKG + threshold sign)" node bls-protocol-smoke-test.mjs
  run_test "BLS12-381 (2-of-3 DKG + threshold sign)" node bls12381-smoke-test.mjs
  run_test "RSA-N (Shoup partial + combine)" node rsa-smoke-test.mjs
  popd >/dev/null
fi

# ---- Summary ----
echo -e "\n${BOLD}━━━ Summary ━━━${RESET}"
total=$((pass + fail))
echo -e "  ${GREEN}$pass passed${RESET}, ${RED}$fail failed${RESET} out of $total"

if [[ $fail -gt 0 ]]; then
  exit 1
fi
