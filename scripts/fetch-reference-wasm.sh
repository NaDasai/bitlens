#!/usr/bin/env bash
# Downloads public GitHub builds of three real mainnet contracts, for scanning
# offline with `npm run scan -- --wasm <file>` (no RPC needed).
# NOTE: these are the projects' published builds, not necessarily byte-identical
# to what is deployed on chain today. For the deployed bytes, scan the account id.
set -euo pipefail
OUT="${1:-fixtures/reference}"
mkdir -p "$OUT"
curl -fsSL -o "$OUT/wrap.near.wasm" https://raw.githubusercontent.com/near/core-contracts/master/w-near/res/w_near.wasm
curl -fsSL -o "$OUT/aurora.wasm" https://github.com/aurora-is-near/aurora-engine/releases/download/3.9.2/aurora-mainnet.wasm
curl -fsSL -o "$OUT/token.sweat.wasm" https://raw.githubusercontent.com/sweatco/sweat-near/main/res/contract.wasm
ls -l "$OUT"
