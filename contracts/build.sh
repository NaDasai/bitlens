#!/usr/bin/env bash
# Build the four demo contracts to contracts/res/*.wasm (committed, so the
# rest of NEAR X-Ray runs without cargo-near). Needs cargo-near 0.22 and
# Rust 1.95.0 with wasm32-unknown-unknown (see rust-toolchain.toml).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p res
flags="RUSTFLAGS=-C link-arg=-s --remap-path-prefix=$HOME=/build --remap-path-prefix=$HOME/.cargo/registry/src=/cargo"
for c in clean_vault risky_vault vulnerable_vault yield_escrow; do
  cargo near build non-reproducible-wasm --manifest-path "$c/Cargo.toml" --no-abi --locked --env "$flags" --out-dir res
done
ls -l res/*.wasm
