#!/usr/bin/env bash
# Same-host baselines for Tables VI-VII of the SILMARILS-MV paper, with AVX2 post-quantum implementations.
# Run inside WSL2/Linux from the hsbench folder:   bash run_baselines.sh
set -euo pipefail
mkdir -p results
lscpu > results/host_cpu.txt
# 1) PQClean AVX2 baselines (ML-DSA-44/65, Falcon-512, SPHINCS+/SLH-DSA-128f/s), Ed25519, SILMARILS-MV (Rust)
cargo build --release --bin baselines
./target/release/baselines | tee results/baselines_avx2.jsonl
# 2) SILMARILS-MV C core (Table VI) and threshold-notarization bench, same host
if ! echo '#include <openssl/evp.h>' | gcc -E - >/dev/null 2>&1; then
  echo "Installing OpenSSL headers (sudo)..."; sudo apt-get update -qq && sudo apt-get install -y -qq libssl-dev
fi
gcc -O3 -march=native -o cbench/silmv_bench cbench/silmv_bench.c -lcrypto
gcc -O3 -march=native -o cbench/tn_bench cbench/tn_bench.c -lcrypto
./cbench/silmv_bench | tee results/c_bench_laptop.jsonl
./cbench/tn_bench | tee results/tn_bench_laptop.jsonl
echo "done: results/baselines_avx2.jsonl results/c_bench_laptop.jsonl results/tn_bench_laptop.jsonl results/host_cpu.txt"
