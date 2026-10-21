# SILMARILS-MV — multi-validator extension

Authors: Khadijeh Bagheri, Hassan Khodaiemehr, Chen Feng.

## Why the earlier second-paper ideas were replaced
- **"New version of Silmarils" (validator–aggregator):**
  - φ: F_p → F_q^ℓ cannot be additive (p ≠ q), so the projection identities fail.
  - Each validator receives both its Shamir share and the masked value, so the mask hides nothing.
  - The aggregator only compares μ_M against a copy the signer sends it directly (a MAC/relay).
  - Validator i holds k_sig,i, so it can forge the SILMARILS core.
- **"New trial" (KR-DVS/TAKO):** TAKO is assumed to be an asymmetric "signer-only opening" primitive, which is the signature it is meant to construct. Its suggested instantiations are symmetric (keyed MAC/hash), so it is circular.

## Construction (SILMARILS-MV)
- **Signature:** α = A·e(m), which is ω+1 field elements.
- **Verifier key:** c_i = Γᵀλ(x_i), using secret "virtual anchors" Γ, with b_i = Aᵀc_i.
- **Verification:** accept iff c_iᵀα = b_iᵀe(m).
- **Security (Thm 1):** a tight bound of Q/q + 1/(q−1) against unbounded adversaries. Transfer works over unbounded hops, and signatures aggregate into QCs.
- **Key issuance (Sec. VI):** a committee MPC with t < n/3 and no broadcast channel, plus a committee arbiter for slashing.
- **Paper storyline:** "one property, three uses". Linearity in the verifier key gives issuance, linearity in the signature gives aggregation, and linearity in the signing key gives threshold notarization.

## Scaling to large committees (Sec. VIII)
- **Threshold notarization (TN):** the committee holds A_k in degree-t shares and signs as one signer. Members release A_k(η_j)e(m) only for decided values. Certificates are 32(ω+1) B for any n, and per-validator issuance cost is bounded independently of n (Thm 4: soundness, uniqueness, robustness).
- **Arbiter-verified keys (ω = 0):** 32-byte client signatures, batch-checked with one multiplication per block (Lemma 4).
- **Membership:** retroactive verifier enrollment (Prop. 3) and robust redistribution for membership change and proactive refresh (Lemma 5).
- **Linear-communication variant:** for t < n/5 (Remark 8, sketched).
- **Results at n = 1000:**
  - 71 KiB per validator per block, against 1.5 MiB for ML-DSA-44 star.
  - The busiest party handles 636 KiB, against 1.5 GiB.
  - Certificates are 544 B and verify in 2.4 µs.

## HotStuff prototype (Sec. IX, Table IX, Fig. 7)
`hsbench/` is a Rust/tokio chained-HotStuff prototype with real cryptography over an emulated network. The schemes are sil-iv, mac, mac-tn, ed25519, mldsa44 and mldsa44-a2a. The full matrix had 354 runs and 0 safety violations. See `hsbench/README.md`.

## Results folders
- `results/*.json, *.jsonl`: the files the paper is built from. CPU timings come from the laptop.
- `results/laptop/`: raw laptop measurements, i.e. the AVX2 baselines, C microbenchmarks, TN benchmark, HotStuff runs and `host_cpu.txt`.
- `results/cloud_2vcpu/`: superseded measurements from a 2-vCPU cloud host, kept for reference only.

## Reproduce
All timings in the paper are from an Intel i9-13900HX (24 cores, 32 threads) under WSL2, with GCC 15.2 and Rust 1.99.
```
cd code
gcc -O3 -march=native -o silmv_bench silmv_bench.c -lcrypto && ./silmv_bench > ../results/c_bench.jsonl
gcc -O3 -march=native -o tn_bench tn_bench.c -lcrypto && ./tn_bench > ../results/tn_bench.jsonl
python3 dki_va.py; python3 dki_sim.py
python3 attacks.py 40000; python3 attacks_va.py 40000; python3 attacks_va_tight.py
python3 tn_sim.py; TNQ=257 python3 tn_sim.py 20000; TNQ=101 python3 tn_sim.py 20000
python3 ledger_model.py         # regenerates paper/data_ledger.dat, data_party.dat
python3 scale_model.py          # regenerates paper/data_scale.dat

cd ../hsbench
./run_baselines.sh              # AVX2 PQClean baselines (ML-DSA, Falcon, SLH-DSA) + Ed25519 -> results/baselines.json
cargo build --release && python3 run_matrix.py --preset full && python3 summarize.py
```
