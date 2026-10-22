# SILMARILS-MV: code, simulators and data

This directory holds the artifact for

> K. Bagheri, H. Khodaiemehr and C. Feng, "SILMARILS-MV: Information-Theoretically Secure Multi-Verifier Signatures with Dealer-Free Key Issuance and Linear Aggregation for Permissioned Blockchains", submitted to IEEE Transactions on Information Forensics and Security, 2026 (full version on arXiv, forthcoming).

SILMARILS-MV is a multi-verifier, unconditionally secure signature: a signature is the vector α = A·e(m), and each verifier holds a secret functional c_i = Γᵀλ(x_i) derived from virtual anchors Γ that no party learns. On top of the core scheme, the paper describes:
- dealer-free key issuance by the validator committee;
- aggregated quorum certificates;
- threshold notarization (TN), in which the committee itself signs and certificates have constant size;
- arbiter-verified keys with batch arbitration;
- retroactive enrollment and robust redistribution.

Section and table numbers below refer to the full version.

## Contents

| Path | What it is | Paper |
|---|---|---|
| `code/fe25519.h`, `code/silmv_bench.c` | C core over F_{2^255−19} and its microbenchmark | Sec. IX-B, Tables VI and VII |
| `code/tn_bench.c` | Threshold notarization: share, combine, fast decoder, certificate verification | Sec. IX-D |
| `code/silmv.py` | Python reference implementation (self-test on run) | Sec. IV |
| `code/dki_va.py`, `code/dki_sim.py` | Issuance simulators, with and without virtual anchors; they check the measured cost against the closed forms | Sec. VI |
| `code/attacks.py`, `code/attacks_va.py`, `code/attacks_va_tight.py` | Monte-Carlo validation of the bounds over small fields | Sec. IX-F |
| `code/batch_check.py` | Exhaustive check of batch arbitration (Lemma 4) over F_3, F_5 and F_7 | Sec. VIII-C, IX-D |
| `code/tn_sim.py` | End-to-end simulation of Π_TN with Byzantine members, retroactive enrollment, redistribution, batch arbitration, and the TN forgery experiment (`TNQ=257`, `TNQ=101`) | Sec. VIII, IX-D |
| `code/ledger_model.py` | Individual-vote ledger model; writes `data_ledger.dat`, `data_party.dat` | Sec. IX-C |
| `code/scale_model.py` | Analytic normal-case scalability model up to n = 1000; writes `data_scale.dat` | Sec. IX-D |
| `code/make_baselines.py` | Converts the AVX2 baselines of `hsbench/run_baselines.sh` into `results/baselines.json` | Table VII |
| `code/make_figure_data.py` | Writes `data_attacks.dat` and `data_micro.dat` from `results/` | Fig. 8, Table VI |
| `code/bench_baselines.py`, `code/ed_bench.c` | Earlier portable baselines (Python bindings, OpenSSL); superseded, kept for reference | — |
| `hsbench/` | Rust/tokio chained-HotStuff prototype with real cryptography over an emulated network; see `hsbench/README.md` | Sec. IX-E |
| `results/` | The measurements the paper is built from | all |
| `results/laptop/` | Raw measurements from the evaluation host | all |
| `results/cloud_2vcpu/` | Superseded measurements from a 2-vCPU cloud host, for reference only | — |

The model scripts write their `.dat` files to `../paper/`, which they create if it is missing.

## Requirements
- **Python:** Python 3.10 or later. All scripts use only the standard library, except `bench_baselines.py`.
- **C:** GCC or Clang, plus the OpenSSL headers and `libcrypto` (`libssl-dev`), which the code uses for SHA3-256.
- **Rust:** a stable toolchain, for `hsbench/`.

## Reproduce
All timings in the paper were measured on an Intel Core i9-13900HX under WSL2 (Ubuntu), with GCC 15.2 and Rust 1.99.

```
cd code
gcc -O3 -march=native -o silmv_bench silmv_bench.c -lcrypto && ./silmv_bench > ../results/c_bench.jsonl
gcc -O3 -march=native -o tn_bench tn_bench.c -lcrypto && ./tn_bench > ../results/tn_bench.jsonl
python3 silmv.py                                  # self-test
python3 dki_va.py; python3 dki_sim.py
python3 attacks.py 40000; python3 attacks_va.py 40000; python3 attacks_va_tight.py
python3 batch_check.py                            # -> results/batch_check.json
python3 tn_sim.py; TNQ=257 python3 tn_sim.py 20000; TNQ=101 python3 tn_sim.py 20000

cd ../hsbench
bash run_baselines.sh                             # AVX2 baselines -> hsbench/results/baselines_avx2.jsonl
cargo build --release && python3 run_matrix.py --preset full && python3 summarize.py

cd ../code
python3 make_baselines.py                         # -> results/baselines.json
python3 make_figure_data.py                       # -> paper/data_attacks.dat, data_micro.dat
python3 ledger_model.py                           # -> results/ledger.json, paper/data_ledger.dat, data_party.dat
python3 scale_model.py                            # -> results/scale.json, paper/data_scale.dat
```

The model scripts are deterministic given `results/`. The simulators draw fresh randomness: Monte-Carlo rates vary within their standard errors, and `tn_sim.py` may take the optimistic or the decoding path in a different run. The paper's statements (all certificates valid, at most one decoding per run, issuance cost within 0.8% of the formula) hold in every run.

## Scope and limitations
- **Security parameters:** the Monte-Carlo experiments use small fields (q ≤ 257) so that forgery rates can be measured. They support the bounds but do not prove them.
- **MAC variants in `hsbench`:** the `mac` and `mac-tn` variants derive MAC keys from fixed per-pair values. They are a timing model of the polynomial Wegman–Carter MAC analyzed in the paper, not a forgery-resistant implementation.
- **Fault model in `hsbench`:** the experiments use honest and crashed replicas only. They measure performance, not Byzantine safety.
- **Scalability figures:** the results up to n = 1000 come from an analytic normal-case model.

## Citation
Until the paper is published, please cite the preprint (the arXiv identifier will be added here). For the original SILMARILS framework, see `../silmarils/` and arXiv:2605.03230.

## License
MIT, see `../LICENSE`.
