# SILMARILS Simulation Package

Electronic supplementary material for the performance evaluation
(Section 9) of the SILMARILS IACR Communications in Cryptology paper.

This package reproduces the authentication-workload model, measured
post-quantum (PQ) CPU timings, and the numeric inputs consumed by
Tables `tab:pq-timing-measured`, `tab:sim-params`, `tab:3party-ic-bytes`
and Figures `fig:perf-tps`, `fig:perf-bandwidth` in the paper.

It is a self-contained analytic simulator (Python 3). It is **not** a
production ledger implementation.

## Hardware used for reported PQ timings

The included file `output/pq_hardware_benchmark.json` records the
author measurements used in the paper:

| Field | Value |
|-------|--------|
| CPU | 13th Gen Intel Core i9-13900HX |
| OS | Windows 11 (build 26200) |
| Python | 3.12.9 |
| Backend | `pqcrypto` 0.4.0 (PQClean `clean` reference code) |
| Measured | 2026-07-08 |
| Message length | 39 bytes |

Schemes timed: Dilithium-2 (ML-DSA-44), Falcon-512, SPHINCS+-128f,
SPHINCS+-128s. Means are over independent sign / verify / paired loops
(`time.perf_counter`). SPHINCS+ uses reduced iteration counts because
the reference implementation is slow (see notes in the JSON).

## Prerequisites

- Python 3.10+ (3.12 recommended; matches the reported platform)
- `pip`

Install dependencies:

```bash
cd silmarils-simulation   # or: cd simulation
pip install -r requirements.txt
```

`pqcrypto` is required only if you re-run the hardware microbenchmark.
Regenerating paper figures from the shipped JSON needs no extra packages
beyond the Python standard library.

## Step-by-step reproduction

### 1. Install dependencies (optional if using shipped timings)

```bash
pip install -r requirements.txt
```

### 2. PQ hardware microbenchmark (optional)

To re-measure PQ latencies on **your** machine:

```bash
python benchmark_pq_hardware.py
```

This overwrites `output/pq_hardware_benchmark.json`.
SPHINCS+-128s signing is very slow (minutes on typical CPUs).

To reproduce the paper numbers exactly, **skip this step** and keep the
included JSON.

### 3. Generate paper results

```bash
python generate_paper_results.py
```

Writes:

| Output | Role |
|--------|------|
| `output/paper_results.json` | Full numeric report (artifacts, TPS, curves) |
| `output/figure_coordinates.tex` | `\Sim...` macros for the paper build |

### 4. Mapping to the paper

| Artifact / script | Paper element |
|-------------------|---------------|
| `pq_hardware_benchmark.json` | Table `tab:pq-timing-measured` |
| TPS macros (`\SimTpsCpu*`, `\SimTpsBw*`, `\SimTpsComb*`) | Figure `fig:perf-tps` |
| Workload log macros (`\Sim*WorkloadLog`) | Figure `fig:perf-bandwidth` |
| `\SimRelayBytesTx`, relay KiB macros | Table `tab:3party-ic-bytes`, relay curves |
| `\SimSilBytesBlock`, `\SimDilBytesBlock`, `\SimSizeRatio` | Inline results in Section 9 |

Default ledger parameters (validators *v*=7, 500 txs/block, 30 s
blocks, etc.) match Table `tab:sim-params`.

## Module layout

| File | Role |
|------|------|
| `constants.py` | Security parameter *k*=256, ledger defaults, PQ sizes |
| `silmarils_core.py` | Two-party SILMARILS reference (sign / verify / audit) |
| `two_party_ledger.py` | Direct signer–validator auth bytes and TPS model |
| `three_party_relay.py` | Mempool-relay (IC) wire-byte model |
| `pq_benchmarks.py` | Loads hardware JSON only (no literature cycle fallback) |
| `benchmark_pq_hardware.py` | Local PQClean timing via `pqcrypto` |
| `generate_paper_results.py` | End-to-end report + LaTeX coordinate dump |
| `output/` | Measured timings and regenerated figure inputs |

## Hardware-only PQ timing policy

The TPS model in `two_party_ledger.py` / `pq_benchmarks.py` reads
**only** `output/pq_hardware_benchmark.json`.

There is **no** fallback to published cycle counts or literature tables.
If the JSON is missing or incomplete, `generate_paper_results.py` exits
with an explicit error. This matches the paper statement that
Table `tab:pq-timing-measured` is the sole PQ CPU timing source.

## Expected runtime

| Step | Typical time |
|------|----------------|
| `generate_paper_results.py` (shipped JSON) | a few seconds |
| Dilithium-2 / Falcon-512 microbenchmark | under a minute |
| SPHINCS+-128f microbenchmark | a few minutes |
| SPHINCS+-128s microbenchmark | tens of minutes |

SILMARILS reference timings inside `generate_paper_results.py` use
at least 200 paired sign/verify operations and finish quickly.

## License and citation

This simulation package is released as electronic supplementary material
accompanying the SILMARILS paper. Please cite the paper when using these
scripts or the measured timing data.

The `pqcrypto` dependency redistributes PQClean reference
implementations under their respective upstream licenses; see the
`pqcrypto` package documentation.
