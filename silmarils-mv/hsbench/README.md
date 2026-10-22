# hsbench: HotStuff prototype for SILMARILS-MV

A chained-HotStuff implementation (3-chain commit, round-robin leaders, timeout-based view change) with pluggable vote authentication. All cryptography is real; replicas run as tokio tasks on one machine and talk over an emulated network. The emulation applies a per-link one-way delay and a per-node egress bandwidth cap, and charges every message its exact wire size.

| scheme        | topology   | votes / QC                                                          |
|---------------|------------|---------------------------------------------------------------------|
| `sil-iv`      | star       | SILMARILS-MV individual votes (ω = t), aggregated QC (ω+1 elements + bitmap) |
| `ed25519`     | star       | Ed25519 votes, QC = 2t+1 signatures (not post-quantum)              |
| `mldsa44`     | star       | ML-DSA-44 (PQClean, AVX2 on Linux), QC = 2t+1 signatures            |
| `mldsa44-a2a` | all-to-all | ML-DSA-44 votes broadcast to everyone; each replica forms the QC locally |
| `mac`         | all-to-all | MACs over F_{2^255−19} with fixed per-pair keys (timing model of the paper's polynomial Wegman–Carter MAC); no transferable certificate |
| `mac-tn`      | all-to-all | `mac` + SILMARILS-MV threshold notarization: on commit, every replica releases a certificate share to a rotating combiner, which interpolates and checks it and sends the 544-byte certificate to 4 external auditors |

Reported metrics, per run as one JSON line:
- throughput (tx/s);
- commit latency (mean and p99, from proposal to commit at replica 0);
- certificate latency (`mac-tn`: commit to verified at an auditor);
- KiB sent per replica per block (average and maximum);
- CPU time spent in cryptography per replica per block;
- process CPU per block;
- timeouts;
- a safety check that all honest replicas committed identical chains.

Keys are dealer-issued before the timed window. Their issuance cost is given by the paper's closed forms and can be injected as background traffic with `--issuance auto`. Signing-key indices are drawn cyclically from a pre-issued pool (`--pool`). This affects only security, not cost, and is a benchmark simplification.

## Requirements
- **Linux or WSL2 (Ubuntu) strongly recommended.** On native Windows, the ML-DSA crate builds only the portable reference code (no AVX2), and CPU-time accounting is unavailable.
- Rust stable (`curl https://sh.rustup.rs -sSf | sh`), Python 3.8+.

## Build and test
```bash
cd hsbench
cargo build --release
cargo test --release
./target/release/hsbench --n 4 --scheme mac-tn --duration 4 --delay-ms 5   # one JSON line
```

## Run the experiments
```bash
lscpu > results/host_cpu.txt            # record the hardware
python3 run_matrix.py --preset quick    # ~10 min sanity run
python3 run_matrix.py --preset full     # ~2 h: E1 scaling to n=100, E2 bandwidth, E3 crashes, E4 issuance, E5 delay
python3 summarize.py                    # -> results/hs_summary.md, hs_summary.csv, hs_E*_*.dat
```
Tips:
- Keep the laptop on AC power and close heavy applications.
- `--threads N` pins the tokio worker count.
- `--reps 5` tightens the medians.

Return `results/hs_results.jsonl`, `results/hs_summary.md` and `results/host_cpu.txt`.

## Version 2 (emulator fix)
v1 started one timer task per delayed message. With all-to-all voting at n = 100 (10^4 messages per view) on 32 runtime threads, the emulator, not the protocol, saturated the CPU: the `mac` and `mac-tn` runs spent about 1.3 s of process CPU per block, against 17-25 ms of cryptography. v2 uses one delay-queue task per node, a min-heap keyed by arrival time, with identical delivery semantics. Experiment E6 checks how sensitive the results are to the number of runtime threads.

## Prompt for Cursor
> Open the `hsbench` folder in WSL (Ubuntu). If an earlier `results/hs_results.jsonl` exists, move the whole `results/` folder to `results_v1/` first. Install Rust with rustup if `cargo` is missing. Run `cargo build --release` and `cargo test --release`. Then run `lscpu > results/host_cpu.txt`, `python3 run_matrix.py --preset full`, and `python3 summarize.py`. Do not modify the source code. When finished, report the contents of `results/hs_summary.md` and keep `results/hs_results.jsonl`.

## Caveats (stated in the paper)
- **MAC variants (`mac`, `mac-tn`).** A replica accepts a QC only after receiving 2t+1 valid MAC-authenticated votes itself (`QcBody::Local`); a proposal whose QC it has not formed locally is held pending. This keeps HotStuff's quorum-intersection argument if the MACs are unforgeable, but Byzantine liveness under selective vote delivery is not addressed. For timing, `mac_tag` derives the key from a fixed per-pair value instead of consuming one-time pads, so the prototype MACs are **not** forgery-resistant; the pad material a deployment needs (32 B per tag and endpoint) is accounted analytically in the paper. The experiments use honest and crashed replicas only; they evaluate performance, not Byzantine safety.
- **QC sizes.** `Qc::wire` charges 4 bytes per signer index in SILMARILS-MV aggregated QCs.
- **Colocation.** All replicas share one machine. Under heavy signature verification at large n, total CPU becomes the bottleneck, which no geo-distributed deployment would share. For that reason we also report CPU time spent in cryptography per replica per block, which does not depend on colocation.
