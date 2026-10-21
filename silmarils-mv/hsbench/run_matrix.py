#!/usr/bin/env python3
"""Run the HotStuff prototype (v2: per-node delay queues in the network emulator) experiment matrix and append JSON lines to results/hs_results.jsonl.

Usage:
  python3 run_matrix.py --preset quick      # ~10 min sanity run
  python3 run_matrix.py --preset full       # ~1.5-2.5 h, the numbers for the paper
  python3 run_matrix.py --preset full --only E1,E2 --reps 5

Experiments
  E1 scaling        n in {4,7,10,16,31,64,100}, all schemes, 10 ms one-way delay, 1 Gbit/s per node
  E2 bandwidth      n = 31, egress cap in {50,100,250,1000} Mbit/s
  E3 crash faults   n in {16,31}, t replicas crashed (they are leaders in their turn -> view changes)
  E4 issuance       sil-iv and mac-tn with background key-issuance traffic (--issuance auto)
  E5 delay          n = 31, one-way delay in {1,10,50} ms
  E6 threads        n = 100, tokio worker threads in {8,16,32} (emulation sensitivity)
"""
import argparse, json, os, platform, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "target", "release", "hsbench" + (".exe" if os.name == "nt" else ""))
SCHEMES = ["sil-iv", "mac-tn", "mac", "ed25519", "mldsa44", "mldsa44-a2a"]


def jobs(preset, only):
    J = []
    if preset == "cloud":   # small-host subset used for the preliminary numbers in the paper
        base = dict(batch=400, tx_size=128, duration=8, warmup=3)
        for n in [4, 10, 31]:
            for s in SCHEMES:
                J.append(dict(base, tag="E1", n=n, scheme=s, delay_ms=10, bw_mbps=1000))
        for d, bw in [(1, 1000), (50, 1000), (10, 100)]:
            for s in SCHEMES:
                J.append(dict(base, tag="E2" if bw != 1000 else "E5", n=31, scheme=s, delay_ms=d, bw_mbps=bw,
                              timeout_ms=max(1000, 40 * d)))
        return J
    full = preset == "full"
    ns = [4, 7, 10, 16, 31, 64, 100] if full else [4, 10, 31]
    dur, warm = (15, 4) if full else (5, 2)
    base = dict(batch=400, tx_size=128, delay_ms=10, bw_mbps=1000, duration=dur, warmup=warm)
    if "E1" in only:
        for n in ns:
            for s in SCHEMES:
                J.append(dict(base, tag="E1", n=n, scheme=s, pool=8 if n >= 64 else 16))
    if "E2" in only:
        for bw in ([50, 100, 250, 1000] if full else [100, 1000]):
            for s in SCHEMES:
                J.append(dict(base, tag="E2", n=31, scheme=s, bw_mbps=bw))
    if "E3" in only:
        for n in ([16, 31] if full else [16]):
            for s in SCHEMES:
                J.append(dict(base, tag="E3", n=n, scheme=s, crash=(n - 1) // 3, timeout_ms=200,
                              duration=dur * 2))
    if "E4" in only:
        for n in ([4, 10, 31, 64, 100] if full else [10, 31]):
            for s in ["sil-iv", "mac-tn"]:
                J.append(dict(base, tag="E4", n=n, scheme=s, issuance="auto", pool=8 if n >= 64 else 16))
    if "E5" in only:
        for d in ([1, 10, 50] if full else [1, 50]):
            for s in SCHEMES:
                J.append(dict(base, tag="E5", n=31, scheme=s, delay_ms=d,
                              timeout_ms=max(1000, 40 * d)))
    if "E6" in only and full:   # runtime-thread sensitivity of the colocated emulation at n = 100
        for th in [8, 16, 32]:
            for s in ["sil-iv", "mac-tn", "mldsa44", "mldsa44-a2a"]:
                J.append(dict(base, tag="E6", n=100, scheme=s, threads=th, pool=8))
    return J


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--preset", default="quick", choices=["quick", "full", "cloud"])
    ap.add_argument("--only", default="E1,E2,E3,E4,E5,E6")
    ap.add_argument("--reps", type=int, default=0, help="repetitions (default: 3 full, 1 quick)")
    ap.add_argument("--threads", type=int, default=0)
    ap.add_argument("--out", default=os.path.join(HERE, "results", "hs_results.jsonl"))
    a = ap.parse_args()
    reps = a.reps or (1 if a.preset == "quick" else 3)
    if not os.path.exists(BIN):
        sys.exit(f"binary not found: {BIN}\nbuild first:  cargo build --release")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    J = jobs(a.preset, set(a.only.split(",")))
    host = dict(host=platform.node(), machine=platform.machine(), system=platform.system(),
                cpus=os.cpu_count(), python=platform.python_version())
    print(f"{len(J)} configurations x {reps} reps; host {host}", flush=True)
    t_start = time.time()
    with open(a.out, "a") as f:
        for i, j in enumerate(J):
            for r in range(reps):
                cmd = [BIN]
                for k, v in j.items():
                    cmd += ["--" + k.replace("_", "-"), str(v)]
                if a.threads and "threads" not in j:
                    cmd += ["--threads", str(a.threads)]
                try:
                    out = subprocess.run(cmd, capture_output=True, text=True, timeout=j["duration"] + j["warmup"] + 300)
                    rec = json.loads(out.stdout.strip().splitlines()[-1])
                except Exception as e:  # keep going; record the failure
                    rec = dict(j, error=str(e)[:300])
                rec.update(rep=r, host=host, preset=a.preset)
                f.write(json.dumps(rec) + "\n"); f.flush()
                el = time.time() - t_start
                print(f"[{i + 1}/{len(J)} rep {r}] {j['tag']} n={j['n']} {j['scheme']:12s} "
                      f"tput={rec.get('tput_tx_s', float('nan')):9.0f} tx/s lat={rec.get('lat_mean_ms', float('nan')):7.1f} ms "
                      f"crypto/replica={rec.get('crypto_ms_per_replica_per_block', float('nan')):.3f} ms "
                      f"safety={rec.get('safety_ok')}  ({el / 60:.1f} min)", flush=True)
    print("done ->", a.out)


if __name__ == "__main__":
    main()
