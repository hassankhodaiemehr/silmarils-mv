#!/usr/bin/env python3
"""Summarize results/hs_results.jsonl: medians over repetitions -> results/hs_summary.csv,
results/hs_summary.md, and pgfplots tables results/hs_E*.dat for the paper."""
import json, os, statistics, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "results", "hs_results.jsonl")
rows = [json.loads(l) for l in open(src) if l.strip()]
rows = [r for r in rows if "error" not in r and r.get("blocks", 0) > 0]
F = ["tput_tx_s", "lat_mean_ms", "lat_p99_ms", "kib_per_replica_per_block_avg", "kib_per_replica_per_block_max",
     "crypto_ms_per_replica_per_block", "crypto_ms_per_block", "cpu_ms_per_block", "cert_lat_mean_ms", "timeouts"]
key = lambda r: (r["tag"], r["n"], r["scheme"], r.get("bw_mbps"), r.get("delay_ms"), r.get("crash", 0), r.get("threads", 0))
groups = collections.defaultdict(list)
bad = 0
for r in rows:
    groups[key(r)].append(r)
    bad += not r.get("safety_ok", True)
def med(v):
    v = [x for x in v if isinstance(x, (int, float)) and x == x]
    return statistics.median(v) if v else float("nan")
summ = []
for k, g in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][3] or 0, kv[0][4] or 0, kv[0][2])):
    d = dict(tag=k[0], n=k[1], scheme=k[2], bw_mbps=k[3], delay_ms=k[4], crash=k[5], threads=k[6], reps=len(g))
    for f in F: d[f] = med([x.get(f) for x in g])
    summ.append(d)
cols = ["tag", "n", "scheme", "bw_mbps", "delay_ms", "crash", "threads", "reps"] + F
with open(os.path.join(HERE, "results", "hs_summary.csv"), "w") as f:
    f.write(",".join(cols) + "\n")
    for d in summ: f.write(",".join(str(d[c]) for c in cols) + "\n")
with open(os.path.join(HERE, "results", "hs_summary.md"), "w") as f:
    f.write(f"safety violations: {bad} of {len(rows)} runs\n\n")
    f.write("| exp | n | scheme | bw | delay | crash | thr | tput (tx/s) | lat mean (ms) | lat p99 | KiB/replica/blk | max KiB | crypto ms/replica/blk | cert lat (ms) |\n")
    f.write("|" + "---|" * 14 + "\n")
    for d in summ:
        f.write(f"| {d['tag']} | {d['n']} | {d['scheme']} | {d['bw_mbps']} | {d['delay_ms']} | {d['crash']} | {d['threads']} | {d['tput_tx_s']:.0f} | "
                f"{d['lat_mean_ms']:.1f} | {d['lat_p99_ms']:.1f} | {d['kib_per_replica_per_block_avg']:.1f} | "
                f"{d['kib_per_replica_per_block_max']:.1f} | {d['crypto_ms_per_replica_per_block']:.3f} | {d['cert_lat_mean_ms']:.1f} |\n")
# pgfplots: one table per experiment, x = n (E1/E3/E4), bw (E2), delay (E5); columns per scheme
xs = {"E1": "n", "E3": "n", "E4": "n", "E2": "bw_mbps", "E5": "delay_ms"}
for tag, xk in xs.items():
    S = [d for d in summ if d["tag"] == tag]
    if not S: continue
    schemes = sorted({d["scheme"] for d in S})
    xvals = sorted({d[xk] for d in S})
    for metric in ["tput_tx_s", "lat_mean_ms", "crypto_ms_per_replica_per_block", "kib_per_replica_per_block_avg"]:
        fn = os.path.join(HERE, "results", f"hs_{tag}_{metric}.dat")
        with open(fn, "w") as f:
            f.write("x " + " ".join(s.replace("-", "") for s in schemes) + "\n")
            for x in xvals:
                vals = []
                for s in schemes:
                    m = [d[metric] for d in S if d[xk] == x and d["scheme"] == s]
                    vals.append(f"{m[0]:.6g}" if m and m[0] == m[0] else "nan")
                f.write(f"{x} " + " ".join(vals) + "\n")
print(open(os.path.join(HERE, "results", "hs_summary.md")).read())
