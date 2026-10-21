"""Baseline signature timings on the same host (PQClean 'clean' C via pqcrypto 0.4.0; Ed25519 via OpenSSL)."""
import sys, time, json, os, importlib, statistics
sys.path.insert(0, '/tmp/pq04x')
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
msg = os.urandom(128)

def bench(fn, reps):
    best = []
    for _ in range(5):
        t = time.perf_counter()
        for _ in range(reps): fn()
        best.append((time.perf_counter() - t) / reps)
    return statistics.median(best) * 1e6

res = []
sk = Ed25519PrivateKey.generate(); pk = sk.public_key(); s = sk.sign(msg)
res.append(dict(scheme="Ed25519 (OpenSSL)", pk=32, sig=64, sign_us=bench(lambda: sk.sign(msg), 4000),
                verify_us=bench(lambda: pk.verify(s, msg), 4000)))
for name, label, reps in [("ml_dsa_44", "ML-DSA-44", 600), ("ml_dsa_65", "ML-DSA-65", 400),
                          ("falcon_512", "Falcon-512", 200), ("sphincs_sha2_128f_simple", "SLH-DSA-SHA2-128f", 6),
                          ("sphincs_sha2_128s_simple", "SLH-DSA-SHA2-128s", 1)]:
    m = importlib.import_module("pqcrypto.sign." + name)
    pk_, sk_ = m.generate_keypair()
    sg = m.sign(sk_, msg)
    r = dict(scheme=label, pk=len(pk_), sig=len(sg))
    r["sign_us"] = bench(lambda: m.sign(sk_, msg), reps)
    r["verify_us"] = bench(lambda: m.verify(pk_, msg, sg), max(reps * 5, 20) if "SLH" not in label else 50)
    res.append(r); print(json.dumps(r)); sys.stdout.flush()
json.dump(res, open('/home/claude/silmv/results/baselines.json', 'w'), indent=1)
print(json.dumps(res[0]))
