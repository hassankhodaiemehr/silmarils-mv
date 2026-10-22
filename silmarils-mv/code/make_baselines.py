"""Converts the same-host AVX2 baselines measured by hsbench/run_baselines.sh
(hsbench/results/baselines_avx2.jsonl) into results/baselines.json, the file read by
ledger_model.py and scale_model.py and reported in the baseline table of the paper.

Usage (from code/):  python3 make_baselines.py
"""
import json, os
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', 'hsbench', 'results', 'baselines_avx2.jsonl')
DST = os.path.join(HERE, '..', 'results', 'baselines.json')
NAMES = {
    'Ed25519 (dalek)': 'Ed25519',
    'ML-DSA-44': 'ML-DSA-44',
    'ML-DSA-65': 'ML-DSA-65',
    'Falcon-512': 'Falcon-512',
    'SPHINCS+-SHA2-128f-simple (SLH-DSA-SHA2-128f parameters)': 'SLH-DSA-SHA2-128f',
    'SPHINCS+-SHA2-128s-simple (SLH-DSA-SHA2-128s parameters)': 'SLH-DSA-SHA2-128s',
}
rows = []
for line in open(SRC):
    r = json.loads(line)
    if r['scheme'] in NAMES:
        rows.append(dict(scheme=NAMES[r['scheme']], impl=r['impl'], pk=r['pk'], sig=r['sig'],
                         sign_us=r['sign_us'], verify_us=r['verify_us']))
json.dump(rows, open(DST, 'w'), indent=1)
print('wrote', os.path.normpath(DST), 'with', len(rows), 'schemes')
