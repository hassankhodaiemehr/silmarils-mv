"""Regenerates paper/data_attacks.dat (Monte-Carlo validation figure) from results/attacks.json and
results/attacks_va.json, and paper/data_micro.dat (core microbenchmarks, the data of the
microbenchmark table) from results/c_bench.jsonl.

Usage (from code/):  python3 make_figure_data.py
"""
import json, os
HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, '..', 'results'); PAPER = os.path.join(HERE, '..', 'paper')
os.makedirs(PAPER, exist_ok=True)

td = {(r['q'], r['omega'], r['psi']): r for r in json.load(open(os.path.join(RES, 'attacks.json')))}
va = {(r['q'], r['omega'], r['psi']): r for r in json.load(open(os.path.join(RES, 'attacks_va.json')))}
with open(os.path.join(PAPER, 'data_attacks.dat'), 'w') as f:
    f.write('q omega psi F1va R1va F1td R1td T1 T2 bF bR\n')
    for k in sorted(va):
        a, b = va[k], td[k]
        f.write('%d %d %d %.6f %.6f %.6f %.6f %.4f %.4f %.6f %.6f\n' % (
            k[0], k[1], k[2], a['F1'], a['R1'], b['F1'], b['R1'], b['T1'], b['T2'], a['bound_F1'], a['bound_R1']))

cb = {(r['omega'], r['psi']): r for r in map(json.loads, open(os.path.join(RES, 'c_bench.jsonl'))) if 'omega' in r}
with open(os.path.join(PAPER, 'data_micro.dat'), 'w') as f:
    f.write('omega sign1 ver1 sign16 ver16 sign64 ver64 sigB\n')
    for w in sorted({w for w, _ in cb}):
        if all((w, p) in cb for p in (1, 16, 64)):
            row = [cb[(w, p)][x] / 1000 for p in (1, 16, 64) for x in ('sign_ns', 'verify_ns')]
            f.write('%d %s %d\n' % (w, ' '.join('%.4f' % v for v in row), cb[(w, 1)]['sig_bytes']))
print('wrote paper/data_attacks.dat and paper/data_micro.dat')
