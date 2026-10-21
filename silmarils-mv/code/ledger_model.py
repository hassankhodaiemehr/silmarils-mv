"""Ledger-level model for a HotStuff/PBFT-style committee, n = 3t+1, omega = t, psi = 16.
Per block: n votes to the leader, QC of 2t+1 votes + 1 proposal signature broadcast to n-1 validators.
Offline (key issuance) cost for SILMARILS-MV: VA-DKI exact element count (validated by dki_va.py) and
trusted-dealer (TD) delivery-only cost. Writes pgfplots tables and JSON."""
import json
B = {r['scheme']: r for r in json.load(open('../results/baselines.json'))}
cb = [json.loads(l) for l in open('../results/c_bench.jsonl') if '"omega"' in l]
HASH_NS = next(json.loads(l)['ns'] for l in open('../results/c_bench.jsonl') if 'hash' in l)
PSI = 16; ELEM = 32
def fit(psi, key):
    pts = sorted((r['omega'], r[key]) for r in cb if r['psi'] == psi)
    xs, ys = zip(*pts); n = len(xs); mx, my = sum(xs)/n, sum(ys)/n
    b = sum((x-mx)*(y-my) for x, y in zip(xs, ys))/sum((x-mx)**2 for x in xs); return lambda w: my + b*(w-mx)
ver_fit, sign_fit = fit(PSI, 'verify_ns'), fit(PSI, 'sign_ns')
FAL_SIG = 666
S = [("SILMARILS-MV", "sil"), ("SILMARILS-MV-agg", "silagg"), ("Ed25519", "ed"), ("ML-DSA-44", "d44"), ("ML-DSA-65", "d65"),
     ("Falcon-512", "fal"), ("SLH-DSA-SHA2-128s", "slh")]
def dki_per_index(n, t, w, psi, nver, mal=True):
    # semi-honest-with-robust-output (simulated): Vandermonde extraction yields n-t sharings per n dealt;
    # malicious (BTH08-style hyper-invertible extraction): n-2t per n dealt.
    d = (n - 2*t) if mal else (n - t)
    E = (w+1)*(psi+1); rc = n*(n-1)/d; mc = 2*(n-1) + 2*n*(n-1)/d
    return E*rc + E*mc + E*n + nver*(psi+1)*n
rows = []
for n in [4, 7, 10, 13, 16, 22, 31, 49, 64, 100]:
    t = (n-1)//3; w = t; Q = 2*t+1; r = dict(n=n, t=t)
    for name, ab in [x for x in S if x[1] != 'silagg']:
        if ab == "sil": sig = ELEM*(w+1); vus = (ver_fit(w) + HASH_NS)/1000
        else: sig = FAL_SIG if ab == "fal" else B[name]['sig']; vus = B[name]['verify_us']
        qc = Q*sig
        r[ab] = dict(sig=sig, qc=qc, leader=(n-1)*(qc+sig), total=n*sig + (n-1)*(qc+sig), cpu=(Q+1)*vus)
    # aggregated QC (linear aggregation): one (omega+1)-vector + n-bit signer bitmap
    aggqc = ELEM*(w+1) + (n+7)//8
    # verification of an aggregate: one <c,alpha> plus |Q| key-polynomial evaluations (psi mults each)
    fe_ns = next(json.loads(l)['ns'] for l in open('../results/c_bench.jsonl') if 'fe_mul' in l)
    agg_cpu = ((w+1)*fe_ns + Q*(PSI+1)*fe_ns + HASH_NS)/1000 + (ver_fit(w) + HASH_NS)/1000
    r['silagg'] = dict(sig=ELEM*(w+1), qc=aggqc, leader=(n-1)*(aggqc+ELEM*(w+1)),
                       total=n*ELEM*(w+1) + (n-1)*(aggqc+ELEM*(w+1)), cpu=agg_cpu)
    Sb = n + 1                                   # signatures per block
    dki_total = Sb/PSI*dki_per_index(n, t, w, PSI, n, mal=True)*ELEM
    dki_sh_total = Sb/PSI*dki_per_index(n, t, w, PSI, n, mal=False)*ELEM
    td_total = Sb/PSI*((w+1)*(PSI+1) + n*(PSI+1))*ELEM
    r['off'] = dict(dki_total=dki_total, dki_party=dki_total/n, dki_sh_party=dki_sh_total/n, td_total=td_total, td_party=td_total/n,
                    vstore=Sb*(PSI+1)/PSI*ELEM, sstore=(w+1)*(PSI+1)/PSI*ELEM)
    rows.append(r)
json.dump(rows, open('../results/ledger.json', 'w'), indent=1)
K = 1024
with open('../paper/data_ledger.dat', 'w') as f:
    cols = ['n', 't'] + [a+s for _, a in S for s in ('qc', 'lead', 'tot', 'cpu')] + ['dkitot', 'dkiparty', 'tdtot', 'silleadoff', 'silaggleadoff']
    f.write(' '.join(cols) + '\n')
    for r in rows:
        v = [r['n'], r['t']]
        for _, a in S: v += [r[a]['qc']/K, r[a]['leader']/K, r[a]['total']/K, r[a]['cpu']]
        v += [r['off']['dki_total']/K, r['off']['dki_party']/K, r['off']['td_total']/K,
              (r['sil']['leader'] + r['off']['dki_party'])/K, (r['silagg']['leader'] + r['off']['dki_party'])/K]
        f.write(' '.join(f"{x:.5g}" for x in v) + '\n')
for r in rows:
    print(r['n'], 'aggQC %.2f KiB aggLead %.1f aggcpu %.1f |' % (r['silagg']['qc']/K, r['silagg']['leader']/K, r['silagg']['cpu']), 'QC KiB sil %.2f d44 %.2f fal %.2f | leader KiB sil %.1f(+off %.1f) d44 %.1f fal %.1f | cpu us sil %.1f d44 %.0f | dki/party %.1f KiB td/party %.2f vstore %.2f' % (
        r['sil']['qc']/K, r['d44']['qc']/K, r['fal']['qc']/K, r['sil']['leader']/K, r['off']['dki_party']/K,
        r['d44']['leader']/K, r['fal']['leader']/K, r['sil']['cpu'], r['d44']['cpu'], r['off']['dki_party']/K,
        r['off']['td_party']/K, r['off']['vstore']/K))

# per-party average bytes per block (online + offline issuance)
with open('../paper/data_party.dat', 'w') as f:
    f.write('n d44 d65 fal ed slh silagg silaggdki silaggdkish silaggtd\n')
    for r in rows:
        n = r['n']
        f.write(' '.join(f"{x:.5g}" for x in [n, r['d44']['total']/n/K, r['d65']['total']/n/K, r['fal']['total']/n/K,
                r['ed']['total']/n/K, r['slh']['total']/n/K, r['silagg']['total']/n/K,
                (r['silagg']['total']/n + r['off']['dki_party'])/K, (r['silagg']['total']/n + r['off']['dki_sh_party'])/K,
                (r['silagg']['total']/n + r['off']['td_party'])/K]) + '\n')
