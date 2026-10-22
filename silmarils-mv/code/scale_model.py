"""Scalability model, n = 3t+1 up to 1000 validators. Counts authentication-related bytes per block
(signatures, MAC tags, certificate shares, certificates, and amortized key-issuance traffic); message headers
and payloads are identical across schemes and excluded.

Topologies
  star (HotStuff-style): every validator sends one vote to the leader; the leader broadcasts a QC of 2t+1 votes.
  a2a  (PBFT/Tendermint-style): two all-to-all voting rounds.
SILMARILS-MV modes
  IV: individual validator signatures, aggregated QC, dealer-free issuance (malicious-cost model d = n-2t).
  TN: consensus authenticated by pairwise information-theoretic MACs (two all-to-all rounds, 32-byte tags);
      each validator releases one certificate share to the combiner; the committee issues keys to nu external
      verifiers; issuance traffic amortized per block (malicious-cost model d = n-2t)."""
import json
B = {r['scheme']: r for r in json.load(open('../results/baselines.json'))}
TNB = [json.loads(l) for l in open('../results/tn_bench.jsonl')]
FE_MUL_US = next(json.loads(l)['ns'] for l in open('../results/c_bench.jsonl') if 'fe_mul' in l) / 1000
HASH_NS = next(json.loads(l)['ns'] for l in open('../results/c_bench.jsonl') if 'hash' in l)
ELEM, TAG, K = 32, 32, 1024
IDX = 4                                              # bytes per signer index in IV votes and QCs
W_EXT, PSI_TN, NU, EPOCH = 16, 64, 64, 3600          # TN: omega, psi, external verifiers, blocks/epoch
FAL = 666; BLS_SIG = 96
MAC_US = 0.2                                          # one-time polynomial MAC on a 32-byte digest (2 mults + pad)
ns = [4, 7, 10, 16, 31, 49, 100, 151, 301, 502, 1000]


def dki_idx(n, t, w, psi, nver, mal=True, open_A=True):
    d = (n - 2 * t) if mal else (n - t)
    E = (w + 1) * (psi + 1); rc = n * (n - 1) / d; mc = 2 * (n - 1) + 2 * n * (n - 1) / d
    return E * rc + E * mc + (E * n if open_A else 0) + nver * (psi + 1) * n

def tnb(n, w=W_EXT):
    r = [x for x in TNB if x['omega'] == w]
    exact = [x for x in r if x['n'] == n]
    if exact: return exact[0]
    # interpolate combine time (quadratic in t) from the measured points
    pts = sorted((x['n'], x['combine_opt_ns']) for x in r)
    lo = max(p for p in pts if p[0] <= n); hi = min(p for p in pts if p[0] >= n)
    f = (n - lo[0]) / (hi[0] - lo[0]) if hi[0] != lo[0] else 0
    base = dict(r[0]); base['n'] = n; base['combine_opt_ns'] = lo[1] + f * (hi[1] - lo[1]); return base

rows = []
for n in ns:
    t = (n - 1) // 3; q2 = 2 * t + 1; r = dict(n=n, t=t)
    def star(sig, vus):
        qc = q2 * sig
        return dict(party=(n * sig + (n - 1) * (qc + sig)) / n, leader=(n - 1) * (qc + sig) + n * sig,
                    cert=qc + (n + 7) // 8, certver=q2 * vus, cpu=q2 * vus + vus)
    def a2a(sig, vus):
        return dict(party=2 * (n - 1) * sig + sig * (n - 1) / n, leader=2 * (n - 1) * sig + (n - 1) * sig,
                    cert=q2 * sig + (n + 7) // 8, certver=q2 * vus, cpu=2 * (n - 1) * vus)
    r['d44s'] = star(B['ML-DSA-44']['sig'], B['ML-DSA-44']['verify_us'])
    r['d44a'] = a2a(B['ML-DSA-44']['sig'], B['ML-DSA-44']['verify_us'])
    r['fals'] = star(FAL, B['Falcon-512']['verify_us'])
    r['eds'] = star(64, B["Ed25519"]['verify_us'])
    bqc = BLS_SIG + (n + 7) // 8
    r['bls'] = dict(party=(n * BLS_SIG + (n - 1) * (bqc + BLS_SIG)) / n, leader=(n - 1) * (bqc + BLS_SIG) + n * BLS_SIG,
                    cert=bqc, certver=None, cpu=None)
    # SILMARILS-MV IV (omega = t, psi = 16), aggregated QC, dealer-free issuance (malicious model)
    w, psi = t, 16; sig = ELEM * (w + 1) + IDX; aq = ELEM * (w + 1) + (n + 7) // 8 + IDX * q2
    off = (n + 1) / psi * dki_idx(n, t, w, psi, n) * ELEM / n
    r['iv'] = dict(party=(n * sig + (n - 1) * (aq + sig)) / n + off, leader=(n - 1) * (aq + sig) + n * sig + off,
                   cert=aq, certver=None, cpu=None, offline=off)
    # MAC-only BFT (no transferable certificate): lower bound for any authenticated all-to-all protocol
    mac = 2 * (n - 1) * TAG + TAG * (n - 1) / n
    r['mac'] = dict(party=mac, leader=mac + (n - 1) * TAG, cert=None, certver=None, cpu=2 * (n - 1) * MAC_US)
    # TN
    w, psi = W_EXT, PSI_TN; E = (w + 1) * (psi + 1)
    iss = dki_idx(n, t, w, psi, NU, open_A=False) / psi * ELEM / n               # per party per block
    epoch = ((w + 1) ** 2 * n * (n - 1) / (n - 2 * t) + NU * (w + 1) * n) / EPOCH * ELEM / n
    share = ELEM * (w + 1)
    dist = NU * ELEM * (w + 1) / n                                               # certificate to NU verifiers (rotating combiner)
    tb = tnb(n)
    d = n - 2 * t; mults_iss = (E / psi) * (n * (n - 1) / d / n * n + 2 * n + (w + 1)) # local issuance work per party per block (approx.)
    r['tn'] = dict(party=mac + share + dist + iss + epoch, leader=mac + n * share + NU * ELEM * (w + 1) + iss + epoch,
                   cert=ELEM * (w + 1), certver=(tb['cert_verify_ns'] + HASH_NS) / 1000,
                   cpu=2 * (n - 1) * MAC_US + tb['share_ns'] / 1000 + mults_iss * FE_MUL_US,
                   combiner_cpu=tb['combine_opt_ns'] / 1000, fallback_ms=tb.get('fallback_ns', 0) / 1e6,
                   issuance=iss + epoch, keycons_party=4 * (n - 1) * TAG, keycons_ver=(psi + 1) / psi * ELEM)
    # AV keys (omega = 0, arbiter-verified): per-index issuance (psi+1)(r_c+mu_c) + opening of a to the signer
    pa = PSI_TN; d = n - 2 * t; rc = n * (n - 1) / d; mc = 2 * (n - 1) + 2 * n * (n - 1) / d
    av_idx = (pa + 1) * (rc + mc + n)
    batch = (n * (n - 1) + 2 * (n - 1) + 2 * n * (n - 1) / d + n * (n - 1) + 2 * rc) / n   # coin + mult + open, per party
    # TN+A: every validator also attaches a 32-byte AV signature to its commit vote (one all-to-all round)
    acc = (av_idx / pa) * ELEM + (n - 1) * ELEM + batch * ELEM
    r['tna'] = dict(party=r['tn']['party'] + acc, leader=r['tn']['leader'] + acc, cert=r['tn']['cert'], certver=r['tn']['certver'], cpu=None)
    # clients: per transaction, bytes added to every validator / received by the client
    r['client'] = dict(av_per_val=av_idx / pa * ELEM / n, av_client_rx=(pa + 1) * n * ELEM / pa, d44_per_val=B['ML-DSA-44']['sig'],
                       iv_per_val=dki_idx(n, t, t, 16, n) / 16 * ELEM / n)
    rows.append(r)
json.dump(rows, open('../results/scale.json', 'w'), indent=1)
keys = ['d44s', 'd44a', 'fals', 'eds', 'bls', 'iv', 'mac', 'tn', 'tna']
import os; os.makedirs('../paper', exist_ok=True)
with open('../paper/data_scale.dat', 'w') as f:
    f.write('n ' + ' '.join(k + s for k in keys for s in ('p', 'l', 'c')) + '\n')
    for r in rows:
        v = [r['n']]
        for k in keys:
            v += [r[k]['party'] / K, r[k]['leader'] / K, (r[k]['cert'] or float('nan')) / K]
        f.write(' '.join('nan' if x != x else f"{x:.5g}" for x in v) + '\n')
for r in rows:
    if r['n'] in (31, 100, 301, 1000):
        print(r['n'], {k: (round(r[k]['party'] / K, 1), round(r[k]['leader'] / K, 1), r[k]['cert'] and round(r[k]['cert'] / K, 2)) for k in keys})
        print('   tn cpu us', round(r['tn']['cpu'], 1), 'combiner us', round(r['tn']['combiner_cpu'], 1), 'certver us', round(r['tn']['certver'], 2),
              'iss KiB', round(r['tn']['issuance'] / K, 2), 'keycons KiB', round(r['tn']['keycons_party'] / K, 1),
              'client', {k: round(v / K, 2) for k, v in r['client'].items()}, 'tna', round(r['tna']['party'] / K, 1),
              'd44 certver ms', round(r['d44s']['certver'] / 1000, 1), 'd44a cpu ms', round(r['d44a']['cpu'] / 1000, 1), 'fallback ms', r['tn']['fallback_ms'])
