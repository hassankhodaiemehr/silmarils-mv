"""Exhaustive check of batch arbitration (Lemma 4) over small prime fields.

Arbiter-verified mode (omega = 0): the anchor is a uniform scalar gamma, and the arbiter key of an honest,
unsigned index is b_0 = gamma * a with a = a_{U,k} e(m) uniform. A submitted value alpha_j gives the residual
delta_j = gamma * (alpha_j - a_j). Item j is non-acceptable for every key (it is not authentic), whatever alpha_j.
The batch is accepted iff D = sum_j w_j(r) delta_j = 0 for a uniform public r drawn after the batch is fixed.

We enumerate gamma, r and the honest values a_j exactly, and maximize over the adversary's choices alpha_j.
  weights 'r^j'     (j = 1..L, the original Lemma 4):  counterexample for L = 1, acceptance 3/q - 3/q^2 + 1/q^3
  weights 'r^(j-1)' (j = 1..L, the corrected Lemma 4): acceptance <= (L+1)/q
Usage: python3 batch_check.py            (prints a table and writes ../results/batch_check.json)"""
import itertools, json

def accept_prob(q, L, alphas, shift):
    hits = tot = 0
    for g in range(q):
        for r in range(q):
            w = [pow(r, j + shift, q) for j in range(L)]          # shift=1: r^j (j=1..L); shift=0: r^(j-1)
            for a in itertools.product(range(q), repeat=L):
                D = sum(wj * g * (al - aj) for wj, al, aj in zip(w, alphas, a)) % q
                hits += (D == 0); tot += 1
    return hits / tot

rows = []
for q in (3, 5, 7):
    for L in (1, 2):
        for name, shift in (("r^j (original)", 1), ("r^(j-1) (corrected)", 0)):
            worst = max(accept_prob(q, L, al, shift) for al in itertools.product(range(q), repeat=L))
            rows.append(dict(q=q, L=L, weights=name, max_accept=worst, bound=(L + 1) / q, within=worst <= (L + 1) / q + 1e-12))
for r in rows:
    print(f"q={r['q']} L={r['L']} {r['weights']:22s} max Pr[accept]={r['max_accept']:.4f}  (L+1)/q={r['bound']:.4f}  {'ok' if r['within'] else 'VIOLATED'}")
json.dump(rows, open('../results/batch_check.json', 'w'), indent=1)
