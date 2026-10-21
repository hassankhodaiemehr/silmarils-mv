"""Prop. 2(b) on the anchored scheme: omega+1 colluding verifiers solve K alpha = B e(m) for a fresh m
and check acceptance at an honest verifier (expected: always). Also Prop. 2(a) with Q queries, no corruption."""
import json, sys
from attacks import R, ev, mv, dt, rv, nullspace
from attacks_va import gam, cfor

def solve_any(K, y, q):
    # find any x with K x = y (consistent system), via Gaussian elimination on augmented matrix
    n = len(K[0]); A = [r[:] + [b] for r, b in zip(K, y)]; piv = []; r = 0
    for c in range(n):
        p = next((i for i in range(r, len(A)) if A[i][c] % q), None)
        if p is None: continue
        A[r], A[p] = A[p], A[r]; iv = pow(A[r][c], q - 2, q); A[r] = [x * iv % q for x in A[r]]
        for i in range(len(A)):
            if i != r and A[i][c]: f = A[i][c]; A[i] = [(a - f * b) % q for a, b in zip(A[i], A[r])]
        piv.append(c); r += 1
    x = [0] * n
    for i, c in enumerate(piv): x[c] = A[i][n]
    return x

def tb(q, w, psi):
    G = gam(q, w); A = [rv(psi + 1, q) for _ in range(w + 1)]
    pts = R.sample(range(1, q), w + 2); K = [cfor(G, x, q, w) for x in pts[:w + 1]]; c = cfor(G, pts[w + 1], q, w)
    m = R.randrange(q); E = ev(m, psi, q)
    y = [dt(k, mv(A, E, q), q) for k in K]           # B e(m) known to colluders
    alpha = solve_any(K, y, q)
    return dt(c, alpha, q) == dt(c, mv(A, E, q), q)

def ta(q, w, psi, Q):
    G = gam(q, w); A = [rv(psi + 1, q) for _ in range(w + 1)]; c = cfor(G, R.randrange(1, q), q, w)
    m = R.randrange(q); target = dt(c, mv(A, ev(m, psi, q), q), q)
    a1 = rv(w + 1, q); wv = rv(w + 1, q)
    return any(dt(c, [(x + l * y) % q for x, y in zip(a1, wv)], q) == target for l in range(Q))

if __name__ == "__main__":
    T = 4000; out = []
    for q in [31, 101, 257]:
        row = dict(q=q, T=T, Tb=sum(tb(q, 2, 2) for _ in range(T)) / T)
        for Q in [1, 4, 16]:
            row[f"a_Q{Q}"] = sum(ta(q, 2, 2, Q) for _ in range(T)) / T; row[f"bound_Q{Q}"] = Q / q + 1 / (q - 1)
        print(json.dumps(row)); out.append(row)
    json.dump(out, open('../results/attacks_va_tight.json', 'w'), indent=1)
