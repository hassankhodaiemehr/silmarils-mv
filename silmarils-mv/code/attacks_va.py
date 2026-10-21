"""Monte-Carlo validation for the virtual-anchor key structure c_W = Gamma^T lambda(x_W).
F1: omega corrupt verifiers (public points x_1..x_omega) + psi signatures; posterior-sampling forgery
    on an unsigned message, checked at an honest verifier.                     bound  1/q + 1/(q-1)
R1: corrupt signer + omega corrupt verifiers, D != 0 orthogonal to corrupt keys; acceptance by honest
    verifier W1 (bound 1/q) and disagreement between two honest verifiers W1, W2."""
import json, sys
from attacks import R, nullspace, ev, mv, dt, rv

def gam(q, w): return [rv(w + 1, q) for _ in range(w + 1)]
def cfor(G, x, q, w):  # c = G^T lambda(x)
    lam = [pow(x, i, q) for i in range(w + 1)]
    return [sum(G[i][j] * lam[i] for i in range(w + 1)) % q for j in range(w + 1)]

def trial_F1(q, w, psi):
    G = gam(q, w); A = [rv(psi + 1, q) for _ in range(w + 1)]
    pts = R.sample(range(1, q), w + 1); Cc = [cfor(G, x, q, w) for x in pts[:w]]; c = cfor(G, pts[w], q, w)
    msgs = R.sample(range(q), psi + 1); signed, mstar = msgs[:psi], msgs[psi]
    N1 = nullspace(Cc, w + 1, q); N2 = nullspace([ev(m, psi, q) for m in signed], psi + 1, q)
    Ap = [r[:] for r in A]
    for g in N1:
        for h in N2:
            lamb = R.randrange(q)
            for i in range(w + 1):
                for j in range(psi + 1): Ap[i][j] = (Ap[i][j] + lamb * g[i] * h[j]) % q
    alpha = mv(Ap, ev(mstar, psi, q), q)
    return dt(c, alpha, q) == dt(c, mv(A, ev(mstar, psi, q), q), q)

def trial_R1(q, w, psi):
    G = gam(q, w); A = [rv(psi + 1, q) for _ in range(w + 1)]
    pts = R.sample(range(1, q), w + 2); Cc = [cfor(G, x, q, w) for x in pts[:w]]
    c1, c2 = cfor(G, pts[w], q, w), cfor(G, pts[w + 1], q, w)
    N1 = nullspace(Cc, w + 1, q)
    while True:
        co = rv(len(N1), q); D = [sum(a * g[i] for a, g in zip(co, N1)) % q for i in range(w + 1)]
        if any(D): break
    a1 = dt(c1, D, q) == 0; a2 = dt(c2, D, q) == 0
    return a1, a1 != a2

if __name__ == "__main__":
    T = int(sys.argv[1]) if len(sys.argv) > 1 else 20000; out = []
    for q in [11, 31, 101, 257]:
        for (w, psi) in [(1, 1), (2, 2), (3, 4)]:
            f = sum(trial_F1(q, w, psi) for _ in range(T)) / T
            rr = [trial_R1(q, w, psi) for _ in range(T)]
            row = dict(q=q, omega=w, psi=psi, trials=T, F1=f, R1=sum(a for a, _ in rr) / T,
                       R1_disagree=sum(d for _, d in rr) / T, bound_F1=1 / q + 1 / (q - 1), bound_R1=1 / q)
            print(json.dumps(row)); sys.stdout.flush(); out.append(row)
    json.dump(out, open('../results/attacks_va.json', 'w'), indent=1)
