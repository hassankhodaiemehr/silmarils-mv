"""Monte-Carlo validation of SILMARILS-MV bounds over small prime fields.
Experiments (per field q, dimensions omega, psi):
 F1  coalition forgery: omega corrupt verifiers + psi signed messages on the target index;
     adversary outputs alpha* = A' e(m*), A' drawn from its exact posterior.   bound 2/q
 F1n naive forgery (uniform alpha*).                                             bound 1/q
 R1  repudiation: corrupt signer + omega corrupt verifiers; D != 0 chosen orthogonal to all
     corrupt functionals (corrupt verifiers accept); honest verifier accepts?    bound 1/q
 T1  omega+1 colluders (tightness):  success should be ~1 - Pr[dependent keys]
 T2  psi+1 signatures on one index (tightness): success 1
"""
import random, json, sys
R = random.SystemRandom()

def inv(a, q): return pow(a, q - 2, q)

def nullspace(M, ncols, q):
    """basis (list of vectors) of {x : M x = 0} over F_q; M list of rows."""
    M = [r[:] for r in M]; piv = []; r = 0
    for c in range(ncols):
        p = next((i for i in range(r, len(M)) if M[i][c] % q), None)
        if p is None: continue
        M[r], M[p] = M[p], M[r]; iv = inv(M[r][c], q)
        M[r] = [x * iv % q for x in M[r]]
        for i in range(len(M)):
            if i != r and M[i][c]:
                f = M[i][c]; M[i] = [(a - f * b) % q for a, b in zip(M[i], M[r])]
        piv.append(c); r += 1
        if r == len(M): break
    free = [c for c in range(ncols) if c not in piv]; basis = []
    for f in free:
        x = [0] * ncols; x[f] = 1
        for i, pc in enumerate(piv): x[pc] = (-M[i][f]) % q
        basis.append(x)
    return basis

def rank(M, ncols, q): return ncols - len(nullspace(M, ncols, q)) if M else 0
def ev(m, psi, q): return [pow(m, j, q) for j in range(psi + 1)]
def mv(A, v, q): return [sum(a * b for a, b in zip(r, v)) % q for r in A]
def dt(u, v, q): return sum(a * b for a, b in zip(u, v)) % q
def rv(n, q): return [R.randrange(q) for _ in range(n)]

def trial_F1(q, w, psi, naive=False):
    A = [rv(psi + 1, q) for _ in range(w + 1)]
    L = [rv(w + 1, q) for _ in range(w)]              # corrupt functionals (any choice)
    msgs = R.sample(range(q), psi + 1); signed, mstar = msgs[:psi], msgs[psi]
    c = rv(w + 1, q)                                  # honest verifier key
    if naive:
        alpha = rv(w + 1, q)
    else:
        # posterior of A given L A and A E: A + N1 R N2^T
        N1 = nullspace(L, w + 1, q)                   # g with L g = 0
        Et = [ev(m, psi, q) for m in signed]          # rows e(m)^T ; h with h^T e(m)=0
        N2 = nullspace(Et, psi + 1, q)
        Ap = [row[:] for row in A]
        for g in N1:
            for h in N2:
                lam = R.randrange(q)
                for i in range(w + 1):
                    if g[i]:
                        for j in range(psi + 1):
                            Ap[i][j] = (Ap[i][j] + lam * g[i] * h[j]) % q
        alpha = mv(Ap, ev(mstar, psi, q), q)
    return dt(c, alpha, q) == dt(c, mv(A, ev(mstar, psi, q), q), q)

def trial_R1(q, w, psi):
    A = [rv(psi + 1, q) for _ in range(w + 1)]
    L = [rv(w + 1, q) for _ in range(w)]
    c = rv(w + 1, q)
    N1 = nullspace(L, w + 1, q)                       # D orthogonal to corrupt keys
    while True:
        coeffs = rv(len(N1), q)
        D = [sum(a * g[i] for a, g in zip(coeffs, N1)) % q for i in range(w + 1)]
        if any(D): break
    m = R.randrange(q)
    alpha = [(x + d) % q for x, d in zip(mv(A, ev(m, psi, q), q), D)]
    corrupt_ok = all(dt(l, alpha, q) == dt(l, mv(A, ev(m, psi, q), q), q) for l in L)
    assert corrupt_ok
    return dt(c, alpha, q) == dt(c, mv(A, ev(m, psi, q), q), q)

def trial_T1(q, w, psi):
    A = [rv(psi + 1, q) for _ in range(w + 1)]
    L = [rv(w + 1, q) for _ in range(w + 1)]          # omega+1 colluders
    if rank(L, w + 1, q) < w + 1: return False        # counted as failure (dependent keys)
    LA = [[dt(l, [A[i][j] for i in range(w + 1)], q) for j in range(psi + 1)] for l in L]
    # solve L X = LA for X (= A)
    import copy
    M = [l[:] + LA[r][:] for r, l in enumerate(L)]
    n = w + 1
    for col in range(n):
        p = next(i for i in range(col, n) if M[i][col])
        M[col], M[p] = M[p], M[col]; iv = inv(M[col][col], q)
        M[col] = [x * iv % q for x in M[col]]
        for i in range(n):
            if i != col and M[i][col]:
                f = M[i][col]; M[i] = [(a - f * b) % q for a, b in zip(M[i], M[col])]
    X = [row[n:] for row in M]
    mstar = R.randrange(q); c = rv(w + 1, q)
    return dt(c, mv(X, ev(mstar, psi, q), q), q) == dt(c, mv(A, ev(mstar, psi, q), q), q)

def trial_T2(q, w, psi):
    A = [rv(psi + 1, q) for _ in range(w + 1)]
    msgs = R.sample(range(q), psi + 2); signed, mstar = msgs[:psi + 1], msgs[psi + 1]
    sigs = [mv(A, ev(m, psi, q), q) for m in signed]
    # Lagrange-interpolate each coordinate polynomial alpha_i(z) of degree psi
    def lag(xs, ys, x):
        s = 0
        for i, xi in enumerate(xs):
            num = den = 1
            for j, xj in enumerate(xs):
                if j != i: num = num * (x - xj) % q; den = den * (xi - xj) % q
            s = (s + ys[i] * num * inv(den, q)) % q
        return s
    alpha = [lag(signed, [s[i] for s in sigs], mstar) for i in range(w + 1)]
    c = rv(w + 1, q)
    return dt(c, alpha, q) == dt(c, mv(A, ev(mstar, psi, q), q), q)

if __name__ == "__main__":
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    out = []
    for q in [11, 31, 101, 257]:
        for (w, psi) in [(1, 1), (2, 2), (3, 4)]:
            row = {"q": q, "omega": w, "psi": psi, "trials": trials}
            for name, fn, kw in [("F1", trial_F1, {}), ("F1n", trial_F1, {"naive": True}),
                                 ("R1", trial_R1, {}), ("T1", trial_T1, {}), ("T2", trial_T2, {})]:
                n_t = trials if name not in ("T1", "T2") else max(1000, trials // 20)
                row[name] = sum(fn(q, w, psi, **kw) for _ in range(n_t)) / n_t
            row["bound_F1"] = 2 / q; row["bound_R1"] = 1 / q
            print(json.dumps(row)); sys.stdout.flush(); out.append(row)
    json.dump(out, open("../results/attacks.json", "w"), indent=1)
