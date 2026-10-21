"""Simulation of distributed key issuance (DKI) for SILMARILS-MV over F_q, n = 3t+1 committee members.
Implements: batch random sharings (Vandermonde extraction), double sharings, DN07-style degree
reduction of inner products, verifier input sharing, and robust private output (Berlekamp-Welch).
Counts every field element sent. Validates that issued keys satisfy b_V = c_V^T A and that
signatures verify, including with t parties sending corrupted output shares."""
import random, json, sys
R = random.SystemRandom()
Q = 2**61 - 1

def inv(a): return pow(a, Q - 2, Q)
def poly_eval(co, x):
    r = 0
    for c in reversed(co): r = (r * x + c) % Q
    return r
def share(s, deg, n): co = [s] + [R.randrange(Q) for _ in range(deg)]; return [poly_eval(co, i + 1) for i in range(n)]
def lagrange0(xs):
    lam = []
    for i, xi in enumerate(xs):
        num = den = 1
        for j, xj in enumerate(xs):
            if j != i: num = num * (-xj) % Q; den = den * (xi - xj) % Q
        lam.append(num * inv(den) % Q)
    return lam
def recon(shares, deg):  # assumes correct shares, uses first deg+1
    xs = list(range(1, deg + 2)); lam = lagrange0(xs)
    return sum(l * s for l, s in zip(lam, shares[:deg + 1])) % Q

def solve(M, b):
    n = len(M); A = [row[:] + [bb] for row, bb in zip(M, b)]
    for c in range(n):
        p = next((i for i in range(c, n) if A[i][c]), None)
        if p is None: return None
        A[c], A[p] = A[p], A[c]; iv = inv(A[c][c]); A[c] = [x * iv % Q for x in A[c]]
        for i in range(n):
            if i != c and A[i][c]:
                f = A[i][c]; A[i] = [(x - f * y) % Q for x, y in zip(A[i], A[c])]
    return [A[i][n] for i in range(n)]

def berlekamp_welch(ys, k, e):
    """decode RS codeword ys at x=1..n of degree < k with <= e errors (n >= k + 2e)."""
    n = len(ys)
    # unknowns: E (monic deg e: e coeffs), Qp (deg < k+e: k+e coeffs); Qp(x) = y E(x)
    rows, rhs = [], []
    for i in range(n):
        x, y = i + 1, ys[i]
        row = [(-y * pow(x, j, Q)) % Q for j in range(e)] + [pow(x, j, Q) for j in range(k + e)]
        rows.append(row); rhs.append(y * pow(x, e, Q) % Q)
    m = e + k + e
    sol = solve_ls(rows, rhs, m)
    Eco = sol[:e] + [1]; Qco = sol[e:]
    # polynomial division Qp / E
    num = Qco[:]; den = Eco; out = [0] * (len(num) - len(den) + 1)
    for i in range(len(out) - 1, -1, -1):
        out[i] = num[i + len(den) - 1] * inv(den[-1]) % Q
        for j, d in enumerate(den): num[i + j] = (num[i + j] - out[i] * d) % Q
    return out[0]  # constant term = secret

def solve_ls(rows, rhs, m):
    """any solution of overdetermined consistent system (Gaussian elimination)."""
    A = [r[:] + [b] for r, b in zip(rows, rhs)]; piv = []; r = 0
    for c in range(m):
        p = next((i for i in range(r, len(A)) if A[i][c]), None)
        if p is None: continue
        A[r], A[p] = A[p], A[r]; iv = inv(A[r][c]); A[r] = [x * iv % Q for x in A[r]]
        for i in range(len(A)):
            if i != r and A[i][c]:
                f = A[i][c]; A[i] = [(x - f * y) % Q for x, y in zip(A[i], A[r])]
        piv.append(c); r += 1
    sol = [0] * m
    for i, c in enumerate(piv): sol[c] = A[i][m]
    return sol

class Net:
    def __init__(s): s.elems = 0
    def send(s, k=1): s.elems += k

def run(n, omega, psi, N, nsign, nver, corrupt_out=True):
    t = (n - 1) // 3; net = Net()
    V = list(range(1, n + 1))  # (row index -> party)
    # Vandermonde extraction matrix (n-t) x n
    Mx = [[pow(i + 1, j, Q) for i in range(n)] for j in range(n - t)]
    def batch_random(deg, count):
        out = []
        while len(out) < count:
            dealt = [share(R.randrange(Q), deg, n) for _ in range(n)]; net.send(n * (n - 1))
            for row in Mx:  # each output sharing: party p holds sum_i row[i]*dealt[i][p]
                out.append([sum(row[i] * dealt[i][p] for i in range(n)) % Q for p in range(n)])
        return out[:count]
    nE = nsign * N * (omega + 1) * (psi + 1); nIP = nver * nsign * N * (psi + 1)
    rand_t = batch_random(t, nE)
    # (generate pairs: dealer shares same r with deg t and 2t)
    dbl = []
    while len(dbl) < nIP:
        rs = [R.randrange(Q) for _ in range(n)]
        d1 = [share(r, t, n) for r in rs]; d2 = [share(r, 2 * t, n) for r in rs]; net.send(2 * n * (n - 1))
        for row in Mx:
            dbl.append(([sum(row[i] * d1[i][p] for i in range(n)) % Q for p in range(n)],
                        [sum(row[i] * d2[i][p] for i in range(n)) % Q for p in range(n)]))
    dbl = dbl[:nIP]
    # verifier inputs c_V (honest: uniform), shared deg t
    cvec = {v: [R.randrange(Q) for _ in range(omega + 1)] for v in range(nver)}
    csh = {v: [share(x, t, n) for x in cvec[v]] for v in range(nver)}; net.send(nver * (omega + 1) * n)
    # A matrices
    it = iter(rand_t); Ash = {}
    for u in range(nsign):
        for k in range(N):
            Ash[u, k] = [[next(it) for _ in range(psi + 1)] for _ in range(omega + 1)]
    # inner products b_{V,u,k,j} = sum_i c_i A_ij  (DN07 degree reduction via king = party 1)
    dit = iter(dbl); bsh = {}
    for v in range(nver):
        for u in range(nsign):
            for k in range(N):
                for j in range(psi + 1):
                    loc = [sum(csh[v][i][p] * Ash[u, k][i][j][p] for i in range(omega + 1)) % Q for p in range(n)]
                    rt, r2t = next(dit)
                    masked = [(a + b) % Q for a, b in zip(loc, r2t)]; net.send(n - 1)      # to king
                    d = recon(masked, 2 * t); net.send(n - 1)                              # king broadcasts
                    bsh[v, u, k, j] = [(d - x) % Q for x in rt]
    # private outputs with robust decoding; t parties send garbage
    bad = set(R.sample(range(n), t)) if corrupt_out else set()
    def open_to(sh):
        net.send(n)
        ys = [(x + R.randrange(1, Q)) % Q if p in bad else x for p, x in enumerate(sh)]
        return berlekamp_welch(ys, t + 1, t)
    A = {(u, k): [[open_to(Ash[u, k][i][j]) for j in range(psi + 1)] for i in range(omega + 1)]
         for u in range(nsign) for k in range(N)}
    B = {key: open_to(sh) for key, sh in bsh.items()}
    # validation: b = c^T A and signatures verify
    ok = True
    for v in range(nver):
        for u in range(nsign):
            for k in range(N):
                for j in range(psi + 1):
                    exp = sum(cvec[v][i] * A[u, k][i][j] for i in range(omega + 1)) % Q
                    ok &= (exp == B[v, u, k, j])
                m = R.randrange(Q); e = [pow(m, j, Q) for j in range(psi + 1)]
                alpha = [sum(A[u, k][i][j] * e[j] for j in range(psi + 1)) % Q for i in range(omega + 1)]
                lhs = sum(cvec[v][i] * alpha[i] for i in range(omega + 1)) % Q
                rhs = sum(B[v, u, k, j] * e[j] for j in range(psi + 1)) % Q
                ok &= (lhs == rhs)
    return dict(n=n, t=t, omega=omega, psi=psi, N=N, signers=nsign, verifiers=nver, entries=nE, IPs=nIP,
                total_elems=net.elems, elems_per_IP=net.elems / nIP, keys_consistent=ok)

if __name__ == "__main__":
    out = []
    for n in [4, 7, 10]:
        t = (n - 1) // 3
        r = run(n, omega=t, psi=4, N=2, nsign=n, nver=n); print(json.dumps(r)); out.append(r)
    json.dump(out, open('../results/dki_sim.json', 'w'), indent=1)
