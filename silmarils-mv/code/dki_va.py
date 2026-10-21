"""DKI with virtual anchors (VA-DKI) for SILMARILS-MV.
Committee of n = 3t+1 parties jointly samples a secret matrix Gamma (never opened) and, per signer
index, a secret matrix A. Outputs: c_W = Gamma^T lambda_W to verifier W (once per epoch), A to the
signer, b_W = lambda_W^T (Gamma A) to every verifier W. Only Gamma*A needs multiplications.
Reuses primitives from dki_sim.py; counts all field elements sent; t parties corrupt their output shares."""
import json, random
from dki_sim import Q, R, share, recon, berlekamp_welch, Net, inv

def run(n, omega, psi, N, nsign):
    t = (n - 1) // 3; net = Net(); nver = n
    Mx = [[pow(i + 1, j, Q) for i in range(n)] for j in range(n - t)]
    pool = []
    def rnd(deg=None):
        nonlocal pool
        if not pool:
            dealt = [share(R.randrange(Q), t, n) for _ in range(n)]; net.send(n * (n - 1))
            pool = [[sum(row[i] * dealt[i][p] for i in range(n)) % Q for p in range(n)] for row in Mx]
        return pool.pop()
    dpool = []
    def dbl():
        nonlocal dpool
        if not dpool:
            rs = [R.randrange(Q) for _ in range(n)]
            d1 = [share(r, t, n) for r in rs]; d2 = [share(r, 2 * t, n) for r in rs]; net.send(2 * n * (n - 1))
            dpool = [([sum(row[i] * d1[i][p] for i in range(n)) % Q for p in range(n)],
                      [sum(row[i] * d2[i][p] for i in range(n)) % Q for p in range(n)]) for row in Mx]
        return dpool.pop()
    bad = set(R.sample(range(n), t))
    def open_to(sh):
        net.send(n); ys = [(x + R.randrange(1, Q)) % Q if p in bad else x for p, x in enumerate(sh)]
        return berlekamp_welch(ys, t + 1, t)
    lam = {W: [pow(W + 1, i, Q) for i in range(omega + 1)] for W in range(nver)}   # public x_W = W+1
    G = [[rnd() for _ in range(omega + 1)] for _ in range(omega + 1)]            # [Gamma]
    lin = lambda coeffs, shs: [sum(c * s[p] for c, s in zip(coeffs, shs)) % Q for p in range(n)]
    cW = {W: [open_to(lin(lam[W], [G[i][j] for i in range(omega + 1)])) for j in range(omega + 1)] for W in range(nver)}
    epoch_elems = net.elems
    A, B = {}, {}
    for u in range(nsign):
        for k in range(N):
            As = [[rnd() for _ in range(psi + 1)] for _ in range(omega + 1)]
            Ms = [[None] * (psi + 1) for _ in range(omega + 1)]
            for i in range(omega + 1):
                for j in range(psi + 1):  # (Gamma A)_{ij} = sum_l Gamma_il A_lj  -> one inner product
                    loc = [sum(G[i][l][p] * As[l][j][p] for l in range(omega + 1)) % Q for p in range(n)]
                    rt, r2t = dbl(); masked = [(a + b) % Q for a, b in zip(loc, r2t)]; net.send(2 * (n - 1))
                    d = recon(masked, 2 * t); Ms[i][j] = [(d - x) % Q for x in rt]
            A[u, k] = [[open_to(As[i][j]) for j in range(psi + 1)] for i in range(omega + 1)]
            for W in range(nver):
                B[W, u, k] = [open_to(lin(lam[W], [Ms[i][j] for i in range(omega + 1)])) for j in range(psi + 1)]
    ok = True
    for (W, u, k), b in B.items():
        exp = [sum(cW[W][i] * A[u, k][i][j] for i in range(omega + 1)) % Q for j in range(psi + 1)]
        ok &= exp == b
        m = R.randrange(Q); e = [pow(m, j, Q) for j in range(psi + 1)]
        al = [sum(A[u, k][i][j] * e[j] for j in range(psi + 1)) % Q for i in range(omega + 1)]
        ok &= sum(c * a for c, a in zip(cW[W], al)) % Q == sum(x * y for x, y in zip(b, e)) % Q
    idx = nsign * N; E = (omega + 1) * (psi + 1)
    per_index = (net.elems - epoch_elems) / idx
    # analytic per-index formula
    rc = n * (n - 1) / (n - t); mc = 2 * (n - 1) + 2 * n * (n - 1) / (n - t)
    formula = E * rc + E * mc + E * n + nver * (psi + 1) * n
    return dict(n=n, t=t, omega=omega, psi=psi, indices=idx, epoch_setup_elems=epoch_elems,
                per_index_elems=per_index, per_index_formula=formula, keys_consistent=ok)

if __name__ == "__main__":
    out = []
    for n in [4, 7, 10, 13]:
        r = run(n, omega=(n - 1) // 3, psi=4, N=2, nsign=n); print(json.dumps(r)); out.append(r)
    json.dump(out, open('../results/dki_va.json', 'w'), indent=1)
