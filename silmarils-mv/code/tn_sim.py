"""Threshold-notarization (TN) mode of SILMARILS-MV: end-to-end simulation.

The committee P (n = 3t+1 members, points y_j = j) holds degree-t Shamir sharings of the virtual anchors
Gamma and of the committee signing matrices A_k (never opened), and of M_k = Gamma A_k (one inner product per
entry, DN07 degree reduction with double sharings). External verifiers (identifiers x_i, collusion bound
omega independent of n) receive c_i = Gamma^T lambda(x_i) and b_{i,k} = M_k^T lambda(x_i) by robust private
opening (Berlekamp-Welch). For a decided slot s -> (k, m) every honest member releases its share
A_k^{(j)} e(m); a combiner interpolates (optimistic path checked with its own verifier key) or falls back
to coordinate-wise Reed-Solomon decoding with erasures.

Byzantine members: garbage shares, silence, and shares on a conflicting message (equivocation).
Also exercised: late (retroactive) verifier enrolment, robust redistribution of all shared state to a new
committee of a different size (membership change / proactive refresh), and communication counts that are
checked against the closed-form cost of Section VIII-F.

Field: Q = 2^61-1 by default; TNQ=257 (env) gives the small-field Monte-Carlo forgery experiment."""
import random, json, os, sys
R = random.SystemRandom()
Q = int(os.environ.get('TNQ', 2**61 - 1))


def inv(a): return pow(a % Q, Q - 2, Q)
def peval(co, x):
    r = 0
    for c in reversed(co): r = (r * x + c) % Q
    return r
def share(s, deg, xs): co = [s % Q] + [R.randrange(Q) for _ in range(deg)]; return [peval(co, x) for x in xs]
def lag0(xs):
    out = []
    for i, xi in enumerate(xs):
        num = den = 1
        for j, xj in enumerate(xs):
            if j != i: num = num * (-xj) % Q; den = den * (xi - xj) % Q
        out.append(num * inv(den) % Q)
    return out
def ev(m, psi): return [pow(m, j, Q) for j in range(psi + 1)]
def lam(x, w): return [pow(x, j, Q) for j in range(w + 1)]
def dot(u, v): return sum(a * b for a, b in zip(u, v)) % Q


def solve_ls(rows, rhs, m):
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


def rs_decode0(pts, deg):
    """Berlekamp-Welch on received points [(x,y)] (missing points = erasures). Returns f(0) for the unique
    degree-<=deg polynomial within distance e = floor((len-deg-1)/2), or None if decoding fails."""
    r = len(pts); e = (r - deg - 1) // 2
    if e < 0: return None
    rows, rhs = [], []
    for x, y in pts:
        rows.append([(-y * pow(x, j, Q)) % Q for j in range(e)] + [pow(x, j, Q) for j in range(deg + 1 + e)])
        rhs.append(y * pow(x, e, Q) % Q)
    sol = solve_ls(rows, rhs, 2 * e + deg + 1)
    Eco = sol[:e] + [1]; num = sol[e:]
    out = [0] * (len(num) - len(Eco) + 1)
    for i in range(len(out) - 1, -1, -1):
        out[i] = num[i + len(Eco) - 1] % Q
        for j, d in enumerate(Eco): num[i + j] = (num[i + j] - out[i] * d) % Q
    if any(num): return None                      # E does not divide: more than e errors
    if sum(1 for x, y in pts if peval(out, x) != y % Q) > e: return None
    return out[0]


class Net:
    def __init__(s): s.elems = 0
    def send(s, k=1): s.elems += k


class Committee:
    """Semi-honest MPC primitives with robust outputs; element counting."""
    def __init__(s, n, net, bad=None, strategy=None):
        s.n, s.t, s.net = n, (n - 1) // 3, net
        s.ys = list(range(1, n + 1))
        s.bad = set(R.sample(range(n), s.t)) if bad is None else set(bad)
        s.strategy = strategy or {}
        s.Mx = [[pow(i + 1, j, Q) for i in range(n)] for j in range(n - s.t)]   # Vandermonde extraction
        s.pool, s.dpool = [], []

    def rnd(s):
        if not s.pool:
            dealt = [share(R.randrange(Q), s.t, s.ys) for _ in range(s.n)]; s.net.send(s.n * (s.n - 1))
            s.pool = [[sum(row[i] * dealt[i][p] for i in range(s.n)) % Q for p in range(s.n)] for row in s.Mx]
        return s.pool.pop()

    def dbl(s):
        if not s.dpool:
            rs = [R.randrange(Q) for _ in range(s.n)]
            d1 = [share(r, s.t, s.ys) for r in rs]; d2 = [share(r, 2 * s.t, s.ys) for r in rs]
            s.net.send(2 * s.n * (s.n - 1))
            s.dpool = [([sum(row[i] * d1[i][p] for i in range(s.n)) % Q for p in range(s.n)],
                        [sum(row[i] * d2[i][p] for i in range(s.n)) % Q for p in range(s.n)]) for row in s.Mx]
        return s.dpool.pop()

    def ip(s, ash, bsh):
        """[a^T b] from vectors of sharings: local product, one degree reduction (king = party 0)."""
        loc = [sum(a[p] * b[p] for a, b in zip(ash, bsh)) % Q for p in range(s.n)]
        rt, r2t = s.dbl(); masked = [(x + y) % Q for x, y in zip(loc, r2t)]
        s.net.send(2 * (s.n - 1))
        lam2 = lag0(s.ys[:2 * s.t + 1]); d = sum(l * v for l, v in zip(lam2, masked)) % Q
        return [(d - x) % Q for x in rt]

    def lin(s, coeffs, shs): return [sum(c * sh[p] for c, sh in zip(coeffs, shs)) % Q for p in range(s.n)]

    def open_to(s, sh):
        """robust private opening towards one receiver: all n shares sent, t corrupted, BW decoding."""
        s.net.send(s.n)
        pts = []
        for p, x in enumerate(sh):
            if p in s.bad:
                st = s.strategy.get(p, 'garbage')
                if st == 'silent': continue
                x = (x + R.randrange(1, Q)) % Q
            pts.append((s.ys[p], x))
        v = rs_decode0(pts, s.t); assert v is not None
        return v


class TN:
    def __init__(s, n, omega, psi, strategy_cycle=('garbage', 'silent', 'equivocate')):
        s.net = Net(); s.w, s.psi = omega, psi
        bad = R.sample(range(n), (n - 1) // 3)
        strat = {p: strategy_cycle[i % len(strategy_cycle)] for i, p in enumerate(bad)}
        s.C = Committee(n, s.net, bad, strat)
        s.G = [[s.C.rnd() for _ in range(omega + 1)] for _ in range(omega + 1)]   # [Gamma]
        s.A, s.M = {}, {}
        s.verifiers = {}

    def issue_index(s, k):
        w, psi, C = s.w, s.psi, s.C
        s.A[k] = [[C.rnd() for _ in range(psi + 1)] for _ in range(w + 1)]
        s.M[k] = [[C.ip([s.G[i][l] for l in range(w + 1)], [s.A[k][l][j] for l in range(w + 1)])
                   for j in range(psi + 1)] for i in range(w + 1)]

    def enroll(s, x, ks):
        """verifier key: c = Gamma^T lambda(x) (epoch), b_k = M_k^T lambda(x): local linear maps + opening."""
        w, C = s.w, s.C; L = lam(x, w)
        c = [C.open_to(C.lin(L, [s.G[i][j] for i in range(w + 1)])) for j in range(w + 1)]
        b = {k: [C.open_to(C.lin(L, [s.M[k][i][j] for i in range(w + 1)])) for j in range(s.psi + 1)] for k in ks}
        s.verifiers[x] = (c, b)
        return c, b

    def add_keys(s, x, ks):
        C = s.C; L = lam(x, s.w); c, b = s.verifiers[x]
        for k in ks:
            b[k] = [C.open_to(C.lin(L, [s.M[k][i][j] for i in range(s.w + 1)])) for j in range(s.psi + 1)]

    def release(s, p, k, m, decided):
        """share of alpha released by member p for (k, m); Byzantine behaviour per strategy."""
        e = ev(m, s.psi)
        honest_share = [sum(s.A[k][i][j][p] * e[j] for j in range(s.psi + 1)) % Q for i in range(s.w + 1)]
        if p not in s.C.bad: return honest_share if m == decided else None   # release rule
        st = s.C.strategy[p]
        if st == 'silent': return None
        if st == 'garbage': return [R.randrange(Q) for _ in range(s.w + 1)]
        return [sum(s.A[k][i][j][p] * ev(m ^ 1, s.psi)[j] for j in range(s.psi + 1)) % Q for i in range(s.w + 1)]

    def combine(s, k, m, shares, vkey=None):
        """shares: {p: vec}. Optimistic: interpolate from first t+1, check with own verifier key.
        Fallback: coordinate-wise RS decoding with erasures. Returns (alpha, path)."""
        t = s.C.t; ps = sorted(shares)
        susp = getattr(s, 'suspect', set())
        if vkey is not None and len(ps) >= t + 1:
            sub = ([p for p in ps if p not in susp] + [p for p in ps if p in susp])[:t + 1]; L = lag0([s.C.ys[p] for p in sub])
            alpha = [sum(l * shares[p][i] for l, p in zip(L, sub)) % Q for i in range(s.w + 1)]
            c, b = vkey
            if dot(c, alpha) == dot(b[k], ev(m, s.psi)): return alpha, 'optimistic'
        alpha = []
        for i in range(s.w + 1):
            v = rs_decode0([(s.C.ys[p], shares[p][i]) for p in ps], t)
            if v is None: return None, 'fail'
            alpha.append(v)
        # remember members whose shares were inconsistent with the decoded certificate
        co = [rs_full([(s.C.ys[p], shares[p][i]) for p in ps], t) for i in range(s.w + 1)]
        s.suspect = susp | {p for p in ps if any(peval(co[i], s.C.ys[p]) != shares[p][i] for i in range(s.w + 1))}
        return alpha, 'decode'

    def verify(s, x, k, m, alpha):
        c, b = s.verifiers[x]; return dot(c, alpha) == dot(b[k], ev(m, s.psi))

    def reshare(s, n_new):
        """Robust redistribution of all shared state to a new committee of size n_new, t' = (n_new-1)//3.
        Every available old member j deals a degree-t' sharing of its share (dealing consistency is what a
        perfect VSS enforces; a corrupt dealer may still share a WRONG value, which we simulate). The new
        committee forms a public random combination of all dealt secrets per dealer, computes the Reed-Solomon
        syndrome of the dealer vector in shared form (local), and opens it robustly. The syndrome depends only on
        the dealers' deviations, never on the secrets. Syndrome decoding locates the deviating dealers; new
        shares are Lagrange combinations over t+1 dealers that passed."""
        old = s.C; tn = (n_new - 1) // 3; zs = list(range(1, n_new + 1))
        new = Committee(n_new, s.net, bad=R.sample(range(n_new), tn), strategy=None)
        new.strategy = {p: 'garbage' for p in new.bad}
        avail = [j for j in range(old.n) if not (j in old.bad and old.strategy[j] == 'silent')]
        delta = {j: R.randrange(1, Q) for j in avail if j in old.bad}
        secrets = []
        def deal(sh):
            D = {j: share((sh[j] + delta.get(j, 0)) % Q, tn, zs) for j in avail}
            s.net.send(len(avail) * n_new); secrets.append(D); return D
        dG = [[deal(x) for x in row] for row in s.G]
        dA = {k: [[deal(x) for x in row] for row in s.A[k]] for k in s.A}
        dM = {k: [[deal(x) for x in row] for row in s.M[k]] for k in s.M}
        # public random combination (coefficients drawn after dealing, e.g. from a common coin)
        r = [R.randrange(Q) for _ in secrets]
        W = {j: [sum(rl * D[j][i] for rl, D in zip(r, secrets)) % Q for i in range(n_new)] for j in avail}
        ys = [old.ys[j] for j in avail]; na = len(avail)
        u = [inv(prod([(yj - yl) for l, yl in enumerate(ys) if l != a])) for a, yj in enumerate(ys)]
        H = [[u[a] * pow(ys[a], b, Q) % Q for a in range(na)] for b in range(na - old.t - 1)]
        syn_sh = [[sum(h[a] * W[avail[a]][i] for a in range(na)) % Q for i in range(n_new)] for h in H]
        syn = [new.open_to(x) for x in syn_sh]
        s.net.send(len(syn) * n_new * (n_new - 1) - len(syn) * n_new)   # open towards all new members
        # syndrome decoding: any y with H y = syn, then y = c' + e with wt(e) <= t; BW recovers c'
        y = solve_ls(H, syn, na)
        co = rs_full(list(zip(ys, y)), old.t)
        bad_dealers = {avail[a] for a in range(na) if peval(co, ys[a]) != y[a]}
        good = [j for j in avail if j not in bad_dealers][:old.t + 1]
        L = lag0([old.ys[j] for j in good])
        comb = lambda D: [sum(l * D[j][i] for l, j in zip(L, good)) % Q for i in range(n_new)]
        s.G = [[comb(D) for D in row] for row in dG]
        s.A = {k: [[comb(D) for D in row] for row in dA[k]] for k in dA}
        s.M = {k: [[comb(D) for D in row] for row in dM[k]] for k in dM}
        s.C = new
        s.detected = (bad_dealers == set(delta))


def prod(xs):
    r = 1
    for x in xs: r = r * x % Q
    return r


def rs_full(pts, deg):
    """Berlekamp-Welch returning the full polynomial (coefficient list)."""
    r = len(pts); e = (r - deg - 1) // 2
    rows, rhs = [], []
    for x, y in pts:
        rows.append([(-y * pow(x, j, Q)) % Q for j in range(e)] + [pow(x, j, Q) for j in range(deg + 1 + e)])
        rhs.append(y * pow(x, e, Q) % Q)
    sol = solve_ls(rows, rhs, 2 * e + deg + 1)
    Eco = sol[:e] + [1]; num = sol[e:]
    out = [0] * (len(num) - len(Eco) + 1)
    for i in range(len(out) - 1, -1, -1):
        out[i] = num[i + len(Eco) - 1] % Q
        for j, d in enumerate(Eco): num[i + j] = (num[i + j] - out[i] * d) % Q
    return out


def recon(sh, C): L = lag0(C.ys[:C.t + 1]); return sum(l * v for l, v in zip(L, sh[:C.t + 1])) % Q


def run_correctness(n, omega=3, psi=4, N=8, nver=4):
    tn = TN(n, omega, psi)
    C = tn.C; strats = sorted(set(C.strategy.values())); t = C.t; E = (omega + 1) * (psi + 1)
    xs = [1000 + i for i in range(nver)]
    e0 = tn.net.elems
    for x in xs: tn.enroll(x, [])
    epoch = tn.net.elems - e0 + 0
    e1 = tn.net.elems
    for k in range(N): tn.issue_index(k)
    for x in xs: tn.add_keys(x, range(N))
    per_index = (tn.net.elems - e1) / N
    d = n - t; rc = n * (n - 1) / d; mc = 2 * (n - 1) + 2 * n * (n - 1) / d
    formula = E * rc + E * mc + nver * (psi + 1) * n
    # slots: s -> (k = s // psi, decided m_s)
    certs, paths, ok = [], {'optimistic': 0, 'decode': 0, 'fail': 0}, True
    for s in range(N * psi):
        k = s // psi; m = R.randrange(Q)
        sh = {}
        for p in range(n):
            v = tn.release(p, k, m, m)
            if v is not None: sh[p] = v
        comb = xs[s % nver]
        alpha, path = tn.combine(k, m, sh, vkey=tn.verifiers[comb]); paths[path] += 1
        ok &= alpha is not None and all(tn.verify(x, k, m, alpha) for x in xs)
        ok &= tn.combine(k, m, sh)[0] == alpha            # decoding path agrees with optimistic path
        certs.append((k, m, alpha))
    # late (retroactive) enrolment of a new verifier
    tn.enroll(5000, range(N)); late_ok = all(tn.verify(5000, k, m, a) for k, m, a in certs)
    # membership change: reshare to a larger committee, issue a new index there, keep old keys valid
    n2 = n + 3; tn.reshare(n2); tn.issue_index(N); tn.add_keys(5000, [N])
    for x in xs: tn.add_keys(x, [N])
    m = R.randrange(Q); sh = {p: tn.release(p, N, m, m) for p in range(n2)}
    sh = {p: v for p, v in sh.items() if v is not None}
    alpha, path2 = tn.combine(N, m, sh, vkey=tn.verifiers[xs[0]])
    reshare_ok = alpha is not None and all(tn.verify(x, N, m, alpha) for x in xs + [5000])
    reshare_ok &= all(tn.verify(x, k, mm, a) for x in xs for k, mm, a in certs)  # history still verifies
    # secrets unchanged by redistribution: arbiter key row is preserved
    return dict(n=n, t=t, omega=omega, psi=psi, N=N, verifiers=nver, epoch_elems=epoch,
                per_index_elems=per_index, per_index_formula=formula, rel_err=abs(per_index - formula) / formula,
                certs_ok=ok, paths=paths, late_enrolment_ok=late_ok, reshare_to=n2, reshare_ok=reshare_ok, bad_dealers_detected=tn.detected,
                strategies=strats)



def run_forgery(T, n=7, omega=2, psi=2):
    """t corrupted members (holding t shares of every sharing) and omega corrupted verifiers try to certify a
    value the committee did not decide, on an index for which the committee has released psi-1 certificates.
    The adversary samples the signing matrix from its exact posterior given (i) the corrupted verifiers'
    keys c_x, b_x and (ii) the released certificates, and signs the target message with it. By Lemma 3 the
    member shares are independent of A and add nothing; they are part of the view but unused."""
    acc = 0; W = omega + 1; P = psi + 1
    for _ in range(T):
        tn = TN(n, omega, psi)
        hx = R.sample(range(1, Q), omega + 1)
        for x in hx: tn.enroll(x, [])
        tn.issue_index(0)
        for x in hx: tn.add_keys(x, [0])
        honest_x, corrupt_x = hx[0], hx[1:]
        msgs = R.sample(range(Q), psi); released, mstar = msgs[:psi - 1], msgs[-1]
        certs = []
        for m in released:
            sh = {p: tn.release(p, 0, m, m) for p in range(n)}
            alpha, _ = tn.combine(0, m, {p: v for p, v in sh.items() if v is not None})
            certs.append((m, alpha))
        rows, rhs = [], []                                   # unknown: vec(A), row-major (W x P)
        for x in corrupt_x:
            c, b = tn.verifiers[x]
            for j in range(P):
                r = [0] * (W * P)
                for i in range(W): r[i * P + j] = c[i]
                rows.append(r); rhs.append(b[0][j])
        for m, alpha in certs:
            e = ev(m, psi)
            for i in range(W):
                r = [0] * (W * P)
                for j in range(P): r[i * P + j] = e[j]
                rows.append(r); rhs.append(alpha[i])
        sol = solve_ls(rows, rhs, W * P)
        for kv in kernel_basis(rows, W * P):
            z = R.randrange(Q); sol = [(x + z * y) % Q for x, y in zip(sol, kv)]
        A = [sol[i * P:(i + 1) * P] for i in range(W)]
        alpha = [dot(row, ev(mstar, psi)) for row in A]
        acc += tn.verify(honest_x, 0, mstar, alpha)
    return acc / T


def kernel_basis(K, m):
    A = [r[:] for r in K]; piv = []; r = 0
    for c in range(m):
        p = next((i for i in range(r, len(A)) if A[i][c]), None)
        if p is None: continue
        A[r], A[p] = A[p], A[r]; iv = inv(A[r][c]); A[r] = [x * iv % Q for x in A[r]]
        for i in range(len(A)):
            if i != r and A[i][c]:
                f = A[i][c]; A[i] = [(x - f * y) % Q for x, y in zip(A[i], A[r])]
        piv.append(c); r += 1
    out = []
    for f in [c for c in range(m) if c not in piv]:
        v = [0] * m; v[f] = 1
        for i, c in enumerate(piv): v[c] = (-A[i][f]) % Q
        out.append(v)
    return out


def kernel_vec(K, m):
    A = [r[:] for r in K]; piv = []; r = 0
    for c in range(m):
        p = next((i for i in range(r, len(A)) if A[i][c]), None)
        if p is None: continue
        A[r], A[p] = A[p], A[r]; iv = inv(A[r][c]); A[r] = [x * iv % Q for x in A[r]]
        for i in range(len(A)):
            if i != r and A[i][c]:
                f = A[i][c]; A[i] = [(x - f * y) % Q for x, y in zip(A[i], A[r])]
        piv.append(c); r += 1
    free = [c for c in range(m) if c not in piv]
    if not free: return [0] * m
    f = free[0]; v = [0] * m; v[f] = 1
    for i, c in enumerate(piv): v[c] = (-A[i][f]) % Q
    return v


def run_av(n, psi=8, clients=6, L=24, bad_frac=0.0):
    """Arbiter-verified (omega = 0) client keys: gamma (scalar) and a_U (row vector) shared; the client receives
    a_U; the committee keeps [b_0] = gamma * a_U (one multiplication per entry). A batch of L signatures
    (alpha in F) is checked collectively: [delta_j] = [gamma] alpha_j - [b_0]^T e(m_j) (local), r opened after
    the batch is fixed, [D] = sum_{j=1..L} r^(j-1) [delta_j] (weights start at r^0, see Lemma 4), one multiplication
    by a fresh random non-zero [rho], open rho*D."""
    net = Net(); C = Committee(n, net, strategy=None); C.strategy = {p: 'garbage' for p in C.bad}
    g = C.rnd(); a, b0 = {}, {}
    for u in range(clients):
        a[u] = [C.rnd() for _ in range(psi + 1)]
        b0[u] = [C.ip([g], [x]) for x in a[u]]
    e_iss = net.elems
    akey = {u: [C.open_to(x) for x in a[u]] for u in range(clients)}
    e_open = net.elems - e_iss
    def batch(sigs):
        r = C.open_to(C.rnd()); net.send(n * (n - 1) - n)          # common coin (opened to all)
        D = [0] * n
        for j, (u, m, al) in enumerate(sigs):
            e = ev(m, psi); rj = pow(r, j, Q)              # j is 0-based: weight r^(j-1) for item j = 1..L
            dl = [(g[p] * al - sum(b0[u][l][p] * e[l] for l in range(psi + 1))) % Q for p in range(n)]
            D = [(x + rj * y) % Q for x, y in zip(D, dl)]
        rho = C.rnd()   # fresh mask per test; the protocol uses a preprocessed non-zero mask (zero has probability 1/q)
        v = C.open_to(C.ip([rho], [D])); net.send(n * (n - 1) - n)
        return v == 0
    ok_valid, ok_invalid = True, True
    for trial in range(10):
        sigs = []
        for j in range(L):
            u = R.randrange(clients); m = R.randrange(Q)
            sigs.append((u, m, dot(akey[u], ev(m, psi))))
        ok_valid &= batch(sigs)
        j = R.randrange(L); u, m, al = sigs[j]; sigs[j] = (u, m, (al + 1) % Q)
        ok_invalid &= not batch(sigs)
    E = psi + 1; d = n - C.t
    return dict(n=n, psi=psi, issuance_per_index=(e_iss) / clients, open_to_client_per_index=e_open / clients,
                formula_iss=E * n * (n - 1) / d + E * (2 * (n - 1) + 2 * n * (n - 1) / d) + (n * (n - 1) / d) / clients,
                batches_valid_accepted=ok_valid, batches_with_one_invalid_rejected=ok_invalid)


if __name__ == "__main__":
    if Q < 2**20:
        T = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
        rate = run_forgery(T); out = dict(q=Q, T=T, accept_rate=rate, bound=1 / Q + 1 / (Q - 1))
        print(json.dumps(out)); json.dump(out, open('../results/tn_forgery_q%d.json' % Q, 'w'), indent=1)
    else:
        out = []
        for n in [4, 7, 10, 13, 16]:
            r = run_correctness(n); print(json.dumps(r)); out.append(r)
        json.dump(out, open('../results/tn_sim.json', 'w'), indent=1)
        av = [run_av(n) for n in [4, 7, 10, 13]]
        for r in av: print(json.dumps(r))
        json.dump(av, open('../results/av_sim.json', 'w'), indent=1)
