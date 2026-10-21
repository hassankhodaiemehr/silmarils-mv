"""SILMARILS-MV reference implementation (pure Python, any prime field).

Core objects
  signer key  : A[k] in F_q^{(omega+1) x (psi+1)}  for index k in [N]
  verifier key: c in F_q^{omega+1}; b[U][k] = c^T A[U][k] in F_q^{psi+1}
  signature   : (U, k, m, alpha) with alpha = A[k] e(m), e(m) = (1, m, ..., m^psi)
  verify      : <c, alpha> == <b[U][k], e(m)>
"""
import secrets, hashlib

def rand(q): return secrets.randbelow(q)

def evec(m, psi, q):
    v, x = [], 1
    for _ in range(psi + 1):
        v.append(x); x = x * m % q
    return v

def matvec(A, v, q): return [sum(a * b for a, b in zip(row, v)) % q for row in A]
def dot(u, v, q): return sum(a * b for a, b in zip(u, v)) % q
def vecmat(c, A, q):  # c^T A
    cols = len(A[0])
    return [sum(c[i] * A[i][j] for i in range(len(c))) % q for j in range(cols)]

def H2F(msg: bytes, q: int) -> int:
    """hash-then-sign domain extension (SHA3-512 reduced mod q, negligible bias)."""
    return int.from_bytes(hashlib.sha3_512(msg).digest(), 'big') % q

class Signer:
    def __init__(self, uid, A_list, psi, q):
        self.uid, self.A, self.psi, self.q = uid, A_list, psi, q
        self.used = {k: [] for k in range(len(A_list))}   # stateful index bookkeeping
    def sign(self, k, m):
        if m not in self.used[k]:
            if len(self.used[k]) >= self.psi:
                raise ValueError("index %d exhausted (psi messages)" % k)
            self.used[k].append(m)
        return (self.uid, k, m, matvec(self.A[k], evec(m, self.psi, self.q), self.q))

class Verifier:
    def __init__(self, vid, c, bkeys, psi, q):
        self.vid, self.c, self.b, self.psi, self.q = vid, c, bkeys, psi, q  # b[uid][k]
    def verify(self, sig):
        uid, k, m, alpha = sig
        if uid not in self.b or not (0 <= k < len(self.b[uid])) or len(alpha) != len(self.c):
            return False
        return dot(self.c, alpha, self.q) == dot(self.b[uid][k], evec(m, self.psi, self.q), self.q)

def trusted_dealer(signers, verifiers, omega, psi, N, q, corrupt_c=None):
    """Ideal key-issuance functionality F_KI. corrupt_c: {vid: adversarial vector}."""
    corrupt_c = corrupt_c or {}
    A = {u: [[[rand(q) for _ in range(psi + 1)] for _ in range(omega + 1)] for _ in range(N)] for u in signers}
    C = {v: (corrupt_c[v] if v in corrupt_c else [rand(q) for _ in range(omega + 1)]) for v in verifiers}
    S = {u: Signer(u, A[u], psi, q) for u in signers}
    V = {v: Verifier(v, C[v], {u: [vecmat(C[v], A[u][k], q) for k in range(N)] for u in signers}, psi, q)
         for v in verifiers}
    return S, V, A, C

def is_valid(sig, A, psi, q):
    uid, k, m, alpha = sig
    return alpha == matvec(A[uid][k], evec(m, psi, q), q)

if __name__ == "__main__":
    q = 2**255 - 19
    S, V, A, C = trusted_dealer(["U1", "U2"], ["V%d" % i for i in range(7)], omega=2, psi=4, N=3, q=q)
    m = H2F(b"block 42 hash ...", q)
    s = S["U1"].sign(1, m)
    assert all(v.verify(s) for v in V.values())
    bad = (s[0], s[1], s[2], [(s[3][0] + 1) % q] + s[3][1:])
    assert not any(v.verify(bad) for v in V.values())
    print("self-test OK")
