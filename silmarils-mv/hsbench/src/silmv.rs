//! SILMARILS-MV keys (dealer-issued for the online benchmark; issuance cost is accounted by the paper's
//! closed-form model). IV mode: every validator signs and verifies. TN mode: the committee holds degree-t
//! shares of the signing matrices; external auditors verify certificates.
use crate::field::{dot, lagrange0, powers, Fe};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub fn lam(x: &Fe, w: usize) -> Vec<Fe> { powers(x, w) }

/// c = Gamma^T lambda(x), Gamma row-major (w+1)x(w+1)
fn anchor_key(gamma: &[Fe], x: &Fe, w: usize) -> Vec<Fe> {
    let l = lam(x, w);
    (0..=w).map(|j| {
        let col: Vec<Fe> = (0..=w).map(|i| gamma[i * (w + 1) + j]).collect();
        dot(&l, &col)
    }).collect()
}

/// b = A^T c, A row-major (w+1)x(psi+1)
fn key_row(a: &[Fe], c: &[Fe], w: usize, psi: usize) -> Vec<Fe> {
    (0..=psi).map(|j| {
        let col: Vec<Fe> = (0..=w).map(|i| a[i * (psi + 1) + j]).collect();
        dot(c, &col)
    }).collect()
}

/// alpha = A e
pub fn sign_core(a: &[Fe], e: &[Fe], w: usize, psi: usize) -> Vec<Fe> {
    (0..=w).map(|i| dot(&a[i * (psi + 1)..(i + 1) * (psi + 1)], e)).collect()
}

// ------------------------------------------------------------------ IV mode
pub struct IvSigner { pub a: Vec<Vec<Fe>> }          // [k] -> (w+1)(psi+1)
pub struct IvVerifier { pub c: Vec<Fe>, pub b: Vec<Fe> } // b[(u*K + k)*(psi+1) + j]
pub struct IvParams { pub n: usize, pub w: usize, pub psi: usize, pub k: usize }

pub fn iv_dealer(p: &IvParams, seed: u64) -> (Vec<IvSigner>, Vec<IvVerifier>) {
    let (n, w, psi, kk) = (p.n, p.w, p.psi, p.k);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let gamma: Vec<Fe> = (0..(w + 1) * (w + 1)).map(|_| Fe::random(&mut rng)).collect();
    let signers: Vec<IvSigner> = (0..n).map(|_| IvSigner {
        a: (0..kk).map(|_| (0..(w + 1) * (psi + 1)).map(|_| Fe::random(&mut rng)).collect()).collect(),
    }).collect();
    let verifiers = (0..n).map(|i| {
        let c = anchor_key(&gamma, &Fe::from_u64(i as u64 + 1), w);
        let mut b = Vec::with_capacity(n * kk * (psi + 1));
        for s in &signers { for k in 0..kk { b.extend(key_row(&s.a[k], &c, w, psi)); } }
        IvVerifier { c, b }
    }).collect();
    (signers, verifiers)
}

impl IvVerifier {
    pub fn verify(&self, p: &IvParams, signer: usize, k: usize, e: &[Fe], alpha: &[Fe]) -> bool {
        let off = (signer * p.k + k % p.k) * (p.psi + 1);
        dot(&self.c, alpha).eq(&dot(&self.b[off..off + p.psi + 1], e))
    }
    pub fn agg_verify(&self, p: &IvParams, signers: &[(usize, usize)], e: &[Fe], alpha: &[Fe]) -> bool {
        // sum_U b_{U,k_U}: accumulate keys, then one inner product with e(m)
        let mut acc = vec![Fe::ZERO; p.psi + 1];
        for (cnt, &(u, k)) in signers.iter().enumerate() {
            let off = (u * p.k + k % p.k) * (p.psi + 1);
            for j in 0..=p.psi { acc[j].add_lazy(&self.b[off + j]); }
            if cnt & 7 == 7 { for x in acc.iter_mut() { x.carry(); } }
        }
        for x in acc.iter_mut() { x.carry(); }
        dot(&self.c, alpha).eq(&dot(&acc, e))
    }
}

// ------------------------------------------------------------------ TN mode
pub struct TnParams { pub n: usize, pub t: usize, pub w: usize, pub psi: usize, pub k: usize }
pub struct TnMember { pub share: Vec<Vec<Fe>> }        // [k] -> A_k(eta_j), (w+1)(psi+1)
pub struct TnVerifier { pub c: Vec<Fe>, pub b: Vec<Vec<Fe>> } // b[k] (psi+1)

pub fn tn_dealer(p: &TnParams, nver: usize, seed: u64) -> (Vec<TnMember>, Vec<TnVerifier>) {
    let (n, t, w, psi, kk) = (p.n, p.t, p.w, p.psi, p.k);
    let e = (w + 1) * (psi + 1);
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x7a7a);
    let gamma: Vec<Fe> = (0..(w + 1) * (w + 1)).map(|_| Fe::random(&mut rng)).collect();
    let mut members: Vec<TnMember> = (0..n).map(|_| TnMember { share: Vec::with_capacity(kk) }).collect();
    let mut amats = Vec::with_capacity(kk);
    for _ in 0..kk {
        // coefficient matrices R_0 = A, R_1..R_t
        let coeffs: Vec<Vec<Fe>> = (0..=t).map(|_| (0..e).map(|_| Fe::random(&mut rng)).collect()).collect();
        for (j, m) in members.iter_mut().enumerate() {
            let y = Fe::from_u64(j as u64 + 1);
            let mut sh = vec![Fe::ZERO; e];
            // Horner over l = t..0
            for l in (0..=t).rev() {
                for i in 0..e { sh[i] = sh[i].mul(&y).add(&coeffs[l][i]); }
            }
            m.share.push(sh);
        }
        amats.push(coeffs.into_iter().next().unwrap());
    }
    let verifiers = (0..nver).map(|i| {
        let c = anchor_key(&gamma, &Fe::from_u64(1_000_000 + i as u64), w);
        let b = amats.iter().map(|a| key_row(a, &c, w, psi)).collect();
        TnVerifier { c, b }
    }).collect();
    (members, verifiers)
}

impl TnVerifier {
    pub fn verify(&self, p: &TnParams, k: usize, e: &[Fe], alpha: &[Fe]) -> bool {
        dot(&self.c, alpha).eq(&dot(&self.b[k % p.k], e))
    }
}

/// combine shares {(member index j, share)} by Lagrange interpolation at 0 over the first t+1
pub fn tn_combine(shares: &[(usize, Vec<Fe>)], t: usize) -> Vec<Fe> {
    let sub = &shares[..t + 1];
    let xs: Vec<Fe> = sub.iter().map(|(j, _)| Fe::from_u64(*j as u64 + 1)).collect();
    let l = lagrange0(&xs);
    let w1 = sub[0].1.len();
    (0..w1).map(|i| {
        let col: Vec<Fe> = sub.iter().map(|(_, s)| s[i]).collect();
        dot(&l, &col)
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn iv_and_tn() {
        let p = IvParams { n: 4, w: 1, psi: 4, k: 3 };
        let (s, v) = iv_dealer(&p, 7);
        let m = Fe::from_u64(12345);
        let e = powers(&m, p.psi);
        let a0 = sign_core(&s[0].a[2], &e, p.w, p.psi);
        let a1 = sign_core(&s[1].a[1], &e, p.w, p.psi);
        assert!(v[3].verify(&p, 0, 2, &e, &a0));
        let agg: Vec<Fe> = a0.iter().zip(a1.iter()).map(|(x, y)| x.add(y)).collect();
        assert!(v[2].agg_verify(&p, &[(0, 2), (1, 1)], &e, &agg));
        assert!(!v[2].agg_verify(&p, &[(0, 2), (1, 2)], &e, &agg));
        let tp = TnParams { n: 7, t: 2, w: 3, psi: 4, k: 2 };
        let (mem, ver) = tn_dealer(&tp, 2, 9);
        let sh: Vec<(usize, Vec<Fe>)> = [5usize, 1, 3].iter().map(|&j| (j, sign_core(&mem[j].share[1], &e, tp.w, tp.psi))).collect();
        let alpha = tn_combine(&sh, tp.t);
        assert!(ver[0].verify(&tp, 1, &e, &alpha));
        assert!(!ver[1].verify(&tp, 0, &e, &alpha));
    }
}
