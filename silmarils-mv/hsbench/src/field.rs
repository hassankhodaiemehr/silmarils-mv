//! Arithmetic in F_p, p = 2^255 - 19, radix 2^51 (port of the paper's fe25519.h).
use rand::RngCore;

const MASK51: u64 = (1u64 << 51) - 1;

#[derive(Clone, Copy, Debug, Default)]
pub struct Fe(pub [u64; 5]);

impl Fe {
    pub const ZERO: Fe = Fe([0; 5]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    pub fn from_u64(x: u64) -> Fe {
        let mut f = Fe([x & MASK51, x >> 51, 0, 0, 0]);
        f.carry();
        f
    }
    pub fn from_bytes(s: &[u8; 32]) -> Fe {
        let w = |i: usize| u64::from_le_bytes(s[8 * i..8 * i + 8].try_into().unwrap());
        let (w0, w1, w2, w3) = (w(0), w(1), w(2), w(3));
        Fe([
            w0 & MASK51,
            ((w0 >> 51) | (w1 << 13)) & MASK51,
            ((w1 >> 38) | (w2 << 26)) & MASK51,
            ((w2 >> 25) | (w3 << 39)) & MASK51,
            (w3 >> 12) & MASK51,
        ])
    }
    pub fn random<R: RngCore>(rng: &mut R) -> Fe {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b[31] &= 0x7f;
        Fe::from_bytes(&b)
    }
    #[inline]
    pub fn carry(&mut self) {
        let h = &mut self.0;
        let mut c;
        c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
        c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
        c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
        c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
        c = h[4] >> 51; h[4] &= MASK51; h[0] += c * 19;
        c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
    }
    /// lazy add (no carry); caller carries before multiplying sums of more than ~8 terms
    #[inline]
    pub fn add_lazy(&mut self, g: &Fe) {
        for i in 0..5 { self.0[i] += g.0[i]; }
    }
    #[inline]
    pub fn add(&self, g: &Fe) -> Fe {
        let mut h = *self;
        h.add_lazy(g);
        h.carry();
        h
    }
    /// h = f - g (both carried)
    #[inline]
    pub fn sub(&self, g: &Fe) -> Fe {
        let mut a = *self; a.carry();
        let mut b = *g; b.carry();
        let mut h = Fe([
            a.0[0] + 0xFFFFFFFFFFFDA * 2 - b.0[0],
            a.0[1] + 0xFFFFFFFFFFFFE * 2 - b.0[1],
            a.0[2] + 0xFFFFFFFFFFFFE * 2 - b.0[2],
            a.0[3] + 0xFFFFFFFFFFFFE * 2 - b.0[3],
            a.0[4] + 0xFFFFFFFFFFFFE * 2 - b.0[4],
        ]);
        h.carry();
        h
    }
    #[inline]
    pub fn mul(&self, g: &Fe) -> Fe {
        let a = &self.0;
        let b = &g.0;
        let (b1, b2, b3, b4) = (b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19);
        let m = |x: u64, y: u64| (x as u128) * (y as u128);
        let t0 = m(a[0], b[0]) + m(a[1], b4) + m(a[2], b3) + m(a[3], b2) + m(a[4], b1);
        let mut t1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4) + m(a[3], b3) + m(a[4], b2);
        let mut t2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4) + m(a[4], b3);
        let mut t3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4);
        let mut t4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        let r0 = (t0 as u64) & MASK51; t1 += t0 >> 51;
        let r1 = (t1 as u64) & MASK51; t2 += t1 >> 51;
        let r2 = (t2 as u64) & MASK51; t3 += t2 >> 51;
        let r3 = (t3 as u64) & MASK51; t4 += t3 >> 51;
        let r4 = (t4 as u64) & MASK51;
        let c = (t4 >> 51) as u64;
        let mut r0 = r0 + c * 19;
        let c = r0 >> 51;
        r0 &= MASK51;
        Fe([r0, r1 + c, r2, r3, r4])
    }
    pub fn sq(&self) -> Fe { self.mul(self) }
    pub fn freeze(&self) -> Fe {
        let mut h = *self;
        h.carry(); h.carry();
        let h = &mut h.0;
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51; q = (h[2] + q) >> 51; q = (h[3] + q) >> 51; q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        let mut c;
        c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
        c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
        c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
        c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
        h[4] &= MASK51;
        Fe(*h)
    }
    pub fn eq(&self, g: &Fe) -> bool { self.freeze().0 == g.freeze().0 }
    pub fn is_zero(&self) -> bool { self.eq(&Fe::ZERO) }
    /// z^(p-2)
    pub fn inv(&self) -> Fe {
        let mut e = [0xffu8; 32];
        e[0] = 0xeb;
        e[31] = 0x7f;
        let mut r = Fe::ONE;
        for i in (0..255).rev() {
            r = r.sq();
            if (e[i >> 3] >> (i & 7)) & 1 == 1 { r = r.mul(self); }
        }
        r
    }
    pub fn neg(&self) -> Fe { Fe::ZERO.sub(self) }
    pub fn to_bytes(&self) -> [u8; 32] {
        let h = self.freeze().0;
        let w = [h[0] | (h[1] << 51), (h[1] >> 13) | (h[2] << 38), (h[2] >> 26) | (h[3] << 25), (h[3] >> 39) | (h[4] << 12)];
        let mut s = [0u8; 32];
        for i in 0..4 { s[8 * i..8 * i + 8].copy_from_slice(&w[i].to_le_bytes()); }
        s
    }
}

/// inner product with lazy reduction
#[inline]
pub fn dot(x: &[Fe], y: &[Fe]) -> Fe {
    let mut acc = Fe::ZERO;
    for (i, (a, b)) in x.iter().zip(y.iter()).enumerate() {
        acc.add_lazy(&a.mul(b));
        if i & 7 == 7 { acc.carry(); }
    }
    acc.carry();
    acc
}

/// e(m) = (1, m, ..., m^psi) with log-depth dependency
pub fn powers(m: &Fe, psi: usize) -> Vec<Fe> {
    let mut e = vec![Fe::ONE; psi + 1];
    if psi >= 1 { e[1] = *m; }
    for k in 2..=psi {
        let j = k >> 1;
        e[k] = if k & 1 == 1 { e[j].mul(&e[j + 1]) } else { e[j].sq() };
    }
    e
}

/// Lagrange coefficients at 0 for distinct points xs (batch inversion).
pub fn lagrange0(xs: &[Fe]) -> Vec<Fe> {
    let k = xs.len();
    let mut num = Fe::ONE;
    for x in xs { num = num.mul(x); }
    let mut den = vec![Fe::ONE; k];
    for i in 0..k {
        let mut d = xs[i];
        for j in 0..k { if i != j { d = d.mul(&xs[j].sub(&xs[i])); } }
        den[i] = d;
    }
    let mut pre = vec![Fe::ONE; k + 1];
    for i in 0..k { pre[i + 1] = pre[i].mul(&den[i]); }
    let mut iv = pre[k].inv();
    let mut out = vec![Fe::ZERO; k];
    for i in (0..k).rev() {
        let ti = iv.mul(&pre[i]);
        iv = iv.mul(&den[i]);
        out[i] = ti.mul(&num);
    }
    out
}

pub fn from_hash(h: &[u8; 32]) -> Fe {
    let mut b = *h;
    b[31] &= 0x7f;
    Fe::from_bytes(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    #[test]
    fn field_basic() {
        let mut r = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        for _ in 0..100 {
            let a = Fe::random(&mut r);
            let b = Fe::random(&mut r);
            assert!(a.mul(&a.inv()).eq(&Fe::ONE));
            assert!(a.add(&b).sub(&b).eq(&a));
            assert!(a.mul(&b).eq(&b.mul(&a)));
        }
        // lagrange: interpolate f(x)=3+5x at x=1,2 -> f(0)=3
        let xs = [Fe::from_u64(1), Fe::from_u64(2)];
        let l = lagrange0(&xs);
        let v = l[0].mul(&Fe::from_u64(8)).add(&l[1].mul(&Fe::from_u64(13)));
        assert!(v.eq(&Fe::from_u64(3)));
    }
}
