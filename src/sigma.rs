//! Fiat–Shamir Σ-protocols used by the trustees (CGY Appendix B/C).
//!
//! Every proof is sent in the equivalent *challenge–response* form: the
//! verifier recomputes the commitments from the responses and checks the
//! challenge equation, so no commitment points travel or need validation.
//! Every hash binds a domain string, the session context (setup + sealed
//! board), the slot (gate) id, the trustee index and the full statement.

use crate::group::*;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Proof that `A_k = Enc(0; r_k)` for every k (CGY Alg. 5, AND-composed with
/// a shared challenge). Used for the rerandomization contributions (Alg. 8).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Zkp0 {
    #[serde(with = "arkser")]
    pub d: F,
    #[serde(with = "arkser")]
    pub z: Vec<F>,
}

fn zkp0_hash(ctx: &[u8; 32], label: u64, a: &[Ct], e: &[Ct]) -> F {
    Hasher::new("wod/zkp0", ctx)
        .u64(label)
        .cts(a)
        .cts(e)
        .scalar()
}

impl Zkp0 {
    pub fn prove<R: RngCore + CryptoRng>(
        k: &Key,
        ctx: &[u8; 32],
        label: u64,
        a: &[Ct],
        r: &[F],
        rng: &mut R,
    ) -> Self {
        let w: Vec<F> = r.iter().map(|_| rand_scalar(rng)).collect();
        let e: Vec<Ct> = w.iter().map(|w| k.enc0(w)).collect();
        let d = zkp0_hash(ctx, label, a, &e);
        let z = w.iter().zip(r).map(|(w, r)| *w + *r * d).collect();
        Zkp0 { d, z }
    }
    pub fn verify(&self, k: &Key, ctx: &[u8; 32], label: u64, a: &[Ct]) -> bool {
        if self.z.len() != a.len() {
            return false;
        }
        let e: Vec<Ct> = a
            .iter()
            .zip(&self.z)
            .map(|(a, z)| k.enc0(z).sub(&a.scale(&self.d)))
            .collect();
        zkp0_hash(ctx, label, a, &e) == self.d
    }
}

/// Proof that `log_g h_i = log_u w_i` (Chaum–Pedersen; CGY Alg. 4), i.e. that
/// `w_i = [s_i]u` is a correct partial decryption of a ciphertext with first
/// component `u`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dleq {
    #[serde(with = "arkser")]
    pub d: F,
    #[serde(with = "arkser")]
    pub z: F,
}

fn dleq_hash(ctx: &[u8; 32], label: u64, hi: &G, u: &G, w: &G, e1: &G, e2: &G) -> F {
    Hasher::new("wod/dleq", ctx)
        .u64(label)
        .pts(&[g(), *hi, *u, *w, *e1, *e2])
        .scalar()
}

impl Dleq {
    pub fn prove<R: RngCore + CryptoRng>(
        tg: &FixedBase,
        ctx: &[u8; 32],
        label: u64,
        s: &F,
        hi: &G,
        u: &G,
        w: &G,
        rng: &mut R,
    ) -> Self {
        let al = rand_scalar(rng);
        let (e1, e2) = (tg.mul(&al), vmul(u, &al));
        let d = dleq_hash(ctx, label, hi, u, w, &e1, &e2);
        Dleq { d, z: al + *s * d }
    }
    /// `thi` is the fixed-base table of the trustee's commitment `h_i`.
    pub fn verify(
        &self,
        tg: &FixedBase,
        thi: &FixedBase,
        ctx: &[u8; 32],
        label: u64,
        hi: &G,
        u: &G,
        w: &G,
    ) -> bool {
        let e1 = tg.mul(&self.z) - thi.mul(&self.d);
        let e2 = vmul(u, &self.z) - vmul(w, &self.d);
        dleq_hash(ctx, label, hi, u, w, &e1, &e2) == self.d
    }
}

/// CGY PoK-CSZ (Alg. 9/10): there are `s ∈ {1,-1}`, `r1`, `r2` with
/// `X_i = s·X_{i-1} + Enc(0;r1)`, `Y_i = s·Y_{i-1} + Enc(0;r2)`, `e = [r1]h~`.
/// Branch σ uses `D^σ_X = X_i − σ·X_{i-1}` and `D^σ_Y = Y_i − σ·Y_{i-1}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Csz {
    /// `[d_1, d_{-1}]`
    #[serde(with = "arkser")]
    pub d: [F; 2],
    /// `[a_{1,X}, a_{1,Y}, a_{-1,X}, a_{-1,Y}]`
    #[serde(with = "arkser")]
    pub a: [F; 4],
}

pub struct CszStmt<'a> {
    pub x0: &'a Ct,
    pub y0: &'a Ct,
    pub x1: &'a Ct,
    pub y1: &'a Ct,
    pub e: &'a G,
}

fn branch_diffs(st: &CszStmt, sigma: i64) -> (Ct, Ct) {
    if sigma == 1 {
        (st.x1.sub(st.x0), st.y1.sub(st.y0))
    } else {
        (st.x1.add(st.x0), st.y1.add(st.y0))
    }
}

fn csz_hash(ctx: &[u8; 32], label: u64, k: &Key, st: &CszStmt, c: &[Ct], ce: &[G]) -> F {
    Hasher::new("wod/csz", ctx)
        .u64(label)
        .pts(&[g(), k.h, h_tilde(), *st.e])
        .cts(&[*st.x0, *st.y0, *st.x1, *st.y1])
        .cts(c)
        .pts(ce)
        .scalar()
}

impl Csz {
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore + CryptoRng>(
        k: &Key,
        tht: &FixedBase,
        ctx: &[u8; 32],
        label: u64,
        st: &CszStmt,
        s: i64,
        r1: &F,
        r2: &F,
        rng: &mut R,
    ) -> Self {
        let (al, be) = (rand_scalar(rng), rand_scalar(rng));
        // real branch s
        let real = [k.enc0(&al), k.enc0(&be)];
        let real_e = tht.mul(&al);
        // simulated branch -s
        let (ds, axs, ays) = (rand_scalar(rng), rand_scalar(rng), rand_scalar(rng));
        let (dx, dy) = branch_diffs(st, -s);
        let sim = [
            k.enc0(&axs).sub(&dx.scale(&ds)),
            k.enc0(&ays).sub(&dy.scale(&ds)),
        ];
        let sim_e = tht.mul(&axs) - vmul(st.e, &ds);
        // order commitments as (branch 1, branch -1)
        let (c, ce) = if s == 1 {
            ([real[0], real[1], sim[0], sim[1]], [real_e, sim_e])
        } else {
            ([sim[0], sim[1], real[0], real[1]], [sim_e, real_e])
        };
        let d = csz_hash(ctx, label, k, st, &c, &ce);
        let dr = d - ds;
        let (ax, ay) = (al + *r1 * dr, be + *r2 * dr);
        if s == 1 {
            Csz {
                d: [dr, ds],
                a: [ax, ay, axs, ays],
            }
        } else {
            Csz {
                d: [ds, dr],
                a: [axs, ays, ax, ay],
            }
        }
    }

    pub fn verify(
        &self,
        k: &Key,
        tht: &FixedBase,
        ctx: &[u8; 32],
        label: u64,
        st: &CszStmt,
    ) -> bool {
        use ark_ff::Zero;
        // CGY Alg. 10 line 1: reject X_i of the form (1_G, *)
        if st.x1.a.is_zero() {
            return false;
        }
        let mut c = [Ct::zero(); 4];
        let mut ce = [G::default(); 2];
        for (j, sigma) in [1i64, -1].into_iter().enumerate() {
            let (dx, dy) = branch_diffs(st, sigma);
            let (d, ax, ay) = (&self.d[j], &self.a[2 * j], &self.a[2 * j + 1]);
            c[2 * j] = k.enc0(ax).sub(&dx.scale(d));
            c[2 * j + 1] = k.enc0(ay).sub(&dy.scale(d));
            ce[j] = tht.mul(ax) - vmul(st.e, d);
        }
        csz_hash(ctx, label, k, st, &c, &ce) == self.d[0] + self.d[1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn zkp0_roundtrip() {
        let mut rng = thread_rng();
        let k = Key::new(g() * rand_scalar(&mut rng));
        let ctx = [7u8; 32];
        let r = [rand_scalar(&mut rng), rand_scalar(&mut rng)];
        let a = [k.enc0(&r[0]), k.enc0(&r[1])];
        let p = Zkp0::prove(&k, &ctx, 3, &a, &r, &mut rng);
        assert!(p.verify(&k, &ctx, 3, &a));
        assert!(!p.verify(&k, &ctx, 4, &a));
        let bad = [a[0], a[1].add(&Ct::trivial(1))];
        assert!(!p.verify(&k, &ctx, 3, &bad));
    }

    #[test]
    fn dleq_roundtrip() {
        let mut rng = thread_rng();
        let tg = FixedBase::new(g());
        let s = rand_scalar(&mut rng);
        let hi = g() * s;
        let thi = FixedBase::new(hi);
        let u = g() * rand_scalar(&mut rng);
        let w = u * s;
        let p = Dleq::prove(&tg, &[1; 32], 9, &s, &hi, &u, &w, &mut rng);
        assert!(p.verify(&tg, &thi, &[1; 32], 9, &hi, &u, &w));
        assert!(!p.verify(&tg, &thi, &[1; 32], 9, &hi, &u, &(w + g())));
    }

    #[test]
    fn csz_both_signs_and_forgery() {
        let mut rng = thread_rng();
        let k = Key::new(g() * rand_scalar(&mut rng));
        let tht = FixedBase::new(h_tilde());
        let x0 = k.enc(&F::from(5u64), &rand_scalar(&mut rng));
        let y0 = k.enc(&F::from(1u64), &rand_scalar(&mut rng));
        for s in [1i64, -1] {
            let (r1, r2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
            let x1 = k.reenc(&x0.small(s), &r1);
            let y1 = k.reenc(&y0.small(s), &r2);
            let e = tht.mul(&r1);
            let st = CszStmt {
                x0: &x0,
                y0: &y0,
                x1: &x1,
                y1: &y1,
                e: &e,
            };
            let p = Csz::prove(&k, &tht, &[0; 32], 1, &st, s, &r1, &r2, &mut rng);
            assert!(p.verify(&k, &tht, &[0; 32], 1, &st));
            // mixed signs (X with s, Y with -s) must not verify
            let y_bad = k.reenc(&y0.small(-s), &r2);
            let st2 = CszStmt {
                x0: &x0,
                y0: &y0,
                x1: &x1,
                y1: &y_bad,
                e: &e,
            };
            assert!(!p.verify(&k, &tht, &[0; 32], 1, &st2));
            // a sign outside {±1} must not verify
            let x2 = k.reenc(&x0.small(2), &r1);
            let st3 = CszStmt {
                x0: &x0,
                y0: &y0,
                x1: &x2,
                y1: &y1,
                e: &e,
            };
            assert!(!p.verify(&k, &tht, &[0; 32], 1, &st3));
        }
    }
}
