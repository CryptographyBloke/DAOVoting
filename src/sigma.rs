//! Fiat–Shamir Σ-protocols used by the trustees (CGY Appendix B/C).
//!
//! Every proof is sent in the equivalent *challenge–response* form: the
//! verifier recomputes the commitments from the responses and checks the
//! challenge equation, so no commitment points travel or need validation.
//! Every hash binds a domain string, the session context (setup + sealed
//! board), the slot (gate) id, the trustee index and the full statement.

use crate::batch::{Job, eval_all};
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
        self.check(k, ctx, label, a, &eval_all(&self.jobs(a)))
    }
    /// Variable-base multiplications of verification: `[d]A_k` (2 per ciphertext).
    pub fn jobs(&self, a: &[Ct]) -> Vec<Job> {
        a.iter()
            .flat_map(|c| [Job::mul(c.a, &self.d), Job::mul(c.b, &self.d)])
            .collect()
    }
    /// Completes verification from the results `r` of [`Self::jobs`].
    pub fn check(&self, k: &Key, ctx: &[u8; 32], label: u64, a: &[Ct], r: &[G]) -> bool {
        if self.z.len() != a.len() || r.len() != 2 * a.len() {
            return false;
        }
        let e: Vec<Ct> = self
            .z
            .iter()
            .zip(r.chunks(2))
            .map(|(z, da)| k.enc0(z).sub(&Ct { a: da[0], b: da[1] }))
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
        self.check(tg, thi, ctx, label, hi, u, w, &eval_all(&self.jobs(u, w)))
    }
    /// Variable-base multiplications of verification: `[z]u`, `[d]w`.
    pub fn jobs(&self, u: &G, w: &G) -> [Job; 2] {
        [Job::mul(*u, &self.z), Job::mul(*w, &self.d)]
    }
    /// Completes verification from the results `r` of [`Self::jobs`].
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        tg: &FixedBase,
        thi: &FixedBase,
        ctx: &[u8; 32],
        label: u64,
        hi: &G,
        u: &G,
        w: &G,
        r: &[G],
    ) -> bool {
        if r.len() != 2 {
            return false;
        }
        let e1 = tg.mul(&self.z) - thi.mul(&self.d);
        let e2 = r[0] - r[1];
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
        self.check(k, tht, ctx, label, st, &eval_all(&self.jobs(st)))
    }

    /// Variable-base multiplications of verification, branch σ = 1 then −1:
    /// `[d_σ]D^σ_X` (2), `[d_σ]D^σ_Y` (2), `[d_σ]e` (1) — 10 jobs.
    pub fn jobs(&self, st: &CszStmt) -> Vec<Job> {
        let mut v = Vec::with_capacity(10);
        for (j, sigma) in [1i64, -1].into_iter().enumerate() {
            let (dx, dy) = branch_diffs(st, sigma);
            let d = &self.d[j];
            v.extend([
                Job::mul(dx.a, d),
                Job::mul(dx.b, d),
                Job::mul(dy.a, d),
                Job::mul(dy.b, d),
                Job::mul(*st.e, d),
            ]);
        }
        v
    }

    /// Completes verification from the results `r` of [`Self::jobs`].
    pub fn check(
        &self,
        k: &Key,
        tht: &FixedBase,
        ctx: &[u8; 32],
        label: u64,
        st: &CszStmt,
        r: &[G],
    ) -> bool {
        use ark_ff::Zero;
        // CGY Alg. 10 line 1: reject X_i of the form (1_G, *)
        if st.x1.a.is_zero() || r.len() != 10 {
            return false;
        }
        let mut c = [Ct::zero(); 4];
        let mut ce = [G::default(); 2];
        for j in 0..2 {
            let (ax, ay, q) = (&self.a[2 * j], &self.a[2 * j + 1], &r[5 * j..5 * j + 5]);
            c[2 * j] = k.enc0(ax).sub(&Ct { a: q[0], b: q[1] });
            c[2 * j + 1] = k.enc0(ay).sub(&Ct { a: q[2], b: q[3] });
            ce[j] = tht.mul(ax) - q[4];
        }
        csz_hash(ctx, label, k, st, &c, &ce) == self.d[0] + self.d[1]
    }
}

// ===================================================== v2 (T007)
//
// Commitment-form proofs over the cofactor-image encoding. On the wire every
// point is a lift (any Q with [8]Q = P); receivers replace it by [8]Q before
// use, so all points below are elements of the prime-order group G. A proof
// carries its commitments explicitly; the Fiat–Shamir challenge is the hash of
// the canonical statement and commitments (as in v1, under v2 domains), and
// verification reduces to linear relations `Σ fixed + Σ var = O`, which can
// be checked one by one or as one random linear combination (one MSM).

/// Fixed bases of v2 relations: `g`, `h`, `h~`, and the sender's weighted
/// share commitment `W_i = [λ_i]h_i`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    G,
    H,
    Ht,
    W,
}

/// One relation `Σ_b [s_b]Base_b + Σ_i [s_i]pts[i] = O`.
#[derive(Clone, Debug, Default)]
pub struct Row {
    pub fixed: Vec<(Base, F)>,
    pub var: Vec<(usize, F)>,
}

/// The relations of one proof and the points they refer to.
#[derive(Clone, Debug, Default)]
pub struct Rels {
    pub pts: Vec<G>,
    pub rows: Vec<Row>,
}

/// Fixed-base tables for the four bases.
pub struct Bases<'a> {
    pub g: &'a FixedBase,
    pub h: &'a FixedBase,
    pub ht: &'a FixedBase,
    pub w: Option<&'a FixedBase>,
}

impl Bases<'_> {
    fn mul(&self, b: Base, s: &F) -> G {
        match b {
            Base::G => self.g.mul(s),
            Base::H => self.h.mul(s),
            Base::Ht => self.ht.mul(s),
            Base::W => self.w.expect("W base").mul(s),
        }
    }
}

fn small_or_vmul(p: &G, s: &F) -> G {
    use ark_ff::{One, Zero};
    if s.is_one() {
        *p
    } else if (-*s).is_one() {
        -*p
    } else if s.is_zero() {
        G::default()
    } else {
        vmul(p, s)
    }
}

impl Rels {
    /// Individual (reference) check: every relation evaluated separately.
    pub fn check_each(&self, b: &Bases) -> bool {
        use ark_ff::Zero;
        self.rows.iter().all(|r| {
            let mut acc = G::default();
            for (base, s) in &r.fixed {
                acc += b.mul(*base, s);
            }
            for (i, s) in &r.var {
                acc += small_or_vmul(&self.pts[*i], s);
            }
            acc.is_zero()
        })
    }
}

/// Random-linear-combination accumulator: `Σ_rows ρ_row · row` with
/// independent coefficients `ρ ∈ [0, 2^128)`; coefficients of the same point
/// within one proof are merged.
#[derive(Clone, Debug, Default)]
pub struct Acc {
    pub fixed: [F; 4],
    pub pts: Vec<G>,
    pub sc: Vec<F>,
    pub rows: usize,
}

impl Acc {
    pub fn add<R: RngCore>(&mut self, rels: &Rels, rng: &mut R) {
        use ark_ff::Zero;
        let mut coef = vec![F::zero(); rels.pts.len()];
        for r in &rels.rows {
            let rho = F::from(((rng.next_u64() as u128) << 64) | rng.next_u64() as u128);
            for (base, s) in &r.fixed {
                self.fixed[*base as usize] += rho * s;
            }
            for (i, s) in &r.var {
                coef[*i] += rho * s;
            }
            self.rows += 1;
        }
        for (p, c) in rels.pts.iter().zip(coef) {
            if !c.is_zero() {
                self.pts.push(*p);
                self.sc.push(c);
            }
        }
    }
    pub fn merge(&mut self, o: Acc) {
        for i in 0..4 {
            self.fixed[i] += o.fixed[i];
        }
        self.pts.extend(o.pts);
        self.sc.extend(o.sc);
        self.rows += o.rows;
    }
    /// Fixed-base part of the combination (the MSM part is computed by the caller).
    pub fn fixed_part(&self, b: &Bases) -> G {
        [Base::G, Base::H, Base::Ht, Base::W]
            .iter()
            .filter(|x| b.w.is_some() || **x != Base::W)
            .map(|x| b.mul(*x, &self.fixed[*x as usize]))
            .sum()
    }
}

fn row(fixed: Vec<(Base, F)>, var: Vec<(usize, F)>) -> Row {
    Row { fixed, var }
}

/// v2 PoK-CSZ: commitments `c = [c_{1,X}, c_{1,Y}, c_{-1,X}, c_{-1,Y}]`,
/// `ce = [c_{1,e}, c_{-1,e}]`, challenge share `d_1` (`d_{-1} = H − d_1`),
/// responses `a = [a_{1,X}, a_{1,Y}, a_{-1,X}, a_{-1,Y}]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Csz2 {
    pub c: [Ct; 4],
    #[serde(with = "arkser_fast")]
    pub ce: [G; 2],
    #[serde(with = "arkser")]
    pub d1: F,
    #[serde(with = "arkser")]
    pub a: [F; 4],
}

fn csz2_hash(ctx: &[u8; 32], label: u64, k: &Key, st: &CszStmt, c: &[Ct], ce: &[G]) -> F {
    Hasher::new("wod/v2/csz", ctx)
        .u64(label)
        .pts(&[g(), k.h, h_tilde(), *st.e])
        .cts(&[*st.x0, *st.y0, *st.x1, *st.y1])
        .cts(c)
        .pts(ce)
        .scalar()
}

impl Csz2 {
    /// Statement in canonical form; returns the proof with *lifted* commitments.
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore + CryptoRng>(
        k: &Key,
        lk: &LiftKey,
        tht8: &FixedBase,
        ctx: &[u8; 32],
        label: u64,
        st: &CszStmt,
        s: i64,
        r1: &F,
        r2: &F,
        rng: &mut R,
    ) -> Self {
        let (al, be) = (rand_scalar(rng), rand_scalar(rng));
        let real_l = [lk.enc0(&al), lk.enc0(&be)];
        let real_el = tht8.mul(&al);
        let (ds, axs, ays) = (rand_scalar(rng), rand_scalar(rng), rand_scalar(rng));
        let (dx, dy) = branch_diffs(st, -s);
        let k8 = ds * inv8();
        let sim_l = [
            lk.enc0(&axs).sub(&dx.scale(&k8)),
            lk.enc0(&ays).sub(&dy.scale(&k8)),
        ];
        let sim_el = tht8.mul(&axs) - vmul(st.e, &k8);
        let (cl, cel) = if s == 1 {
            (
                [real_l[0], real_l[1], sim_l[0], sim_l[1]],
                [real_el, sim_el],
            )
        } else {
            (
                [sim_l[0], sim_l[1], real_l[0], real_l[1]],
                [sim_el, real_el],
            )
        };
        let c = cl.map(|x| x.clear8());
        let ce = cel.map(|x| clear8(&x));
        let d = csz2_hash(ctx, label, k, st, &c, &ce);
        let dr = d - ds;
        let (ax, ay) = (al + *r1 * dr, be + *r2 * dr);
        if s == 1 {
            Csz2 {
                c: cl,
                ce: cel,
                d1: dr,
                a: [ax, ay, axs, ays],
            }
        } else {
            Csz2 {
                c: cl,
                ce: cel,
                d1: ds,
                a: [axs, ays, ax, ay],
            }
        }
    }

    /// Relations of a canonical (decoded) proof; `None` if CGY Alg. 10 line 1
    /// (`X_i` of the form `(1_G, *)`) rejects.
    pub fn rels(&self, k: &Key, ctx: &[u8; 32], label: u64, st: &CszStmt) -> Option<Rels> {
        use ark_ff::Zero;
        if st.x1.a.is_zero() {
            return None;
        }
        let d = csz2_hash(ctx, label, k, st, &self.c, &self.ce);
        let ds = [self.d1, d - self.d1];
        let mut r = Rels::default();
        let m1 = -F::from(1u64);
        for (j, sigma) in [1i64, -1].into_iter().enumerate() {
            let (dx, dy) = branch_diffs(st, sigma);
            let b = r.pts.len();
            r.pts.extend([dx.a, dx.b, dy.a, dy.b, *st.e]);
            r.pts.extend([
                self.c[2 * j].a,
                self.c[2 * j].b,
                self.c[2 * j + 1].a,
                self.c[2 * j + 1].b,
                self.ce[j],
            ]);
            let (nd, ax, ay) = (-ds[j], self.a[2 * j], self.a[2 * j + 1]);
            r.rows
                .push(row(vec![(Base::G, ax)], vec![(b, nd), (b + 5, m1)]));
            r.rows
                .push(row(vec![(Base::H, ax)], vec![(b + 1, nd), (b + 6, m1)]));
            r.rows
                .push(row(vec![(Base::G, ay)], vec![(b + 2, nd), (b + 7, m1)]));
            r.rows
                .push(row(vec![(Base::H, ay)], vec![(b + 3, nd), (b + 8, m1)]));
            r.rows
                .push(row(vec![(Base::Ht, ax)], vec![(b + 4, nd), (b + 9, m1)]));
        }
        Some(r)
    }
}

/// v2 ZKP0: lifted commitments `e_k`, responses `z_k`; `d` is recomputed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Zkp02 {
    pub e: Vec<Ct>,
    #[serde(with = "arkser")]
    pub z: Vec<F>,
}

fn zkp02_hash(ctx: &[u8; 32], label: u64, a: &[Ct], e: &[Ct]) -> F {
    Hasher::new("wod/v2/zkp0", ctx)
        .u64(label)
        .cts(a)
        .cts(e)
        .scalar()
}

impl Zkp02 {
    /// `a` canonical (`A_k = Enc(0; r_k)`); returns lifted commitments.
    pub fn prove<R: RngCore + CryptoRng>(
        k: &Key,
        lk: &LiftKey,
        ctx: &[u8; 32],
        label: u64,
        a: &[Ct],
        r: &[F],
        rng: &mut R,
    ) -> Self {
        let w: Vec<F> = r.iter().map(|_| rand_scalar(rng)).collect();
        let el: Vec<Ct> = w.iter().map(|w| lk.enc0(w)).collect();
        let e: Vec<Ct> = el.iter().map(|x| x.clear8()).collect();
        let _ = k;
        let d = zkp02_hash(ctx, label, a, &e);
        let z = w.iter().zip(r).map(|(w, r)| *w + *r * d).collect();
        Zkp02 { e: el, z }
    }

    pub fn rels(&self, ctx: &[u8; 32], label: u64, a: &[Ct]) -> Option<Rels> {
        if self.z.len() != a.len() || self.e.len() != a.len() {
            return None;
        }
        let d = zkp02_hash(ctx, label, a, &self.e);
        let mut r = Rels::default();
        let m1 = -F::from(1u64);
        for ((x, e), z) in a.iter().zip(&self.e).zip(&self.z) {
            let b = r.pts.len();
            r.pts.extend([x.a, x.b, e.a, e.b]);
            r.rows
                .push(row(vec![(Base::G, *z)], vec![(b, -d), (b + 2, m1)]));
            r.rows
                .push(row(vec![(Base::H, *z)], vec![(b + 1, -d), (b + 3, m1)]));
        }
        Some(r)
    }
}

/// v2 DLEQ for a *pre-weighted* partial decryption `w = [λ_i s_i]u` against
/// the public base `W_i = [λ_i]h_i`; lifted commitments `e1, e2`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dleq2 {
    #[serde(with = "arkser_fast")]
    pub e1: G,
    #[serde(with = "arkser_fast")]
    pub e2: G,
    #[serde(with = "arkser")]
    pub z: F,
}

fn dleq2_hash(ctx: &[u8; 32], label: u64, wb: &G, u: &G, w: &G, e1: &G, e2: &G) -> F {
    Hasher::new("wod/v2/dleq", ctx)
        .u64(label)
        .pts(&[g(), *wb, *u, *w, *e1, *e2])
        .scalar()
}

impl Dleq2 {
    /// Returns the lifted share `[λ_i s_i / 8]u` and the proof (lifted commitments).
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore + CryptoRng>(
        tg: &FixedBase,
        lk: &LiftKey,
        ctx: &[u8; 32],
        label: u64,
        sw: &F,
        wb: &G,
        u: &G,
        rng: &mut R,
    ) -> (G, Self) {
        let wl = vmul(u, &(*sw * inv8()));
        let w = clear8(&wl);
        let al = rand_scalar(rng);
        let e2l = vmul(u, &(al * inv8()));
        let d = dleq2_hash(ctx, label, wb, u, &w, &tg.mul(&al), &clear8(&e2l));
        (
            wl,
            Dleq2 {
                e1: lk.tg.mul(&al),
                e2: e2l,
                z: al + *sw * d,
            },
        )
    }

    pub fn rels(&self, ctx: &[u8; 32], label: u64, wb: &G, u: &G, w: &G) -> Rels {
        let d = dleq2_hash(ctx, label, wb, u, w, &self.e1, &self.e2);
        let m1 = -F::from(1u64);
        Rels {
            pts: vec![*u, *w, self.e1, self.e2],
            rows: vec![
                row(vec![(Base::G, self.z), (Base::W, -d)], vec![(2, m1)]),
                row(vec![], vec![(0, self.z), (1, -d), (3, m1)]),
            ],
        }
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

    // ---------------------------------------------------- v2 (T007)

    fn canon_csz(p: &Csz2) -> Csz2 {
        Csz2 {
            c: p.c.map(|x| x.clear8()),
            ce: p.ce.map(|x| clear8(&x)),
            ..p.clone()
        }
    }

    fn batch_ok(rels: &[Rels], b: &Bases) -> bool {
        use ark_ff::Zero;
        let mut acc = Acc::default();
        let mut rng = thread_rng();
        for r in rels {
            acc.add(r, &mut rng);
        }
        (acc.fixed_part(b) + crate::batch::msm_cpu(&acc.pts, &acc.sc)).is_zero()
    }

    #[test]
    fn v2_csz_complete_sound_and_batchable() {
        let mut rng = thread_rng();
        let k = Key::new(g() * rand_scalar(&mut rng));
        let lk = LiftKey::new(k.h);
        let (tht, tht8) = (
            FixedBase::new(h_tilde()),
            FixedBase::new(lift_of(&h_tilde())),
        );
        let b = Bases {
            g: &k.tg,
            h: &k.th,
            ht: &tht,
            w: None,
        };
        let x0 = k.enc(&F::from(5u64), &rand_scalar(&mut rng));
        let y0 = k.enc(&F::from(1u64), &rand_scalar(&mut rng));
        let t2 = ark_ed_on_bn254::EdwardsAffine::new_unchecked(Fb::from(0u64), -Fb::from(1u64));
        let mut all = Vec::new();
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
            let pl = Csz2::prove(&k, &lk, &tht8, &[0; 32], 1, &st, s, &r1, &r2, &mut rng);
            // lifts with arbitrary torsion offsets decode to the same proof
            let mut pt = pl.clone();
            pt.c[0].a += t2;
            pt.ce[1] += t2;
            let p = canon_csz(&pl);
            assert_eq!(canon_csz(&pt).c, p.c);
            let r = p.rels(&k, &[0; 32], 1, &st).unwrap();
            assert!(r.check_each(&b) && batch_ok(std::slice::from_ref(&r), &b));
            // altered response / challenge share / commitment / label / context
            let mut q = p.clone();
            q.a[1] += F::from(1u64);
            assert!(!q.rels(&k, &[0; 32], 1, &st).unwrap().check_each(&b));
            let mut q = p.clone();
            q.d1 += F::from(1u64);
            assert!(!batch_ok(&[q.rels(&k, &[0; 32], 1, &st).unwrap()], &b));
            let mut q = p.clone();
            q.c[2].b += g();
            assert!(!batch_ok(&[q.rels(&k, &[0; 32], 1, &st).unwrap()], &b));
            assert!(!p.rels(&k, &[0; 32], 2, &st).unwrap().check_each(&b));
            assert!(!batch_ok(&[p.rels(&k, &[9; 32], 1, &st).unwrap()], &b));
            // mixed signs are rejected
            let yb = k.reenc(&y0.small(-s), &r2);
            let st2 = CszStmt {
                x0: &x0,
                y0: &y0,
                x1: &x1,
                y1: &yb,
                e: &e,
            };
            assert!(!batch_ok(&[p.rels(&k, &[0; 32], 1, &st2).unwrap()], &b));
            all.push(r);
        }
        assert!(batch_ok(&all, &b));
    }

    #[test]
    fn v2_zkp0_and_weighted_dleq() {
        let mut rng = thread_rng();
        let k = Key::new(g() * rand_scalar(&mut rng));
        let lk = LiftKey::new(k.h);
        let tht = FixedBase::new(h_tilde());
        let rs = [rand_scalar(&mut rng), rand_scalar(&mut rng)];
        let a: Vec<Ct> = rs.iter().map(|r| k.enc0(r)).collect();
        let p = Zkp02::prove(&k, &lk, &[1; 32], 5, &a, &rs, &mut rng);
        let p = Zkp02 {
            e: p.e.iter().map(|x| x.clear8()).collect(),
            z: p.z,
        };
        let b = Bases {
            g: &k.tg,
            h: &k.th,
            ht: &tht,
            w: None,
        };
        let r0 = p.rels(&[1; 32], 5, &a).unwrap();
        assert!(r0.check_each(&b) && batch_ok(std::slice::from_ref(&r0), &b));
        let bad = [a[0], a[1].add(&Ct::trivial(1))];
        assert!(!batch_ok(&[p.rels(&[1; 32], 5, &bad).unwrap()], &b));
        // weighted DLEQ: w = [λ s]u against W = [λ]h_i = [λ s]g
        let (s, lam) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
        let wb = g() * (lam * s);
        let tw = FixedBase::new(wb);
        let u = g() * rand_scalar(&mut rng);
        let (wl, d) = Dleq2::prove(&k.tg, &lk, &[1; 32], 7, &(lam * s), &wb, &u, &mut rng);
        let w = clear8(&wl);
        assert_eq!(w, u * (lam * s));
        let d = Dleq2 {
            e1: clear8(&d.e1),
            e2: clear8(&d.e2),
            z: d.z,
        };
        let bw = Bases {
            g: &k.tg,
            h: &k.th,
            ht: &tht,
            w: Some(&tw),
        };
        let r1 = d.rels(&[1; 32], 7, &wb, &u, &w);
        assert!(r1.check_each(&bw) && batch_ok(&[r0.clone(), r1.clone()], &bw));
        assert!(!batch_ok(&[d.rels(&[1; 32], 7, &wb, &u, &(w + g()))], &bw));
    }

    /// Two invalid relations with opposite residuals cancel under a plain sum
    /// but not under independent random coefficients; a torsion residual of
    /// order 2 survives an even coefficient, which is why v2 only ever forms
    /// combinations of elements of G.
    #[test]
    fn cancellation_and_torsion_residuals() {
        use ark_ff::Zero;
        let mut rng = thread_rng();
        let k = Key::new(g() * rand_scalar(&mut rng));
        let tht = FixedBase::new(h_tilde());
        let b = Bases {
            g: &k.tg,
            h: &k.th,
            ht: &tht,
            w: None,
        };
        let delta = g() * rand_scalar(&mut rng);
        // rows "P1 = O" and "P2 = O" with P1 = Δ, P2 = −Δ
        let rel = |p: G| Rels {
            pts: vec![p],
            rows: vec![row(vec![], vec![(0, F::from(1u64))])],
        };
        let (r1, r2) = (rel(delta), rel(-delta));
        assert!((delta + (-delta)).is_zero()); // naive sum accepts
        assert!(!batch_ok(&[r1, r2], &b)); // randomized check rejects
        let t2 = ark_ed_on_bn254::EdwardsAffine::new_unchecked(Fb::from(0u64), -Fb::from(1u64));
        let t: G = t2.into();
        assert!((t * F::from(2u64)).is_zero() && !(t * F::from(3u64)).is_zero());
        let _ = &mut rng;
    }
}
