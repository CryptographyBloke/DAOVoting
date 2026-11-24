//! T009 second protocol: verifiable threshold ElGamal decryption of a batch
//! of `k` ciphertexts by a fixed decryption set of `t` out of `n` trustees.
//!
//! Setup is a documented trusted dealer (Shamir, degree `t−1`), as in the
//! CGY workload. Shares are pre-weighted: trustee `i` publishes
//! `w_{i,j} = [λ_i s_i]u_j` against `W_i = [λ_i]h_i`, so reconstruction is
//! `M_j = b_j − Σ_i w_{i,j}`. Five public-verification methods are compared
//! on identical inputs:
//!
//! * `cp` — one challenge–response Chaum–Pedersen proof per share
//!   (CGY/v1 DLEQ), verified individually;
//! * `cp-msm` — one commitment-form Chaum–Pedersen proof per share
//!   (T007 `Dleq2`), all verified as one random linear combination;
//! * `rfc9497` — one constant-size batched DLEQ per trustee in the
//!   RFC 9497 §2.2 form (full-width hashed composites, challenge–response);
//! * `lin` — one constant-size commitment-form batched DLEQ per trustee
//!   (the T009 [`crate::sigma::Lin`] proof) with all trustees verified in one
//!   MSM in which each `u_j`, shared by all trustees, appears **once**;
//! * `joint` — a joint batched Chaum–Pedersen proof for the *combined*
//!   decryptions `C_j = Σ_i w_{i,j}` (three extra trustee rounds); the
//!   public transcript carries `k` combined points and one proof.

use crate::batch::msm_cpu;
use crate::group::*;
use crate::shamir;
use crate::sigma::{Acc, Bases, Dleq, Dleq2, Lin, LinStmt};
use ark_ff::{UniformRand, Zero};
use rand::{CryptoRng, Rng, RngCore};
use rayon::prelude::*;
use serde_json::{Value, json};
use std::time::Instant;

pub const METHODS: [&str; 5] = ["cp", "cp-msm", "rfc9497", "lin", "joint"];
/// Attribution variants (§13.1 of reports/T009.md): RFC 9497 structure with
/// 128-bit composites; `lin` proofs verified per trustee (one MSM each) and
/// in one MSM without merging the shared bases u_j.
pub const ATTRIBUTION: [&str; 4] = ["rfc9497", "rfc9497-128", "lin-sep", "lin-nomerge"];
const PT: usize = 32;
const SC: usize = 32;

/// Public parameters and the (test-only) dealt key material.
pub struct Setup {
    pub ctx: [u8; 32],
    pub key: Key,
    /// weighted verification keys `W_i = [λ_i s_i]g` of the decryption set
    pub wb: Vec<G>,
    pub tw: Vec<FixedBase>,
    /// weighted secret shares `σ_i = λ_i s_i` (trustee-private)
    pub sigma: Vec<F>,
    pub lk: LiftKey,
}

impl Setup {
    pub fn deal<R: RngCore + CryptoRng>(n: usize, t: usize, rng: &mut R) -> Setup {
        let (x, shares) = shamir::deal(t - 1, n, rng);
        let set: Vec<usize> = (1..=t).collect();
        let lam = shamir::lagrange(&set);
        let sigma: Vec<F> = (0..t).map(|i| lam[i] * shares[i]).collect();
        let wb: Vec<G> = sigma.iter().map(|s| g() * s).collect();
        let h = g() * x;
        debug_assert_eq!(wb.iter().sum::<G>(), h);
        Setup {
            ctx: rng.r#gen(),
            key: Key::new(h),
            tw: wb.iter().map(|w| FixedBase::new(*w)).collect(),
            wb,
            sigma,
            lk: LiftKey::new(h),
        }
    }
    pub fn t(&self) -> usize {
        self.wb.len()
    }
    fn label(i: usize, j: usize) -> u64 {
        ((j as u64) << 8) | i as u64
    }
}

/// A batch of ciphertexts of random group-element messages.
pub fn ciphertexts<R: RngCore + CryptoRng>(s: &Setup, k: usize, rng: &mut R) -> (Vec<Ct>, Vec<G>) {
    (0..k)
        .map(|_| {
            let m = g() * F::rand(rng);
            let r = rand_scalar(rng);
            (
                Ct {
                    a: s.key.tg.mul(&r),
                    b: s.key.th.mul(&r) + m,
                },
                m,
            )
        })
        .unzip()
}

/// Everything a method publishes: per-trustee shares (or combined
/// decryptions for `joint`) and proofs, with their wire size.
pub enum Proofs {
    Cp(Vec<Vec<Dleq>>),
    CpMsm(Vec<Vec<Dleq2>>),
    /// proofs, 128-bit composites
    Rfc(Vec<(F, F)>, bool),
    /// proofs, verification mode: 0 merged one MSM, 1 per trustee, 2 one MSM unmerged
    Lin(Vec<Lin>, u8),
    /// combined decryptions, (A, B, z), challenge-binding data
    Joint(Vec<G>, (G, G, F)),
}

pub struct Published {
    /// `shares[i][j]` (empty for `joint`)
    pub shares: Vec<Vec<G>>,
    pub proofs: Proofs,
    pub bytes_public: usize,
    /// bytes exchanged among trustees only (joint: shares + rounds)
    pub bytes_internal: usize,
    pub rounds: usize,
}

fn shares_of(s: &Setup, cts: &[Ct]) -> Vec<Vec<G>> {
    (0..s.t())
        .map(|i| cts.par_iter().map(|c| vmul(&c.a, &s.sigma[i])).collect())
        .collect()
}

fn rfc_composites(s: &Setup, i: usize, u: &[G], w: &[G], short: bool) -> Vec<F> {
    let seed = Hasher::new("wod/t009/rfc9497-seed", &s.ctx)
        .pts(&[s.wb[i]])
        .digest();
    (0..u.len())
        .into_par_iter()
        .map(|j| {
            Hasher::new("wod/t009/rfc9497-composite", &s.ctx)
                .bytes(&seed)
                .u64(j as u64)
                .pts(&[u[j], w[j]])
                .scalar()
        })
        .map(|d| {
            if short {
                use ark_ff::{BigInteger, PrimeField};
                let b = d.into_bigint().to_bytes_le();
                F::from(u128::from_le_bytes(b[..16].try_into().unwrap()))
            } else {
                d
            }
        })
        .collect()
}

fn rfc_challenge(s: &Setup, i: usize, m: &G, z: &G, t2: &G, t3: &G) -> F {
    Hasher::new("wod/t009/rfc9497-challenge", &s.ctx)
        .pts(&[s.wb[i], *m, *z, *t2, *t3])
        .scalar()
}

fn lin_stmt(i: usize, u: &[G], w: &[G]) -> LinStmt {
    LinStmt {
        enc: vec![],
        dec: (0..u.len())
            .map(|j| (Setup::label(i, j), u[j], w[j]))
            .collect(),
    }
}

fn joint_seed(s: &Setup, u: &[G], c: &[G]) -> ([u8; 32], Vec<F>) {
    let st = LinStmt {
        enc: vec![],
        dec: (0..u.len()).map(|j| (j as u64, u[j], c[j])).collect(),
    };
    let seed = st.seed(&s.ctx, 0, usize::MAX, &s.key.h);
    let (_, be) = st.coeffs(&seed);
    (seed, be)
}

fn joint_challenge(s: &Setup, seed: &[u8; 32], a: &G, b: &G) -> F {
    Hasher::new("wod/t009/joint-challenge", &s.ctx)
        .bytes(seed)
        .pts(&[*a, *b])
        .scalar()
}

/// The trustees' side of a method (all trustees, sequentially per trustee).
pub fn prove<R: RngCore + CryptoRng>(
    s: &Setup,
    cts: &[Ct],
    method: &str,
    rng: &mut R,
) -> Published {
    let (t, k) = (s.t(), cts.len());
    let u: Vec<G> = cts.iter().map(|c| c.a).collect();
    let shares = shares_of(s, cts);
    let seeds: Vec<[u8; 32]> = (0..t).map(|_| rng.r#gen()).collect();
    match method {
        "cp" => {
            let p: Vec<Vec<Dleq>> = (0..t)
                .map(|i| {
                    (0..k)
                        .into_par_iter()
                        .map(|j| {
                            let mut r = rng_from(&seeds[i], j);
                            Dleq::prove(
                                &s.key.tg,
                                &s.ctx,
                                Setup::label(i, j),
                                &s.sigma[i],
                                &s.wb[i],
                                &u[j],
                                &shares[i][j],
                                &mut r,
                            )
                        })
                        .collect()
                })
                .collect();
            Published {
                shares,
                proofs: Proofs::Cp(p),
                bytes_public: t * k * (PT + 2 * SC),
                bytes_internal: 0,
                rounds: 1,
            }
        }
        "cp-msm" => {
            let p: Vec<Vec<Dleq2>> = (0..t)
                .map(|i| {
                    (0..k)
                        .into_par_iter()
                        .map(|j| {
                            let mut r = rng_from(&seeds[i], j);
                            let (_, d) = Dleq2::prove(
                                &s.key.tg,
                                &s.lk,
                                &s.ctx,
                                Setup::label(i, j),
                                &s.sigma[i],
                                &s.wb[i],
                                &u[j],
                                &mut r,
                            );
                            Dleq2 {
                                e1: clear8(&d.e1),
                                e2: clear8(&d.e2),
                                z: d.z,
                            }
                        })
                        .collect()
                })
                .collect();
            Published {
                shares,
                proofs: Proofs::CpMsm(p),
                bytes_public: t * k * (3 * PT + SC),
                bytes_internal: 0,
                rounds: 1,
            }
        }
        "rfc9497" | "rfc9497-128" => {
            let short = method == "rfc9497-128";
            let p = (0..t)
                .map(|i| {
                    let d = rfc_composites(s, i, &u, &shares[i], short);
                    let m = msm_cpu(&u, &d);
                    let z = vmul(&m, &s.sigma[i]);
                    let r = rand_scalar(rng);
                    let (t2, t3) = (s.key.tg.mul(&r), vmul(&m, &r));
                    let c = rfc_challenge(s, i, &m, &z, &t2, &t3);
                    (c, r - c * s.sigma[i])
                })
                .collect();
            Published {
                shares,
                proofs: Proofs::Rfc(p, short),
                bytes_public: t * (k * PT + 2 * SC),
                bytes_internal: 0,
                rounds: 1,
            }
        }
        "lin" | "lin-sep" | "lin-nomerge" => {
            let mode = match method {
                "lin" => 0,
                "lin-sep" => 1,
                _ => 2,
            };
            let p = (0..t)
                .map(|i| {
                    let st = lin_stmt(i, &u, &shares[i]);
                    let mut l =
                        Lin::prove(&s.lk, &s.ctx, 0, i, &s.wb[i], &st, &[], &s.sigma[i], rng);
                    l.t.iter_mut().for_each(|p| *p = clear8(p));
                    l
                })
                .collect();
            Published {
                shares,
                proofs: Proofs::Lin(p, mode),
                bytes_public: t * (k * PT + 2 * PT + SC),
                bytes_internal: 0,
                rounds: 1,
            }
        }
        "joint" => {
            // round 1: shares among trustees; everybody combines
            let c: Vec<G> = (0..k)
                .into_par_iter()
                .map(|j| (0..t).map(|i| shares[i][j]).sum())
                .collect();
            let (seed, be) = joint_seed(s, &u, &c);
            let ustar = msm_cpu(&u, &be);
            // round 2: hash commitments to (A_i, B_i); round 3: openings
            let r: Vec<F> = (0..t).map(|_| rand_scalar(rng)).collect();
            let ab: Vec<(G, G)> = r
                .iter()
                .map(|r| (s.key.tg.mul(r), vmul(&ustar, r)))
                .collect();
            let (a, b) = ab
                .iter()
                .fold((G::zero(), G::zero()), |acc, x| (acc.0 + x.0, acc.1 + x.1));
            let e = joint_challenge(s, &seed, &a, &b);
            // round 4: responses; the aggregator checks each one (blame)
            let zs: Vec<F> = (0..t).map(|i| r[i] + e * s.sigma[i]).collect();
            for i in 0..t {
                let di = msm_cpu(&shares[i], &be);
                assert!(
                    s.key.tg.mul(&zs[i]) == ab[i].0 + s.tw[i].mul(&e)
                        && vmul(&ustar, &zs[i]) == ab[i].1 + vmul(&di, &e),
                    "aggregator: trustee {i} response"
                );
            }
            Published {
                shares: vec![],
                proofs: Proofs::Joint(c, (a, b, zs.iter().sum())),
                bytes_public: k * PT + 2 * PT + SC,
                bytes_internal: t * (k * PT + 32 + 2 * PT + SC),
                rounds: 4,
            }
        }
        _ => panic!("unknown method {method}"),
    }
}

fn rng_from(seed: &[u8; 32], j: usize) -> rand_chacha::ChaCha20Rng {
    use rand::SeedableRng;
    rand_chacha::ChaCha20Rng::from_seed(sha256(&[seed, &(j as u64).to_be_bytes()]))
}

/// Public verification; returns the reconstructed plaintexts on success.
pub fn verify(s: &Setup, cts: &[Ct], p: &Published) -> Option<(Vec<G>, Value)> {
    let (t, k) = (s.t(), cts.len());
    let u: Vec<G> = cts.iter().map(|c| c.a).collect();
    let mut terms = 0usize;
    let ok = match &p.proofs {
        Proofs::Cp(pr) => (0..t).all(|i| {
            terms += 2 * k;
            (0..k).into_par_iter().all(|j| {
                pr[i][j].verify(
                    &s.key.tg,
                    &s.tw[i],
                    &s.ctx,
                    Setup::label(i, j),
                    &s.wb[i],
                    &u[j],
                    &p.shares[i][j],
                )
            })
        }),
        Proofs::CpMsm(pr) => {
            let mut rng = rand::thread_rng();
            let seeds: Vec<[u8; 32]> = (0..t * k).map(|_| rng.r#gen()).collect();
            let mut total = G::zero();
            let mut all = Acc::default();
            for i in 0..t {
                let acc = (0..k)
                    .into_par_iter()
                    .map(|j| {
                        let r = pr[i][j].rels(
                            &s.ctx,
                            Setup::label(i, j),
                            &s.wb[i],
                            &u[j],
                            &p.shares[i][j],
                        );
                        let mut a = Acc::default();
                        a.add(&r, &mut rng_from(&seeds[i * k + j], 0));
                        a
                    })
                    .reduce(Acc::default, |mut a, b| {
                        a.merge(b);
                        a
                    });
                total += acc.fixed_part(&bases(s, i));
                all.merge(Acc {
                    fixed: [F::zero(); 4],
                    ..acc
                });
            }
            terms += all.pts.len();
            (total + msm_cpu(&all.pts, &all.sc)).is_zero()
        }
        Proofs::Rfc(pr, short) => (0..t).all(|i| {
            let d = rfc_composites(s, i, &u, &p.shares[i], *short);
            let m = msm_cpu(&u, &d);
            let z = msm_cpu(&p.shares[i], &d);
            terms += 2 * k;
            let (c, sr) = pr[i];
            let t2 = s.key.tg.mul(&sr) + s.tw[i].mul(&c);
            let t3 = vmul(&m, &sr) + vmul(&z, &c);
            rfc_challenge(s, i, &m, &z, &t2, &t3) == c
        }),
        Proofs::Lin(pr, mode) if *mode > 0 => {
            // attribution variants: per-trustee MSMs, or one unmerged MSM
            let mut rng = rand::thread_rng();
            let mut total = G::zero();
            let mut all = Acc::default();
            let mut ok = true;
            for i in 0..t {
                let st = lin_stmt(i, &u, &p.shares[i]);
                let Some(r) = pr[i].rels(&s.ctx, 0, i, &s.wb[i], &st) else {
                    ok = false;
                    break;
                };
                let mut a = Acc::default();
                a.add(&r, &mut rng);
                terms += a.pts.len();
                if *mode == 1 {
                    ok &= (a.fixed_part(&bases(s, i)) + msm_cpu(&a.pts, &a.sc)).is_zero();
                } else {
                    total += a.fixed_part(&bases(s, i));
                    all.merge(Acc {
                        fixed: [F::zero(); 4],
                        ..a
                    });
                }
            }
            if *mode == 2 {
                ok &= (total + msm_cpu(&all.pts, &all.sc)).is_zero();
            }
            ok
        }
        Proofs::Lin(pr, _) => {
            // one MSM over all trustees; u_j merged across trustees
            let mut rng = rand::thread_rng();
            let mut uc = vec![F::zero(); k];
            let (mut pts, mut sc) = (Vec::new(), Vec::new());
            let mut fixed_g = F::zero();
            let mut ok = true;
            for i in 0..t {
                let st = lin_stmt(i, &u, &p.shares[i]);
                let Some(r) = pr[i].rels(&s.ctx, 0, i, &s.wb[i], &st) else {
                    ok = false;
                    break;
                };
                let rho: Vec<F> = (0..r.rows.len())
                    .map(|_| F::from(rng.r#gen::<u128>()))
                    .collect();
                for (row, rho) in r.rows.iter().zip(&rho) {
                    for (b, x) in &row.fixed {
                        match b {
                            crate::sigma::Base::G => fixed_g += *rho * x,
                            // W_i joins the MSM as a point
                            _ => {
                                pts.push(s.wb[i]);
                                sc.push(*rho * x);
                            }
                        }
                    }
                    for (idx, x) in &row.var {
                        // points 2j are u_j, 2j+1 are w_{i,j}, then T3, T4
                        if *idx < 2 * k && idx % 2 == 0 {
                            uc[idx / 2] += *rho * x;
                        } else {
                            pts.push(r.pts[*idx]);
                            sc.push(*rho * x);
                        }
                    }
                }
            }
            pts.extend_from_slice(&u);
            sc.extend(uc);
            terms += pts.len();
            ok && (s.key.tg.mul(&fixed_g) + msm_cpu(&pts, &sc)).is_zero()
        }
        Proofs::Joint(c, (a, b, z)) => {
            let (seed, be) = joint_seed(s, &u, c);
            let e = joint_challenge(s, &seed, a, b);
            let mut rng = rand::thread_rng();
            let (r1, r2) = (F::from(rng.r#gen::<u128>()), F::from(rng.r#gen::<u128>()));
            // r1([z]g − A − [e]h) + r2([z]U* − B − [e]C*) = O, U*, C* expanded
            let mut pts: Vec<G> = u.clone();
            let mut sc: Vec<F> = be.iter().map(|x| r2 * z * x).collect();
            pts.extend_from_slice(c);
            sc.extend(be.iter().map(|x| -(r2 * e * x)));
            pts.extend([*a, *b, s.key.h]);
            sc.extend([-r1, -r2, -(r1 * e)]);
            terms += pts.len();
            (s.key.tg.mul(&(r1 * z)) + msm_cpu(&pts, &sc)).is_zero()
        }
    };
    if !ok {
        return None;
    }
    let m: Vec<G> = match &p.proofs {
        Proofs::Joint(c, _) => cts.par_iter().zip(c).map(|(x, c)| x.b - c).collect(),
        _ => (0..k)
            .into_par_iter()
            .map(|j| cts[j].b - (0..t).map(|i| p.shares[i][j]).sum::<G>())
            .collect(),
    };
    Some((m, json!({"msm_or_vmul_terms": terms})))
}

fn bases(s: &Setup, i: usize) -> Bases<'_> {
    Bases {
        g: &s.key.tg,
        h: &s.key.th,
        ht: &s.key.tg,
        w: Some(&s.tw[i]),
    }
}

/// Controlled sweep: identical setup and ciphertexts for every method.
pub fn sweep(ks: &[usize], n: usize, t: usize, reps: usize, methods: &[&str]) -> Value {
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(20261124009);
    let s = Setup::deal(n, t, &mut rng);
    let max = *ks.iter().max().unwrap();
    let (all_cts, all_m) = ciphertexts(&s, max, &mut rng);
    let mut rows = Vec::new();
    for &k in ks {
        let (cts, msgs) = (&all_cts[..k], &all_m[..k]);
        let mut samples = Vec::new();
        for rep in 0..reps {
            for off in 0..methods.len() {
                let method = methods[(off + rep) % methods.len()];
                let t0 = Instant::now();
                let p = prove(&s, cts, method, &mut rng);
                let tp = t0.elapsed().as_secs_f64();
                let t0 = Instant::now();
                let (m, info) = verify(&s, cts, &p).expect("honest proofs verify");
                let tv = t0.elapsed().as_secs_f64();
                assert_eq!(m, msgs, "{method}: reconstruction");
                samples.push(json!({"rep":rep,"method":method,"prove_seconds":tp,"verify_seconds":tv,
                    "bytes_public":p.bytes_public,"bytes_internal":p.bytes_internal,"rounds":p.rounds,
                    "info":info,"plaintexts_ok":true}));
            }
        }
        eprintln!("tdec-sweep k={k}: all methods PASS");
        rows.push(json!({"k":k,"samples":samples}));
    }
    json!({"scope":"Threshold ElGamal decryption (pre-weighted shares, fixed decryption set). prove = all trustees' shares and proofs (joint: all rounds incl. aggregator blame checks); verify = public verification incl. reconstruction. Same setup and ciphertexts for all methods; method order rotates per repetition.",
           "n":n,"t":t,"reps":reps,"seed":20261124009u64,"rows":rows})
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn t009_threshold_decryption_methods_complete_and_sound() {
        let mut rng = thread_rng();
        let s = Setup::deal(5, 3, &mut rng);
        let (cts, msgs) = ciphertexts(&s, 12, &mut rng);
        for method in METHODS.iter().chain(&ATTRIBUTION[1..]) {
            let method = *method;
            let p = prove(&s, &cts, method, &mut rng);
            let (m, _) = verify(&s, &cts, &p).expect(method);
            assert_eq!(m, msgs, "{method}");
            let delta = g() * rand_scalar(&mut rng);
            let tamper = |f: &dyn Fn(&mut Published)| {
                let mut q = prove(&s, &cts, method, &mut rand::thread_rng());
                f(&mut q);
                q
            };
            if method == "joint" {
                // a wrong combined decryption, and cancelling errors
                let q = tamper(&|q| {
                    if let Proofs::Joint(c, _) = &mut q.proofs {
                        c[3] += g();
                    }
                });
                assert!(verify(&s, &cts, &q).is_none(), "joint: wrong C_j");
                let q = tamper(&|q| {
                    if let Proofs::Joint(c, _) = &mut q.proofs {
                        c[0] += delta;
                        c[1] -= delta;
                    }
                });
                assert!(verify(&s, &cts, &q).is_none(), "joint: cancelling");
                continue;
            }
            let q = tamper(&|q| q.shares[1][5] += g());
            assert!(verify(&s, &cts, &q).is_none(), "{method}: wrong share");
            // cancelling errors inside one trustee's batch
            let q = tamper(&|q| {
                q.shares[2][0] += delta;
                q.shares[2][7] -= delta;
            });
            assert!(verify(&s, &cts, &q).is_none(), "{method}: cancelling");
            // errors that cancel across trustees keep every M_j correct,
            // but each trustee's own statement is false: rejected
            let q = tamper(&|q| {
                q.shares[0][4] += delta;
                q.shares[1][4] -= delta;
            });
            assert!(verify(&s, &cts, &q).is_none(), "{method}: cross-trustee");
            // swapped shares between two ciphertexts
            let q = tamper(&|q| q.shares[0].swap(2, 3));
            assert!(verify(&s, &cts, &q).is_none(), "{method}: swapped");
        }
    }
}
