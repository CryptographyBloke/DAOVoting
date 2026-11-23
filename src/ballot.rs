//! Certified weighted admission (paper Sect. 4): the ballot relation
//! `R_ballot`, proven with Groth16 over BN254.
//!
//! Statement (37 public inputs): the 8 ciphertexts `CT_k` (4 coordinates
//! each), the nullifier `ν`, the registry root `rt`, the poll id `p` and the
//! committee key `h`. Witness: credential secret `s`, weight `w`, vote `v`,
//! Merkle path, encryption randomness `r_k`. The circuit enforces
//! * `Poseidon_2(Poseidon_1(s), w)` is a leaf under `rt` (depth 10),
//! * `0 ≤ w < 2^8`, `v ∈ {0,1}`, `x_k = v · w_k`,
//! * `CT_k = ([r_k]g, [r_k]h + [x_k]g)` with the stated randomness,
//! * `ν = Poseidon_2(s, p)`.
//!
//! Poseidon is the arkworks instance over BN254 (t = 3, α = 5, R_F = 8,
//! R_P = 57, Grain-LFSR constants); `Poseidon_k` absorbs the arity `k` first
//! for domain separation. It is *not* bit-compatible with circomlib.

use crate::group::*;
use anyhow::{Result, ensure};
use ark_bn254::Bn254;
use ark_crypto_primitives::sponge::{
    CryptographicSponge,
    constraints::CryptographicSpongeVar,
    poseidon::{
        PoseidonConfig, PoseidonSponge, constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds,
    },
};
use ark_ec::CurveGroup;
use ark_ed_on_bn254::constraints::{EdwardsVar, FqVar};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::FieldVar, groups::CurveVar,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_snark::SNARK;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub const L_VOTE: usize = 8;
pub const DEPTH: usize = 10;
const R_BITS: usize = 251;

pub fn poseidon_config() -> &'static PoseidonConfig<Fb> {
    static C: OnceLock<PoseidonConfig<Fb>> = OnceLock::new();
    C.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fb>(Fb::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0);
        PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
    })
}

/// `Poseidon_k(x_1..x_k)`.
pub fn poseidon(x: &[Fb]) -> Fb {
    let mut sp = PoseidonSponge::new(poseidon_config());
    let mut v = vec![Fb::from(x.len() as u64)];
    v.extend_from_slice(x);
    sp.absorb(&v);
    sp.squeeze_field_elements::<Fb>(1)[0]
}

fn poseidon_var(cs: ConstraintSystemRef<Fb>, x: &[FqVar]) -> Result<FqVar, SynthesisError> {
    let mut sp = PoseidonSpongeVar::new(cs, poseidon_config());
    let mut v = vec![FqVar::constant(Fb::from(x.len() as u64))];
    v.extend_from_slice(x);
    sp.absorb(&v)?;
    Ok(sp.squeeze_field_elements(1)?.remove(0))
}

/// Fixed-depth Poseidon Merkle tree over the registry leaves
/// `Poseidon_2(Poseidon_1(s), w)`; unused leaves are 0.
pub struct Registry {
    levels: Vec<Vec<Fb>>,
}

impl Registry {
    /// `entries[i] = (credential commitment Poseidon_1(s_i), weight w_i)`.
    pub fn new(entries: &[(Fb, u64)]) -> Self {
        assert!(entries.len() <= 1 << DEPTH);
        let mut lv: Vec<Fb> = entries
            .iter()
            .map(|(c, w)| poseidon(&[*c, Fb::from(*w)]))
            .collect();
        lv.resize(1 << DEPTH, Fb::zero());
        let mut levels = vec![lv];
        for _ in 0..DEPTH {
            let prev = levels.last().unwrap();
            levels.push(prev.chunks(2).map(|p| poseidon(&[p[0], p[1]])).collect());
        }
        Registry { levels }
    }
    pub fn root(&self) -> Fb {
        self.levels[DEPTH][0]
    }
    /// Siblings bottom-up and direction bits (`true` = current node is a right child).
    pub fn path(&self, mut i: usize) -> (Vec<Fb>, Vec<bool>) {
        let mut sib = Vec::new();
        let mut dir = Vec::new();
        for l in 0..DEPTH {
            sib.push(self.levels[l][i ^ 1]);
            dir.push(i & 1 == 1);
            i >>= 1;
        }
        (sib, dir)
    }
}

/// An encrypted ballot as submitted to the admission contract.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ballot {
    pub cts: Vec<Ct>,
    #[serde(with = "arkser")]
    pub nullifier: Fb,
    #[serde(with = "arkser")]
    pub proof: Proof<Bn254>,
}

/// Public statement of `R_ballot`.
pub struct Statement<'a> {
    pub cts: &'a [Ct],
    pub nullifier: Fb,
    pub root: Fb,
    pub poll: u64,
    pub h: G,
}

impl Statement<'_> {
    /// The 37 public inputs in circuit order.
    pub fn public_inputs(&self) -> Vec<Fb> {
        let pts: Vec<G> = self
            .cts
            .iter()
            .flat_map(|c| [c.a, c.b])
            .chain(std::iter::once(self.h))
            .collect();
        let aff = G::normalize_batch(&pts);
        let mut v = Vec::with_capacity(37);
        for p in &aff[..2 * L_VOTE] {
            v.push(p.x);
            v.push(p.y);
        }
        v.extend([
            self.nullifier,
            self.root,
            Fb::from(self.poll),
            aff[2 * L_VOTE].x,
            aff[2 * L_VOTE].y,
        ]);
        v
    }
}

/// Full assignment of the ballot circuit (public part + witness).
#[derive(Clone)]
pub struct BallotCircuit {
    pub public: Vec<Fb>,
    pub s: Fb,
    pub w: u64,
    pub v: bool,
    pub sib: Vec<Fb>,
    pub dir: Vec<bool>,
    pub r: Vec<F>,
}

impl ConstraintSynthesizer<Fb> for BallotCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fb>) -> Result<(), SynthesisError> {
        assert_eq!(self.public.len(), 4 * L_VOTE + 5);
        let inp: Vec<FqVar> = self
            .public
            .iter()
            .map(|x| FqVar::new_input(cs.clone(), || Ok(*x)))
            .collect::<Result<_, _>>()?;
        let ct = |k: usize, j: usize| {
            EdwardsVar::new(inp[4 * k + 2 * j].clone(), inp[4 * k + 2 * j + 1].clone())
        };
        let base = 4 * L_VOTE;
        let (nul, root, poll) = (&inp[base], &inp[base + 1], &inp[base + 2]);
        let h = EdwardsVar::new(inp[base + 3].clone(), inp[base + 4].clone());

        let s = FqVar::new_witness(cs.clone(), || Ok(self.s))?;
        let v = Boolean::new_witness(cs.clone(), || Ok(self.v))?;
        let wb: Vec<Boolean<Fb>> = (0..L_VOTE)
            .map(|k| Boolean::new_witness(cs.clone(), || Ok((self.w >> k) & 1 == 1)))
            .collect::<Result<_, _>>()?;
        // w = Σ w_k 2^k with 8 boolean bits enforces 0 ≤ w < 2^8
        let mut w = FqVar::zero();
        for (k, b) in wb.iter().enumerate() {
            w += FqVar::from(b.clone()) * Fb::from(1u64 << k);
        }
        // registry membership
        let cred = poseidon_var(cs.clone(), &[s.clone()])?;
        let mut cur = poseidon_var(cs.clone(), &[cred, w])?;
        for (sb, d) in self.sib.iter().zip(&self.dir) {
            let sib = FqVar::new_witness(cs.clone(), || Ok(*sb))?;
            let d = Boolean::new_witness(cs.clone(), || Ok(*d))?;
            let left = d.select(&sib, &cur)?;
            let right = d.select(&cur, &sib)?;
            cur = poseidon_var(cs.clone(), &[left, right])?;
        }
        cur.enforce_equal(root)?;
        // nullifier
        poseidon_var(cs.clone(), &[s, poll.clone()])?.enforce_equal(nul)?;
        // encryptions of the bits of v·w
        let gbases: Vec<G> = {
            let mut b = g();
            (0..R_BITS)
                .map(|_| {
                    let x = b;
                    b.double_in_place();
                    x
                })
                .collect()
        };
        let gv = EdwardsVar::constant(g());
        for k in 0..L_VOTE {
            let x = &v & &wb[k];
            let bits = self.r[k].into_bigint().to_bits_le();
            let rb: Vec<Boolean<Fb>> = (0..R_BITS)
                .map(|i| Boolean::new_witness(cs.clone(), || Ok(bits[i])))
                .collect::<Result<_, _>>()?;
            let mut c1 = EdwardsVar::zero();
            c1.precomputed_base_scalar_mul_le(rb.iter().zip(gbases.iter()))?;
            let c2 = h.scalar_mul_le(rb.iter())? + x.select(&gv, &EdwardsVar::zero())?;
            c1.enforce_equal(&ct(k, 0))?;
            c2.enforce_equal(&ct(k, 1))?;
        }
        Ok(())
    }
}

pub struct Voter {
    pub index: usize,
    pub s: Fb,
    pub w: u64,
}

pub fn nullifier(s: &Fb, poll: u64) -> Fb {
    poseidon(&[*s, Fb::from(poll)])
}

/// Encrypts `x = v·w` bit by bit and proves `R_ballot`.
pub fn cast<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    key: &Key,
    reg: &Registry,
    poll: u64,
    voter: &Voter,
    v: bool,
    rng: &mut R,
) -> Ballot {
    let (circ, cts, nullifier) = ballot_circuit(key, reg, poll, voter, v, rng);
    let proof = Groth16::<Bn254>::prove(pk, circ, rng).expect("prove");
    Ballot {
        cts,
        nullifier,
        proof,
    }
}

/// Per-stage wall-clock times of one Groth16 proof (seconds) and MSM sizes.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ProveTimes {
    pub synthesis: f64,
    pub finalize: f64,
    pub witness_map_fft: f64,
    pub msm_h_g1: f64,
    pub msm_l_g1: f64,
    pub msm_a_g1: f64,
    pub msm_b_g1: f64,
    pub msm_b_g2: f64,
    pub assemble: f64,
    pub total: f64,
    /// sizes of the H, L, A, B(G1), B(G2) multi-scalar multiplications
    pub msm_sizes: [usize; 5],
    pub constraints: usize,
}

/// Groth16 proving split into its stages, for profiling. It reproduces
/// `ark-groth16 0.5`'s `create_proof_with_reduction` step by step (libsnark
/// QAP reduction, same MSMs and blinding), so it yields ordinary proofs that
/// the unchanged verifier accepts. The MSM calls are the natural hook for a
/// GPU MSM backend (e.g. ICICLE BN254 G1/G2).
pub fn prove_staged<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    circ: BallotCircuit,
    rng: &mut R,
) -> Result<(Proof<Bn254>, ProveTimes)> {
    use ark_ec::{VariableBaseMSM, pairing::Pairing};
    use ark_ff::UniformRand;
    use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
    use ark_poly::GeneralEvaluationDomain;
    use ark_relations::r1cs::OptimizationGoal;
    use std::time::Instant;
    type G1 = <Bn254 as Pairing>::G1;
    type G2 = <Bn254 as Pairing>::G2;
    let t0 = Instant::now();
    let mut tm = ProveTimes::default();
    let (r, s) = (Fb::rand(rng), Fb::rand(rng));
    let cs = ConstraintSystem::<Fb>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    let t = Instant::now();
    circ.generate_constraints(cs.clone())?;
    tm.synthesis = t.elapsed().as_secs_f64();
    let t = Instant::now();
    cs.finalize();
    tm.finalize = t.elapsed().as_secs_f64();
    tm.constraints = cs.num_constraints();
    let t = Instant::now();
    let h = LibsnarkReduction::witness_map::<Fb, GeneralEvaluationDomain<Fb>>(cs.clone())?;
    tm.witness_map_fft = t.elapsed().as_secs_f64();
    let prover = cs.borrow().unwrap();
    let input: Vec<_> = prover.instance_assignment[1..]
        .iter()
        .map(|x| x.into_bigint())
        .collect();
    let aux: Vec<_> = prover
        .witness_assignment
        .iter()
        .map(|x| x.into_bigint())
        .collect();
    let hb: Vec<_> = h.iter().map(|x| x.into_bigint()).collect();
    let assignment = [&input[..], &aux[..]].concat();
    let t = Instant::now();
    let h_acc = G1::msm_bigint(&pk.h_query, &hb);
    tm.msm_h_g1 = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let l_acc = G1::msm_bigint(&pk.l_query, &aux);
    tm.msm_l_g1 = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let g_a = pk.delta_g1 * r
        + pk.a_query[0]
        + G1::msm_bigint(&pk.a_query[1..], &assignment)
        + pk.vk.alpha_g1;
    tm.msm_a_g1 = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let g1_b = pk.delta_g1 * s
        + pk.b_g1_query[0]
        + G1::msm_bigint(&pk.b_g1_query[1..], &assignment)
        + pk.beta_g1;
    tm.msm_b_g1 = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let g2_b = pk.vk.delta_g2 * s
        + pk.b_g2_query[0]
        + G2::msm_bigint(&pk.b_g2_query[1..], &assignment)
        + pk.vk.beta_g2;
    tm.msm_b_g2 = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let g_c = g_a * s + g1_b * r - pk.delta_g1 * (r * s) + l_acc + h_acc;
    let proof = Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    };
    tm.assemble = t.elapsed().as_secs_f64();
    tm.msm_sizes = [
        hb.len(),
        aux.len(),
        assignment.len(),
        assignment.len(),
        assignment.len(),
    ];
    tm.total = t0.elapsed().as_secs_f64();
    Ok((proof, tm))
}

/// Ballot witness and statement for [`prove_staged`] (same as [`cast`]).
pub fn ballot_circuit<R: RngCore + CryptoRng>(
    key: &Key,
    reg: &Registry,
    poll: u64,
    voter: &Voter,
    v: bool,
    rng: &mut R,
) -> (BallotCircuit, Vec<Ct>, Fb) {
    let x = if v { voter.w } else { 0 };
    let r: Vec<F> = (0..L_VOTE).map(|_| rand_scalar(rng)).collect();
    let cts: Vec<Ct> = (0..L_VOTE)
        .map(|k| key.enc(&F::from((x >> k) & 1), &r[k]))
        .collect();
    let nul = nullifier(&voter.s, poll);
    let public = Statement {
        cts: &cts,
        nullifier: nul,
        root: reg.root(),
        poll,
        h: key.h,
    }
    .public_inputs();
    let (sib, dir) = reg.path(voter.index);
    (
        BallotCircuit {
            public,
            s: voter.s,
            w: voter.w,
            v,
            sib,
            dir,
            r,
        },
        cts,
        nul,
    )
}

pub fn verify(
    pvk: &PreparedVerifyingKey<Bn254>,
    b: &Ballot,
    root: Fb,
    poll: u64,
    h: G,
) -> Result<()> {
    ensure!(b.cts.len() == L_VOTE, "wrong ciphertext count");
    let inputs = Statement {
        cts: &b.cts,
        nullifier: b.nullifier,
        root,
        poll,
        h,
    }
    .public_inputs();
    ensure!(
        Groth16::<Bn254>::verify_with_processed_vk(pvk, &inputs, &b.proof)?,
        "Groth16 proof rejected"
    );
    Ok(())
}

/// A satisfying dummy assignment used for the circuit-specific setup and for
/// constraint counting.
pub fn dummy_circuit(h: G) -> BallotCircuit {
    let s = Fb::from(7u64);
    let reg = Registry::new(&[(poseidon(&[s]), 1)]);
    let r: Vec<F> = (1..=L_VOTE as u64).map(F::from).collect();
    let key = Key::new(h);
    let cts: Vec<Ct> = (0..L_VOTE)
        .map(|k| key.enc(&F::from((k == 0) as u64), &r[k]))
        .collect();
    let public = Statement {
        cts: &cts,
        nullifier: nullifier(&s, 1),
        root: reg.root(),
        poll: 1,
        h,
    }
    .public_inputs();
    let (sib, dir) = reg.path(0);
    BallotCircuit {
        public,
        s,
        w: 1,
        v: true,
        sib,
        dir,
        r,
    }
}

/// Test-only reference-string generation (a deployment uses an MPC ceremony).
pub fn crs<R: RngCore + CryptoRng>(h: G, rng: &mut R) -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    Groth16::<Bn254>::circuit_specific_setup(dummy_circuit(h), rng).expect("setup")
}

/// `(constraints, public inputs, witnesses)` of the ballot relation.
pub fn constraint_count(h: G) -> (usize, usize, usize) {
    let cs = ConstraintSystem::<Fb>::new_ref();
    dummy_circuit(h).generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    (
        cs.num_constraints(),
        cs.num_instance_variables() - 1,
        cs.num_witness_variables(),
    )
}

pub fn identity_free(b: &Ballot) -> bool {
    b.cts.iter().all(|c| !c.a.into_affine().is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn relation_satisfied_and_rejects_bad_witness() {
        let mut rng = thread_rng();
        let key = Key::new(g() * rand_scalar(&mut rng));
        let (s1, s2) = (Fb::from(11u64), Fb::from(22u64));
        let reg = Registry::new(&[(poseidon(&[s1]), 200), (poseidon(&[s2]), 3)]);
        let mk = |idx: usize, s: Fb, w: u64, claimed_w: u64, v: bool, xbits: u64| {
            let r: Vec<F> = (0..L_VOTE)
                .map(|_| rand_scalar(&mut thread_rng()))
                .collect();
            let cts: Vec<Ct> = (0..L_VOTE)
                .map(|k| key.enc(&F::from((xbits >> k) & 1), &r[k]))
                .collect();
            let public = Statement {
                cts: &cts,
                nullifier: nullifier(&s, 5),
                root: reg.root(),
                poll: 5,
                h: key.h,
            }
            .public_inputs();
            let (sib, dir) = reg.path(idx);
            let _ = w;
            let c = BallotCircuit {
                public,
                s,
                w: claimed_w,
                v,
                sib,
                dir,
                r,
            };
            let cs = ConstraintSystem::<Fb>::new_ref();
            c.generate_constraints(cs.clone()).unwrap();
            cs.is_satisfied().unwrap()
        };
        assert!(mk(0, s1, 200, 200, true, 200));
        assert!(mk(0, s1, 200, 200, false, 0));
        assert!(mk(1, s2, 3, 3, true, 3));
        // encrypting a different value than v·w
        assert!(!mk(0, s1, 200, 200, true, 201));
        assert!(!mk(0, s1, 200, 200, false, 200));
        // claiming a weight that is not registered
        assert!(!mk(1, s2, 3, 255, true, 255));
        // wrong credential for the leaf
        assert!(!mk(0, s2, 200, 200, true, 200));
        let _ = &mut rng;
    }

    #[test]
    fn groth16_roundtrip_and_constraints() {
        let mut rng = thread_rng();
        let key = Key::new(g() * rand_scalar(&mut rng));
        let (nc, ni, _) = constraint_count(key.h);
        assert_eq!(ni, 37);
        eprintln!("ballot relation: {nc} constraints");
        let s = Fb::from(99u64);
        let reg = Registry::new(&[(Fb::from(1u64), 1), (poseidon(&[s]), 77)]);
        let (pk, vk) = crs(key.h, &mut rng);
        let pvk = ark_groth16::prepare_verifying_key(&vk);
        let voter = Voter { index: 1, s, w: 77 };
        let b = cast(&pk, &key, &reg, 4, &voter, true, &mut rng);
        verify(&pvk, &b, reg.root(), 4, key.h).unwrap();
        assert!(verify(&pvk, &b, reg.root(), 5, key.h).is_err());
        let mut b2 = b.clone();
        b2.cts.swap(0, 1);
        assert!(verify(&pvk, &b2, reg.root(), 4, key.h).is_err());
    }

    #[test]
    fn staged_prover_proofs_verify() {
        let mut rng = thread_rng();
        let key = Key::new(g() * rand_scalar(&mut rng));
        let s = Fb::from(5u64);
        let reg = Registry::new(&[(poseidon(&[s]), 200)]);
        let (pk, vk) = crs(key.h, &mut rng);
        let pvk = ark_groth16::prepare_verifying_key(&vk);
        let voter = Voter {
            index: 0,
            s,
            w: 200,
        };
        for v in [true, false] {
            let (circ, cts, nullifier) = ballot_circuit(&key, &reg, 9, &voter, v, &mut rng);
            let (proof, tm) = prove_staged(&pk, circ, &mut rng).unwrap();
            assert!(tm.total > 0.0 && tm.msm_sizes[0] > tm.constraints);
            verify(
                &pvk,
                &Ballot {
                    cts,
                    nullifier,
                    proof,
                },
                reg.root(),
                9,
                key.h,
            )
            .unwrap();
        }
    }
}
