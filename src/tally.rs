//! Encrypted winner-only tally: the CGY conditional gate (Alg. 7/CSZ with the
//! masking chain, Alg. 8 rerandomization and threshold decryption) evaluated
//! over the threshold circuit, followed by the rerandomize-then-decrypt
//! release of `C_b`.
//!
//! The same [`Engine`] is run by every trustee (which verifies every message
//! of the others, CGY line 8), by the coordinator/publisher, and by the
//! independent public verifier, so every gate output is recomputed from
//! public values only.
//!
//! Per gate (slot) and trustee `i` the protocol messages are
//! * `Mask`   — `X_i = s·X_{i-1} + Enc(0;r1)`, `Y_i = s·Y_{i-1} + Enc(0;r2)`,
//!   `e = [r1]h~`, PoK-CSZ, and a hash commitment to the trustee's
//!   rerandomizers (Alg. 8 commit step, sent with the mask),
//! * `Reveal` — rerandomizers `A_i = Enc(0)`, `B_i = Enc(0)` + ZKP0 (Alg. 8),
//! * `Dec`    — partial decryption of `Y' = Y_a + ΣB_i` + DLEQ proof.
//!
//! The output is `Z = (X + y'·X')/2` with `X' = X_a + ΣA_i` and the opened
//! `y' = σ(2y−1) ∈ {±1}`. The release slot uses `Commit`, `Reveal`, `Dec` on
//! `C_b` and only accepts a decryption equal to the identity or `g`.

use crate::batch::{Job, MulBackend, eval_all};
use crate::circuit::{Circuit, Node, ReferenceSchedule, Scheduler};
use crate::group::*;
use crate::shamir;
use crate::sigma::{Acc, Bases, Csz, Csz2, CszStmt, Dleq, Dleq2, Rels, Zkp0, Zkp02};
use anyhow::{Result, bail, ensure};
use ark_ff::{Field, Zero};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Item {
    Mask {
        slot: u32,
        x: Ct,
        y: Ct,
        #[serde(with = "arkser_fast")]
        e: G,
        proof: Csz,
        commit: [u8; 32],
    },
    Commit {
        slot: u32,
        commit: [u8; 32],
    },
    Reveal {
        slot: u32,
        r: Vec<Ct>,
        proof: Zkp0,
        salt: [u8; 32],
    },
    Dec {
        slot: u32,
        #[serde(with = "arkser_fast")]
        w: G,
        proof: Dleq,
    },
    // ---- transcript format v2 (T007): lifted points, commitment-form proofs
    Mask2 {
        slot: u32,
        x: Ct,
        y: Ct,
        #[serde(with = "arkser_fast")]
        e: G,
        proof: Csz2,
        commit: [u8; 32],
    },
    Reveal2 {
        slot: u32,
        r: Vec<Ct>,
        proof: Zkp02,
        salt: [u8; 32],
    },
    /// pre-weighted partial decryption `w = [λ_i s_i]u`
    Dec2 {
        slot: u32,
        #[serde(with = "arkser_fast")]
        w: G,
        proof: Dleq2,
    },
}

impl Item {
    /// Refresh every transmitted lift independently. Canonical values, proof
    /// challenges and canonical commit/reveal bindings are unchanged.
    fn randomize_lifts<R: RngCore + CryptoRng>(&mut self, rng: &mut R) {
        let mut ct = |c: &mut Ct| {
            randomize_lift(&mut c.a, rng);
            randomize_lift(&mut c.b, rng);
        };
        match self {
            Item::Mask2 { x, y, e, proof, .. } => {
                ct(x);
                ct(y);
                for c in &mut proof.c {
                    ct(c);
                }
                randomize_lift(e, rng);
                for p in &mut proof.ce {
                    randomize_lift(p, rng);
                }
            }
            Item::Reveal2 { r, proof, .. } => {
                for c in r {
                    ct(c);
                }
                for c in &mut proof.e {
                    ct(c);
                }
            }
            Item::Dec2 { w, proof, .. } => {
                randomize_lift(w, rng);
                randomize_lift(&mut proof.e1, rng);
                randomize_lift(&mut proof.e2, rng);
            }
            Item::Commit { .. } => {}
            _ => unreachable!("representation refresh only applies to lifted proofs"),
        }
    }
    /// Every group element carried by the item lies in the prime-order
    /// subgroup (decoding only guarantees an on-curve point).
    pub fn points_valid(&self) -> bool {
        let cts_ok = |c: &[Ct]| c.iter().all(|c| in_subgroup(&c.a) && in_subgroup(&c.b));
        match self {
            Item::Mask { x, y, e, .. } => cts_ok(&[*x, *y]) && in_subgroup(e),
            Item::Commit { .. } => true,
            Item::Reveal { r, .. } => cts_ok(r),
            Item::Dec { w, .. } => in_subgroup(w),
            // v2 points are canonicalised by [8] on decode (always in G)
            Item::Mask2 { .. } | Item::Reveal2 { .. } | Item::Dec2 { .. } => true,
        }
    }

    /// `Some(true)` for v2 items, `Some(false)` for v1 items, `None` for `Commit`.
    pub fn is_v2(&self) -> Option<bool> {
        match self {
            Item::Commit { .. } => None,
            Item::Mask2 { .. } | Item::Reveal2 { .. } | Item::Dec2 { .. } => Some(true),
            _ => Some(false),
        }
    }

    /// v2 decoding: replaces every lifted point `Q` by `[8]Q ∈ G`; returns the
    /// lifts of a mask's `(X_i, Y_i)` (needed by the next masker).
    pub fn canonicalize(&mut self) -> Option<(Ct, Ct)> {
        match self {
            Item::Mask2 { x, y, e, proof, .. } => {
                let l = (*x, *y);
                *x = x.clear8();
                *y = y.clear8();
                *e = clear8(e);
                proof.c = proof.c.map(|c| c.clear8());
                proof.ce = proof.ce.map(|p| clear8(&p));
                Some(l)
            }
            Item::Reveal2 { r, proof, .. } => {
                r.iter_mut().for_each(|c| *c = c.clear8());
                proof.e.iter_mut().for_each(|c| *c = c.clear8());
                None
            }
            Item::Dec2 { w, proof, .. } => {
                *w = clear8(w);
                proof.e1 = clear8(&proof.e1);
                proof.e2 = clear8(&proof.e2);
                None
            }
            _ => None,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Item::Mask { .. } | Item::Mask2 { .. } => "PoK-CSZ",
            Item::Reveal { .. } | Item::Reveal2 { .. } => "ZKP0",
            Item::Dec { .. } | Item::Dec2 { .. } => "DLEQ",
            Item::Commit { .. } => "commit",
        }
    }

    /// The group elements carried by the item (all must lie in `G`).
    pub fn points(&self) -> Vec<G> {
        match self {
            Item::Mask { x, y, e, .. } => vec![x.a, x.b, y.a, y.b, *e],
            Item::Commit { .. } => vec![],
            Item::Reveal { r, .. } => r.iter().flat_map(|c| [c.a, c.b]).collect(),
            Item::Dec { w, .. } => vec![*w],
            Item::Mask2 { .. } | Item::Reveal2 { .. } | Item::Dec2 { .. } => vec![],
        }
    }

    pub fn slot(&self) -> u32 {
        match self {
            Item::Mask { slot, .. }
            | Item::Commit { slot, .. }
            | Item::Reveal { slot, .. }
            | Item::Dec { slot, .. }
            | Item::Mask2 { slot, .. }
            | Item::Reveal2 { slot, .. }
            | Item::Dec2 { slot, .. } => *slot,
        }
    }
}

/// An authenticated board message: a batch of items signed by one trustee.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Msg {
    pub from: u8,
    pub ctr: u64,
    /// bincode of `Vec<Vec<u8>>`, one bincode-encoded `Item` per entry
    /// (items decode in parallel)
    pub body: Vec<u8>,
    pub sig: Vec<u8>,
}

fn msg_digest(ctx: &[u8; 32], from: u8, ctr: u64, body: &[u8]) -> [u8; 32] {
    sha256(&[b"wod/msg/v1", ctx, &[from], &ctr.to_be_bytes(), body])
}

fn msg_digest_format(ctx: &[u8; 32], from: u8, ctr: u64, body: &[u8], version: u8) -> [u8; 32] {
    match version {
        3 => sha256(&[b"wod/msg/v3", ctx, &[from], &ctr.to_be_bytes(), body]),
        4 => sha256(&[b"wod/msg/v4", ctx, &[from], &ctr.to_be_bytes(), body]),
        _ => msg_digest(ctx, from, ctr, body),
    }
}

impl Msg {
    pub fn sign(sk: &SigningKey, ctx: &[u8; 32], from: u8, ctr: u64, items: &[Item]) -> Msg {
        Self::sign_format(sk, ctx, from, ctr, items, 1)
    }
    pub fn sign_format(
        sk: &SigningKey,
        ctx: &[u8; 32],
        from: u8,
        ctr: u64,
        items: &[Item],
        version: u8,
    ) -> Msg {
        let enc: Vec<Vec<u8>> = items
            .par_iter()
            .map(|i| message_wire(version == 4, || bincode::serialize(i).unwrap()))
            .collect();
        let body = bincode::serialize(&enc).unwrap();
        let sig = sk
            .sign(&msg_digest_format(ctx, from, ctr, &body, version))
            .to_bytes()
            .to_vec();
        Msg {
            from,
            ctr,
            body,
            sig,
        }
    }
    pub fn verify_sig(&self, vk: &VerifyingKey, ctx: &[u8; 32]) -> Result<()> {
        self.verify_sig_format(vk, ctx, 1)
    }
    pub fn verify_sig_format(&self, vk: &VerifyingKey, ctx: &[u8; 32], version: u8) -> Result<()> {
        let sig = Signature::from_slice(&self.sig)?;
        vk.verify(
            &msg_digest_format(ctx, self.from, self.ctr, &self.body, version),
            &sig,
        )?;
        Ok(())
    }
}

/// Public tally parameters (no secrets).
pub struct Public {
    pub a: usize,
    pub key: Key,
    pub tht: FixedBase,
    pub hi: Vec<G>,
    pub thi: Vec<FixedBase>,
    pub vks: Vec<VerifyingKey>,
    /// session context: H(setup ‖ sealed-board commitment)
    pub ctx: [u8; 32],
    /// Lagrange coefficients for the full set {1..a} (q_dec = a)
    pub lam: Vec<F>,
    v2: std::sync::OnceLock<V2Pub>,
}

/// Public tables for transcript format v2: lift bases `g/8, h/8, h~/8` and the
/// weighted share commitments `W_i = [λ_i]h_i` (fixed set of all `a` trustees).
pub struct V2Pub {
    pub lk: LiftKey,
    pub tht8: FixedBase,
    pub wb: Vec<G>,
    pub tw: Vec<FixedBase>,
}

/// Transcript format selected for new runs: v2 iff `WOD_FORMAT=v2` (set by
/// the CLI flag `--format v2` and inherited by subprocesses).
pub fn default_v2() -> bool {
    default_format() >= 2
}

pub fn default_format() -> u8 {
    match std::env::var("WOD_FORMAT").as_deref() {
        Ok("v2") => 2,
        Ok("v3") => 3,
        Ok("v4") => 4,
        _ => 1,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LiftPolicy {
    Legacy,
    Canonical,
    Randomized,
}

fn default_lift_policy() -> LiftPolicy {
    if default_format() < 3 {
        LiftPolicy::Legacy
    } else if std::env::var("WOD_LIFT_POLICY").as_deref() == Ok("canonical") {
        LiftPolicy::Canonical
    } else {
        LiftPolicy::Randomized
    }
}

impl Public {
    pub fn new(pk: G, hi: Vec<G>, vks: Vec<VerifyingKey>, ctx: [u8; 32]) -> Self {
        let a = hi.len();
        let set: Vec<usize> = (1..=a).collect();
        Public {
            a,
            key: Key::new(pk),
            tht: FixedBase::new(h_tilde()),
            thi: hi.iter().map(|h| FixedBase::new(*h)).collect(),
            hi,
            vks,
            ctx,
            lam: shamir::lagrange(&set),
            v2: std::sync::OnceLock::new(),
        }
    }
    /// Same parameters under another session context (tests, cross-poll checks).
    pub fn clone_with_ctx(&self, ctx: [u8; 32]) -> Public {
        Public::new(self.key.h, self.hi.clone(), self.vks.clone(), ctx)
    }
    pub fn v2(&self) -> &V2Pub {
        if let Some(public) = self.v2.get() {
            return public;
        }
        // Never hold OnceLock's initialization guard across Rayon work:
        // normalize_batch can steal a second caller waiting on this lock.
        // Producers/processors prewarm outside item parallelism. Concurrent
        // cold callers may duplicate public precomputation, then publish once.
        let wb: Vec<G> = self.hi.iter().zip(&self.lam).map(|(h, l)| *h * l).collect();
        let public = V2Pub {
            lk: LiftKey::new(self.key.h),
            tht8: FixedBase::new(lift_of(&h_tilde())),
            tw: wb.iter().map(|w| FixedBase::new(*w)).collect(),
            wb,
        };
        self.v2.get_or_init(|| public)
    }
    fn label(slot: u32, who: usize) -> u64 {
        ((slot as u64) << 8) | who as u64
    }
}

#[derive(Default, Clone)]
struct Slot {
    /// gate: the `X` input; release: `C_b`
    x: Option<Ct>,
    /// gate: `Y_0 = E_{-1}·Y^2`; release: unused
    y0: Option<Ct>,
    chain: Vec<(Ct, Ct)>,
    /// v2: the lifts of `chain`, as received (used by the next masker)
    chain_lift: Vec<(Ct, Ct)>,
    commits: Vec<Option<[u8; 32]>>,
    rr: Vec<Option<Vec<Ct>>>,
    n_rr: usize,
    /// gate: `X'`; release: unused
    xp: Option<Ct>,
    /// ciphertext to open: gate `Y'`, release `C_b'`
    dct: Option<Ct>,
    dec: Vec<Option<G>>,
    n_dec: usize,
    done: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum Act {
    Mask(u32),
    Commit(u32),
    Reveal(u32),
    Dec(u32),
}

pub struct Engine {
    pub pp: Arc<Public>,
    pub circ: Arc<Circuit>,
    wires: Vec<Option<Ct>>,
    pending: Vec<u32>,
    slots: Vec<Slot>,
    active: BTreeSet<u32>,
    next_ctr: Vec<u64>,
    pub gates_done: usize,
    pub result: Option<bool>,
    pub n_msgs: usize,
    pub n_items: usize,
    reference: Option<ReferenceSchedule>,
    stage_remaining: Vec<usize>,
    pub completed_stages: usize,
    pub gate_batches: usize,
    pub max_gate_batch: usize,
    /// `None`: original per-item verification; `Some(b)`: message-level
    /// batching of all public variable-base multiplications through `b`.
    batch: Option<Arc<dyn MulBackend>>,
    pending_finish: Vec<u32>,
    pub prof: Prof,
    /// transcript format v2 (lifted points, commitment-form proofs)
    pub v2: bool,
    /// v3/v4 repair: subgroup reference or independently uniform torsion.
    pub lift_policy: LiftPolicy,
    /// v4: validated uncompressed affine message points (experimental).
    pub wide_points: bool,
    /// v2 only: verify every relation separately instead of one MSM per message
    pub v2_individual: bool,
    /// v2 only: derive batch coefficients from the message (reproducible)
    /// instead of fresh verifier randomness
    pub v2_coeff_fs: bool,
}

/// Wall-clock breakdown of [`Engine::process`] (seconds, summed over messages).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Prof {
    pub decode: f64,
    /// Subset of decode: cofactor-image canonicalization (not additive to decode).
    pub cofactor_decode: f64,
    pub signature: f64,
    /// inline path: subgroup checks + proof verification
    pub verify_inline: f64,
    /// batched path: state checks and job collection
    pub batch_build: f64,
    /// batched path: time inside the backend
    pub batch_run: f64,
    /// batched path: fixed-base parts, hashing and comparisons
    pub batch_check: f64,
    /// applying items, including inline gate finishing
    pub apply: f64,
    /// batched gate finishing (share combination and halving)
    pub finish: f64,
    pub jobs: u64,
    pub batches: u64,
    pub max_batch: u64,
}

fn inv2() -> F {
    static I: std::sync::OnceLock<F> = std::sync::OnceLock::new();
    *I.get_or_init(|| F::from(2u64).inverse().unwrap())
}

fn commit_hash(
    ctx: &[u8; 32],
    slot: u32,
    who: usize,
    r: &[Ct],
    proof: &Zkp0,
    salt: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new("wod/rr-commit", ctx)
        .u64(Public::label(slot, who))
        .bytes(salt)
        .cts(r);
    h = h.bytes(&bincode::serialize(proof).unwrap());
    h.digest()
}

fn commit_hash2(
    ctx: &[u8; 32],
    slot: u32,
    who: usize,
    r: &[Ct],
    proof: &Zkp02,
    salt: &[u8; 32],
) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let mut h = Hasher::new("wod/v2/rr-commit", ctx)
        .u64(Public::label(slot, who))
        .bytes(salt)
        .cts(r)
        .cts(&proof.e);
    for z in &proof.z {
        h = h.bytes(&z.into_bigint().to_bytes_le());
    }
    h.digest()
}

impl Engine {
    pub fn new(pp: Arc<Public>, circ: Arc<Circuit>, inputs: &[Ct]) -> Result<Self> {
        let n_in = circ.n * circ.l_vote;
        ensure!(
            inputs.len() == n_in,
            "expected {} input ciphertexts, got {}",
            n_in,
            inputs.len()
        );
        let a = pp.a;
        let slot = Slot {
            commits: vec![None; a],
            rr: vec![None; a],
            dec: vec![None; a],
            ..Default::default()
        };
        let mut e = Engine {
            wires: vec![None; circ.nodes.len()],
            pending: circ.indeg.clone(),
            slots: vec![slot; circ.n_gates() + 1],
            active: BTreeSet::new(),
            next_ctr: vec![0; a],
            gates_done: 0,
            result: None,
            n_msgs: 0,
            n_items: 0,
            reference: None,
            stage_remaining: Vec::new(),
            completed_stages: 0,
            gate_batches: 0,
            max_gate_batch: 0,
            batch: crate::batch::default_backend(),
            pending_finish: Vec::new(),
            prof: Prof::default(),
            v2: default_v2(),
            lift_policy: default_lift_policy(),
            wide_points: default_format() == 4,
            v2_individual: std::env::var("WOD_V2_VERIFY")
                .map(|v| v == "individual")
                .unwrap_or(false),
            v2_coeff_fs: std::env::var("WOD_V2_COEFF")
                .map(|v| v == "fs")
                .unwrap_or(false),
            pp,
            circ,
        };
        let circ = e.circ.clone();
        for (i, nd) in circ.nodes.iter().enumerate() {
            match nd {
                Node::Input(j) => e.set_wire(i as u32, inputs[*j as usize]),
                Node::Affine { terms, c } if terms.is_empty() => {
                    e.set_wire(i as u32, Ct::trivial(*c))
                }
                _ => {}
            }
        }
        Ok(e)
    }

    /// Select a producer policy before processing any message. Public replay
    /// keeps the original DAG acceptance predicate and needs no scheduler flag.
    pub fn select_scheduler(&mut self, scheduler: Scheduler) -> Result<()> {
        ensure!(
            self.n_msgs == 0 && self.gates_done == 0,
            "cannot switch an active scheduler"
        );
        self.reference = match scheduler {
            Scheduler::Dataflow => None,
            Scheduler::Reference => Some(self.circ.reference_schedule()),
        };
        self.stage_remaining = self
            .reference
            .as_ref()
            .map(|p| p.stage_gates.clone())
            .unwrap_or_default();
        Ok(())
    }

    /// Verify through message-level batches on `backend` (public data only).
    pub fn set_batch_backend(&mut self, backend: Option<Arc<dyn MulBackend>>) {
        self.batch = backend;
    }

    pub fn format(&self) -> u8 {
        if !self.v2 {
            1
        } else if self.lift_policy == LiftPolicy::Legacy {
            2
        } else if self.wide_points {
            4
        } else {
            3
        }
    }

    /// Public verification derives format exclusively from the signed
    /// transcript header. Producer-only canonical/randomized policies share
    /// the same v3 predicate and have identical canonical semantics.
    pub fn select_format(&mut self, version: u8) {
        self.v2 = version >= 2;
        self.lift_policy = if version >= 3 {
            LiftPolicy::Randomized
        } else {
            LiftPolicy::Legacy
        };
        self.wide_points = version == 4;
    }

    pub fn release_slot(&self) -> u32 {
        self.circ.n_gates() as u32
    }

    fn wire(&self, i: u32) -> &Ct {
        self.wires[i as usize].as_ref().expect("wire not ready")
    }

    /// Dataflow propagation of affine wires; makes gates ready.
    fn set_wire(&mut self, node: u32, ct: Ct) {
        let circ = self.circ.clone();
        let mut work = vec![(node, ct)];
        while let Some((n, c)) = work.pop() {
            debug_assert!(self.wires[n as usize].is_none());
            self.wires[n as usize] = Some(c);
            if n == circ.output {
                let rs = self.release_slot();
                self.slots[rs as usize].x = Some(c);
                self.active.insert(rs);
            }
            for &d in &circ.dependents[n as usize] {
                self.pending[d as usize] -= 1;
                if self.pending[d as usize] > 0 {
                    continue;
                }
                match &circ.nodes[d as usize] {
                    Node::Affine { terms, c } => {
                        let mut acc = Ct::trivial(*c);
                        for (w, k) in terms {
                            acc = acc.add(&self.wire(*w).small(*k));
                        }
                        work.push((d, acc));
                    }
                    Node::Gate { x, y } => {
                        let gid = circ.gate_of[d as usize];
                        let s = &mut self.slots[gid as usize];
                        s.x = Some(*self.wires[*x as usize].as_ref().unwrap());
                        // Y_0 = E_{-1} · Y^2 encrypts 2y − 1
                        s.y0 = Some(
                            self.wires[*y as usize]
                                .unwrap()
                                .small(2)
                                .add(&Ct::trivial(-1)),
                        );
                        self.active.insert(gid);
                    }
                    Node::Input(_) => unreachable!(),
                }
            }
        }
    }

    fn is_release(&self, slot: u32) -> bool {
        slot == self.release_slot()
    }

    /// Actions currently enabled for trustee `me` (0-based).
    pub fn actions(&self, me: usize) -> Vec<Act> {
        let a = self.pp.a;
        let mut out = Vec::new();
        for &sid in &self.active {
            if !self.is_release(sid) {
                if let Some(plan) = &self.reference {
                    let gate = sid as usize;
                    if plan.stage[gate] != self.completed_stages
                        || plan.previous[gate].is_some_and(|p| !self.slots[p].done)
                    {
                        continue;
                    }
                }
            }
            let s = &self.slots[sid as usize];
            if s.done {
                continue;
            }
            if self.is_release(sid) {
                if s.commits[me].is_none() {
                    out.push(Act::Commit(sid));
                }
            } else if s.chain.len() == me {
                out.push(Act::Mask(sid));
            }
            let committed = s.commits.iter().all(|c| c.is_some());
            let masked = self.is_release(sid) || s.chain.len() == a;
            if committed && masked && s.rr[me].is_none() {
                out.push(Act::Reveal(sid));
            }
            if s.dct.is_some() && s.dec[me].is_none() {
                out.push(Act::Dec(sid));
            }
        }
        out
    }

    /// Verifies one item from trustee `from` against the current state.
    pub fn check(&self, from: usize, it: &Item) -> Result<()> {
        self.validate(from, it)?;
        self.proof_ok(from, it, &eval_all(&self.proof_jobs(from, it)))
    }

    /// Statement inputs of a mask item: the previous `(X_{i-1}, Y_{i-1})`.
    fn mask_prev(&self, sid: u32, from: usize) -> (&Ct, &Ct) {
        let s = &self.slots[sid as usize];
        if from == 0 {
            (s.x.as_ref().unwrap(), s.y0.as_ref().unwrap())
        } else {
            let p = &s.chain[from - 1];
            (&p.0, &p.1)
        }
    }

    /// Ordering, state and commitment checks (no proof arithmetic).
    pub fn validate(&self, from: usize, it: &Item) -> Result<()> {
        let pp = &*self.pp;
        let sid = it.slot();
        ensure!((sid as usize) < self.slots.len(), "bad slot");
        let s = &self.slots[sid as usize];
        ensure!(!s.done, "slot already closed");
        ensure!(
            it.is_v2().unwrap_or(self.v2) == self.v2,
            "item of the wrong transcript format"
        );
        match it {
            Item::Mask { .. } | Item::Mask2 { .. } => {
                ensure!(!self.is_release(sid), "mask on release slot");
                ensure!(s.chain.len() == from, "mask out of order");
                ensure!(from > 0 || s.x.is_some(), "gate not ready");
            }
            Item::Commit { .. } => {
                ensure!(self.is_release(sid) && s.x.is_some(), "commit not allowed");
                ensure!(s.commits[from].is_none(), "duplicate commit");
            }
            Item::Reveal { r, proof, salt, .. } => {
                ensure!(s.rr[from].is_none(), "duplicate reveal");
                ensure!(
                    s.commits.iter().all(|c| c.is_some()),
                    "reveal before all commitments"
                );
                let want = if self.is_release(sid) { 1 } else { 2 };
                ensure!(
                    self.is_release(sid) || s.chain.len() == pp.a,
                    "reveal before masking complete"
                );
                ensure!(r.len() == want, "wrong rerandomizer count");
                ensure!(
                    commit_hash(&pp.ctx, sid, from, r, proof, salt) == s.commits[from].unwrap(),
                    "reveal does not match commitment"
                );
            }
            Item::Reveal2 { r, proof, salt, .. } => {
                ensure!(s.rr[from].is_none(), "duplicate reveal");
                ensure!(
                    s.commits.iter().all(|c| c.is_some()),
                    "reveal before all commitments"
                );
                let want = if self.is_release(sid) { 1 } else { 2 };
                ensure!(
                    self.is_release(sid) || s.chain.len() == pp.a,
                    "reveal before masking complete"
                );
                ensure!(r.len() == want, "wrong rerandomizer count");
                ensure!(
                    commit_hash2(&pp.ctx, sid, from, r, proof, salt) == s.commits[from].unwrap(),
                    "reveal does not match commitment"
                );
            }
            Item::Dec { .. } | Item::Dec2 { .. } => {
                ensure!(s.dct.is_some(), "nothing to decrypt");
                ensure!(s.dec[from].is_none(), "duplicate share");
            }
        }
        Ok(())
    }

    /// Public variable-base multiplications of the item's proof (validated item).
    pub fn proof_jobs(&self, from: usize, it: &Item) -> Vec<Job> {
        match it {
            Item::Mask { x, y, e, proof, .. } => {
                let (x0, y0) = self.mask_prev(it.slot(), from);
                proof.jobs(&CszStmt {
                    x0,
                    y0,
                    x1: x,
                    y1: y,
                    e,
                })
            }
            Item::Commit { .. } | Item::Mask2 { .. } | Item::Reveal2 { .. } | Item::Dec2 { .. } => {
                vec![]
            }
            Item::Reveal { r, proof, .. } => proof.jobs(r),
            Item::Dec { w, proof, .. } => {
                let d = self.slots[it.slot() as usize].dct.as_ref().unwrap();
                proof.jobs(&d.a, w).to_vec()
            }
        }
    }

    /// Completes the proof check from the results of [`Self::proof_jobs`].
    pub fn proof_ok(&self, from: usize, it: &Item, r: &[G]) -> Result<()> {
        let pp = &*self.pp;
        let sid = it.slot();
        let label = Public::label(sid, from);
        match it {
            Item::Mask { x, y, e, proof, .. } => {
                let (x0, y0) = self.mask_prev(sid, from);
                let st = CszStmt {
                    x0,
                    y0,
                    x1: x,
                    y1: y,
                    e,
                };
                ensure!(
                    proof.check(&pp.key, &pp.tht, &pp.ctx, label, &st, r),
                    "PoK-CSZ rejected"
                );
            }
            Item::Commit { .. } => {}
            Item::Mask2 { .. } | Item::Reveal2 { .. } | Item::Dec2 { .. } => {
                bail!("v2 items are verified by verify_v2")
            }
            Item::Reveal { r: rr, proof, .. } => {
                ensure!(proof.check(&pp.key, &pp.ctx, label, rr, r), "ZKP0 rejected");
            }
            Item::Dec { w, proof, .. } => {
                let d = self.slots[sid as usize].dct.as_ref().unwrap();
                ensure!(
                    proof.check(
                        &pp.key.tg,
                        &pp.thi[from],
                        &pp.ctx,
                        label,
                        &pp.hi[from],
                        &d.a,
                        w,
                        r
                    ),
                    "DLEQ rejected"
                );
            }
        }
        Ok(())
    }

    /// Records a verified item and advances the slot.
    pub fn apply(&mut self, from: usize, it: Item) -> Result<()> {
        let a = self.pp.a;
        let sid = it.slot();
        let rel = self.is_release(sid);
        let s = &mut self.slots[sid as usize];
        match it {
            Item::Mask { x, y, commit, .. } | Item::Mask2 { x, y, commit, .. } => {
                s.chain.push((x, y));
                s.commits[from] = Some(commit);
            }
            Item::Commit { commit, .. } => s.commits[from] = Some(commit),
            Item::Reveal { r, .. } | Item::Reveal2 { r, .. } => {
                s.rr[from] = Some(r);
                s.n_rr += 1;
                if s.n_rr == a {
                    let all = s.rr.iter().map(|v| v.as_ref().unwrap());
                    if rel {
                        let mut c = s.x.unwrap();
                        for v in all {
                            c = c.add(&v[0]);
                        }
                        s.dct = Some(c);
                    } else {
                        let (mut xp, mut yp) = s.chain[a - 1];
                        for v in all {
                            xp = xp.add(&v[0]);
                            yp = yp.add(&v[1]);
                        }
                        s.xp = Some(xp);
                        s.dct = Some(yp);
                    }
                }
            }
            Item::Dec { w, .. } | Item::Dec2 { w, .. } => {
                s.dec[from] = Some(w);
                s.n_dec += 1;
                if s.n_dec == a {
                    if self.batch.is_some() || self.v2 {
                        self.pending_finish.push(sid);
                    } else {
                        self.finish(&[sid], &crate::batch::Inline)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Opens the decryptions of completed slots and computes the gate outputs
    /// `Z = (X + y'X')/2`. Both multiplication rounds (`λ_i·w_i` and the
    /// halving) are evaluated as one batch per round on `b`.
    fn finish(&mut self, sids: &[u32], b: &dyn MulBackend) -> Result<()> {
        let pp = self.pp.clone();
        let (a, lam) = (pp.a, &pp.lam);
        let lw = if self.v2 {
            // v2 shares are pre-weighted: w_i = [λ_i s_i]u
            sids.iter()
                .flat_map(|&sid| self.slots[sid as usize].dec.iter().map(|w| w.unwrap()))
                .collect()
        } else {
            let jobs: Vec<Job> = sids
                .iter()
                .flat_map(|&sid| {
                    let s = &self.slots[sid as usize];
                    (0..a).map(move |i| Job::mul(s.dec[i].unwrap(), &lam[i]))
                })
                .collect();
            b.run(&jobs)?
        };
        let mut sums = Vec::new();
        let mut halves = Vec::new();
        for (k, &sid) in sids.iter().enumerate() {
            let s = &self.slots[sid as usize];
            // [m]g = b − Σ λ_i w_i
            let m = lw[a * k..a * (k + 1)]
                .iter()
                .fold(s.dct.unwrap().b, |acc, x| acc - x);
            if self.is_release(sid) {
                ensure!(self.result.is_none(), "release opened twice");
                self.result = Some(if m.is_zero() {
                    false
                } else if m == g() {
                    true
                } else {
                    bail!("release decrypted to neither identity nor g")
                });
            } else {
                let xp = s.xp.unwrap();
                let sum = if m == g() {
                    s.x.unwrap().add(&xp)
                } else if m == -g() {
                    s.x.unwrap().sub(&xp)
                } else {
                    bail!("gate {sid}: opened value is not ±1");
                };
                // Z = (X · X'^{y'})^{1/2}
                halves.extend([Job::mul(sum.a, &inv2()), Job::mul(sum.b, &inv2())]);
                sums.push(sid);
            }
        }
        let z = if halves.is_empty() {
            vec![]
        } else {
            b.run(&halves)?
        };
        for &sid in sids {
            self.slots[sid as usize].done = true;
            self.active.remove(&sid);
        }
        for (k, &sid) in sums.iter().enumerate() {
            self.gates_done += 1;
            if let Some(plan) = &self.reference {
                let stage = plan.stage[sid as usize];
                self.stage_remaining[stage] -= 1;
                if self.stage_remaining[stage] == 0 {
                    self.completed_stages += 1;
                }
            }
            let node = self.circ.gates[sid as usize];
            self.set_wire(
                node,
                Ct {
                    a: z[2 * k],
                    b: z[2 * k + 1],
                },
            );
        }
        Ok(())
    }

    /// Authenticates, verifies (in parallel) and applies one board message.
    /// With `verify = false` only the signature and ordering are checked
    /// (used by a publisher that relies on the trustees' and verifier's checks).
    pub fn process(&mut self, msg: &Msg, verify: bool) -> Result<()> {
        // Initializers build affine tables using Rayon batch inversion.
        // Warm before any per-item Rayon work can block on the same OnceLock.
        if self.v2 {
            self.pp.v2();
        }
        let from = msg.from as usize;
        ensure!(from < self.pp.a, "unknown sender");
        ensure!(
            msg.ctr == self.next_ctr[from],
            "replayed or reordered message"
        );
        let t = Instant::now();
        msg.verify_sig_format(&self.pp.vks[from], &self.pp.ctx, self.format())?;
        self.prof.signature += t.elapsed().as_secs_f64();
        let t = Instant::now();
        let enc: Vec<Vec<u8>> = bincode::deserialize(&msg.body)?;
        let mut items: Vec<Item> = enc
            .par_iter()
            .map(|b| message_wire(self.wide_points, || bincode::deserialize(b)))
            .collect::<Result<_, _>>()?;
        ensure!(
            items
                .iter()
                .all(|it| it.is_v2().unwrap_or(self.v2) == self.v2),
            "item of the wrong transcript format"
        );
        let cofactor_start = Instant::now();
        let lifts: Vec<Option<(Ct, Ct)>> = if self.v2 {
            items.par_iter_mut().map(|it| it.canonicalize()).collect()
        } else {
            vec![None; items.len()]
        };
        if self.v2 {
            self.prof.cofactor_decode += cofactor_start.elapsed().as_secs_f64();
        }
        self.prof.decode += t.elapsed().as_secs_f64();
        let mut seen = HashSet::new();
        let mut starts = 0;
        for it in &items {
            if from == 0 && matches!(it, Item::Mask { .. } | Item::Mask2 { .. }) {
                starts += 1;
            }
            ensure!(
                seen.insert((std::mem::discriminant(it), it.slot())),
                "duplicate item in batch"
            );
        }
        if starts > 0 {
            self.gate_batches += 1;
            self.max_gate_batch = self.max_gate_batch.max(starts);
        }
        if verify && self.v2 {
            self.verify_v2(from, &items, msg)?;
        } else if verify {
            match self.batch.clone() {
                None => {
                    let t = Instant::now();
                    items.par_iter().try_for_each(|it| {
                        ensure!(it.points_valid(), "point outside the prime-order subgroup");
                        self.check(from, it)
                    })?;
                    self.prof.verify_inline += t.elapsed().as_secs_f64();
                }
                Some(b) => self.verify_batched(from, &items, &*b)?,
            }
        }
        let t = Instant::now();
        for (it, lift) in items.into_iter().zip(lifts) {
            self.n_items += 1;
            if let Some(l) = lift {
                self.slots[it.slot() as usize].chain_lift.push(l);
            }
            self.apply(from, it)?;
        }
        self.prof.apply += t.elapsed().as_secs_f64();
        if !self.pending_finish.is_empty() {
            let t = Instant::now();
            let sids = std::mem::take(&mut self.pending_finish);
            let b = self
                .batch
                .clone()
                .unwrap_or_else(|| Arc::new(crate::batch::Cpu));
            self.finish(&sids, &*b)?;
            self.prof.finish += t.elapsed().as_secs_f64();
        }
        self.next_ctr[from] += 1;
        self.n_msgs += 1;
        Ok(())
    }

    /// Message-level batched verification: state checks, then one backend
    /// call for all subgroup checks and proof multiplications of the batch,
    /// then the (parallel) completion of every check.
    fn verify_batched(&mut self, from: usize, items: &[Item], b: &dyn MulBackend) -> Result<()> {
        let t = Instant::now();
        items
            .par_iter()
            .try_for_each(|it| self.validate(from, it))?;
        let per: Vec<(usize, Vec<Job>)> = items
            .par_iter()
            .map(|it| {
                let pts = it.points();
                let mut v: Vec<Job> = pts.iter().map(|p| Job::subgroup(*p)).collect();
                v.extend(self.proof_jobs(from, it));
                (pts.len(), v)
            })
            .collect();
        let mut offs = Vec::with_capacity(per.len() + 1);
        offs.push(0);
        let mut all = Vec::with_capacity(per.iter().map(|p| p.1.len()).sum());
        for (_, v) in &per {
            all.extend_from_slice(v);
            offs.push(all.len());
        }
        self.prof.batch_build += t.elapsed().as_secs_f64();
        let t = Instant::now();
        let res = if all.is_empty() { vec![] } else { b.run(&all)? };
        ensure!(
            res.len() == all.len(),
            "backend returned {} results for {} jobs",
            res.len(),
            all.len()
        );
        self.prof.batch_run += t.elapsed().as_secs_f64();
        self.prof.jobs += all.len() as u64;
        self.prof.batches += 1;
        self.prof.max_batch = self.prof.max_batch.max(all.len() as u64);
        let t = Instant::now();
        items.par_iter().enumerate().try_for_each(|(i, it)| {
            let r = &res[offs[i]..offs[i + 1]];
            let np = per[i].0;
            ensure!(
                r[..np].iter().all(|z| z.is_zero()),
                "point outside the prime-order subgroup"
            );
            self.proof_ok(from, it, &r[np..])
        })?;
        self.prof.batch_check += t.elapsed().as_secs_f64();
        Ok(())
    }

    /// v2 relations of one (canonical, validated) item.
    fn rels_v2(&self, from: usize, it: &Item) -> Result<Rels> {
        let pp = &*self.pp;
        let sid = it.slot();
        let label = Public::label(sid, from);
        Ok(match it {
            Item::Mask2 { x, y, e, proof, .. } => {
                let (x0, y0) = self.mask_prev(sid, from);
                let st = CszStmt {
                    x0,
                    y0,
                    x1: x,
                    y1: y,
                    e,
                };
                proof
                    .rels(&pp.key, &pp.ctx, label, &st)
                    .ok_or_else(|| anyhow::anyhow!("PoK-CSZ rejected"))?
            }
            Item::Reveal2 { r, proof, .. } => proof
                .rels(&pp.ctx, label, r)
                .ok_or_else(|| anyhow::anyhow!("ZKP0 rejected"))?,
            Item::Dec2 { w, proof, .. } => {
                let u = self.slots[sid as usize].dct.unwrap().a;
                proof.rels(&pp.ctx, label, &pp.v2().wb[from], &u, w)
            }
            Item::Commit { .. } => Rels::default(),
            _ => bail!("v1 item in a v2 transcript"),
        })
    }

    /// v2 verification of one message: state checks, then either every
    /// relation separately (`v2_individual`) or one random linear combination
    /// `Σ ρ_j R_j = O` with independent `ρ_j ∈ [0, 2^128)` evaluated as a
    /// single MSM. On a failed combination the items are re-checked one by one
    /// to report the offending proof.
    fn verify_v2(&mut self, from: usize, items: &[Item], msg: &Msg) -> Result<()> {
        let t = Instant::now();
        items
            .par_iter()
            .try_for_each(|it| self.validate(from, it))?;
        let rels: Vec<Rels> = items
            .par_iter()
            .map(|it| self.rels_v2(from, it))
            .collect::<Result<_>>()?;
        let pp = self.pp.clone();
        let tw = &pp.v2().tw[from];
        let bases = Bases {
            g: &pp.key.tg,
            h: &pp.key.th,
            ht: &pp.tht,
            w: Some(tw),
        };
        let individual = |rels: &[Rels]| -> Result<()> {
            items.par_iter().zip(rels).try_for_each(|(it, r)| {
                ensure!(r.check_each(&bases), "{} rejected", it.kind());
                Ok(())
            })
        };
        if self.v2_individual {
            self.prof.batch_build += t.elapsed().as_secs_f64();
            let t = Instant::now();
            individual(&rels)?;
            self.prof.verify_inline += t.elapsed().as_secs_f64();
            return Ok(());
        }
        let seed: [u8; 32] = if self.v2_coeff_fs {
            sha256(&[
                if self.lift_policy == LiftPolicy::Legacy {
                    b"wod/v2/batch-coefficients"
                } else {
                    b"wod/v3/batch-coefficients"
                },
                &pp.ctx,
                &[from as u8],
                &msg.ctr.to_be_bytes(),
                &msg.body,
            ])
        } else {
            rand::random()
        };
        let acc = rels
            .par_iter()
            .enumerate()
            .map(|(i, r)| {
                let key = if self.lift_policy == LiftPolicy::Legacy {
                    sha256(&[&seed, &(i as u64).to_be_bytes()])
                } else {
                    sha256(&[
                        b"wod/v3/relation-coefficients",
                        &seed,
                        &(i as u64).to_be_bytes(),
                    ])
                };
                let mut rng = ChaCha20Rng::from_seed(key);
                let mut a = Acc::default();
                a.add(r, &mut rng);
                a
            })
            .reduce(Acc::default, |mut a, b| {
                a.merge(b);
                a
            });
        let fixed = acc.fixed_part(&bases);
        self.prof.batch_build += t.elapsed().as_secs_f64();
        let t = Instant::now();
        let m = match &self.batch {
            Some(b) => b.msm(&acc.pts, &acc.sc)?,
            None => crate::batch::msm_cpu(&acc.pts, &acc.sc),
        };
        self.prof.batch_run += t.elapsed().as_secs_f64();
        self.prof.jobs += acc.pts.len() as u64;
        self.prof.batches += 1;
        self.prof.max_batch = self.prof.max_batch.max(acc.pts.len() as u64);
        if !(fixed + m).is_zero() {
            individual(&rels)?;
            bail!("v2 batch relation failed");
        }
        Ok(())
    }

    pub fn output_ct(&self) -> Option<Ct> {
        self.wires[self.circ.output as usize]
    }

    pub fn finished(&self) -> bool {
        self.result.is_some()
    }
}

/// A trustee: private key share, signing key and per-slot rerandomizer secrets.
pub struct Trustee {
    pub id: usize,
    share: F,
    sk: SigningKey,
    ctr: u64,
    rng: ChaCha20Rng,
    /// Independent random tape: never reused for a witness/proof nonce.
    representation_rng: Option<ChaCha20Rng>,
    reveals: HashMap<u32, Item>,
    sent: HashSet<Act>,
}

enum Out {
    Item(Item),
    WithReveal(Item, Item),
}

impl Trustee {
    pub fn new(id: usize, share: F, sk: SigningKey) -> Self {
        Trustee {
            id,
            share,
            sk,
            ctr: 0,
            rng: ChaCha20Rng::from_entropy(),
            representation_rng: None,
            reveals: HashMap::new(),
            sent: HashSet::new(),
        }
    }

    /// Fresh rerandomizers `Enc(0)` with ZKP0, a salt and the hash commitment.
    fn rerand<R: RngCore + CryptoRng>(
        &self,
        eng: &Engine,
        sid: u32,
        k: usize,
        rng: &mut R,
    ) -> (Item, [u8; 32]) {
        let pp = &*eng.pp;
        let rs: Vec<F> = (0..k).map(|_| rand_scalar(rng)).collect();
        let r: Vec<Ct> = rs.iter().map(|x| pp.key.enc0(x)).collect();
        let proof = Zkp0::prove(&pp.key, &pp.ctx, Public::label(sid, self.id), &r, &rs, rng);
        let salt: [u8; 32] = rng.r#gen();
        let commit = commit_hash(&pp.ctx, sid, self.id, &r, &proof, &salt);
        (
            Item::Reveal {
                slot: sid,
                r,
                proof,
                salt,
            },
            commit,
        )
    }

    /// v2 rerandomizers: lifted `Enc(0)` with a v2 ZKP0, salt and commitment
    /// (computed over the canonical values).
    fn rerand2<R: RngCore + CryptoRng>(
        &self,
        eng: &Engine,
        sid: u32,
        k: usize,
        rng: &mut R,
    ) -> (Item, [u8; 32]) {
        let pp = &*eng.pp;
        let v2 = pp.v2();
        let rs: Vec<F> = (0..k).map(|_| rand_scalar(rng)).collect();
        let rl: Vec<Ct> = rs.iter().map(|x| v2.lk.enc0(x)).collect();
        let r: Vec<Ct> = rl.iter().map(|c| c.clear8()).collect();
        let label = Public::label(sid, self.id);
        let proof = Zkp02::prove(&pp.key, &v2.lk, &pp.ctx, label, &r, &rs, rng);
        let canon = Zkp02 {
            e: proof.e.iter().map(|c| c.clear8()).collect(),
            z: proof.z.clone(),
        };
        let salt: [u8; 32] = rng.r#gen();
        let commit = commit_hash2(&pp.ctx, sid, self.id, &r, &canon, &salt);
        (
            Item::Reveal2 {
                slot: sid,
                r: rl,
                proof,
                salt,
            },
            commit,
        )
    }

    fn act2(&self, eng: &Engine, act: Act, rng: &mut ChaCha20Rng) -> Out {
        let pp = &*eng.pp;
        let v2 = pp.v2();
        let me = self.id;
        match act {
            Act::Mask(sid) => {
                let s = &eng.slots[sid as usize];
                let ((x0, y0), (lx0, ly0)) = if me == 0 {
                    let (x, y) = (s.x.unwrap(), s.y0.unwrap());
                    ((x, y), (x.lift_of(), y.lift_of()))
                } else if eng.lift_policy == LiftPolicy::Canonical {
                    let (x, y) = s.chain[me - 1];
                    ((x, y), (x.lift_of(), y.lift_of()))
                } else {
                    (s.chain[me - 1], s.chain_lift[me - 1])
                };
                let sign: i64 = if rng.r#gen::<bool>() { 1 } else { -1 };
                let (r1, r2) = (rand_scalar(rng), rand_scalar(rng));
                let lx1 = lx0.small(sign).add(&v2.lk.enc0(&r1));
                let ly1 = ly0.small(sign).add(&v2.lk.enc0(&r2));
                let le = v2.tht8.mul(&r1);
                let (x1, y1, e) = (lx1.clear8(), ly1.clear8(), clear8(&le));
                let st = CszStmt {
                    x0: &x0,
                    y0: &y0,
                    x1: &x1,
                    y1: &y1,
                    e: &e,
                };
                let label = Public::label(sid, me);
                let proof = Csz2::prove(
                    &pp.key, &v2.lk, &v2.tht8, &pp.ctx, label, &st, sign, &r1, &r2, rng,
                );
                let (rev, commit) = self.rerand2(eng, sid, 2, rng);
                Out::WithReveal(
                    Item::Mask2 {
                        slot: sid,
                        x: lx1,
                        y: ly1,
                        e: le,
                        proof,
                        commit,
                    },
                    rev,
                )
            }
            Act::Commit(sid) => {
                let (rev, commit) = self.rerand2(eng, sid, 1, rng);
                Out::WithReveal(Item::Commit { slot: sid, commit }, rev)
            }
            Act::Reveal(_) => unreachable!("reveals are precomputed"),
            Act::Dec(sid) => {
                let u = eng.slots[sid as usize].dct.unwrap().a;
                let sw = pp.lam[me] * self.share;
                let (w, proof) = Dleq2::prove(
                    &pp.key.tg,
                    &v2.lk,
                    &pp.ctx,
                    Public::label(sid, me),
                    &sw,
                    &v2.wb[me],
                    &u,
                    rng,
                );
                Out::Item(Item::Dec2 {
                    slot: sid,
                    w,
                    proof,
                })
            }
        }
    }

    fn act(&self, eng: &Engine, act: Act, rng: &mut ChaCha20Rng) -> Out {
        if eng.v2 {
            return self.act2(eng, act, rng);
        }
        let pp = &*eng.pp;
        let me = self.id;
        match act {
            Act::Mask(sid) => {
                let s = &eng.slots[sid as usize];
                let (x0, y0) = if me == 0 {
                    (s.x.unwrap(), s.y0.unwrap())
                } else {
                    s.chain[me - 1]
                };
                let sign: i64 = if rng.r#gen::<bool>() { 1 } else { -1 };
                let (r1, r2) = (rand_scalar(rng), rand_scalar(rng));
                let x1 = pp.key.reenc(&x0.small(sign), &r1);
                let y1 = pp.key.reenc(&y0.small(sign), &r2);
                let e = pp.tht.mul(&r1);
                let st = CszStmt {
                    x0: &x0,
                    y0: &y0,
                    x1: &x1,
                    y1: &y1,
                    e: &e,
                };
                let proof = Csz::prove(
                    &pp.key,
                    &pp.tht,
                    &pp.ctx,
                    Public::label(sid, me),
                    &st,
                    sign,
                    &r1,
                    &r2,
                    rng,
                );
                let (rev, commit) = self.rerand(eng, sid, 2, rng);
                Out::WithReveal(
                    Item::Mask {
                        slot: sid,
                        x: x1,
                        y: y1,
                        e,
                        proof,
                        commit,
                    },
                    rev,
                )
            }
            Act::Commit(sid) => {
                let (rev, commit) = self.rerand(eng, sid, 1, rng);
                Out::WithReveal(Item::Commit { slot: sid, commit }, rev)
            }
            Act::Reveal(_) => unreachable!("reveals are precomputed"),
            Act::Dec(sid) => {
                let u = eng.slots[sid as usize].dct.unwrap().a;
                let w = vmul(&u, &self.share);
                let proof = Dleq::prove(
                    &pp.key.tg,
                    &pp.ctx,
                    Public::label(sid, me),
                    &self.share,
                    &pp.hi[me],
                    &u,
                    &w,
                    rng,
                );
                Out::Item(Item::Dec {
                    slot: sid,
                    w,
                    proof,
                })
            }
        }
    }

    /// Computes all newly enabled contributions in parallel and signs them as
    /// one board message. Returns `None` if nothing is enabled.
    pub fn produce(&mut self, eng: &Engine) -> Option<Msg> {
        if eng.v2 {
            eng.pp.v2();
        }
        let acts: Vec<Act> = eng
            .actions(self.id)
            .into_iter()
            .filter(|a| !self.sent.contains(a))
            .collect();
        if acts.is_empty() {
            return None;
        }
        let mut items = Vec::with_capacity(acts.len());
        let mut todo = Vec::new();
        for a in &acts {
            self.sent.insert(*a);
            match a {
                Act::Reveal(sid) => items.push(self.reveals.remove(sid).expect("reveal secret")),
                _ => {
                    let representation_seed = if eng.lift_policy == LiftPolicy::Randomized {
                        self.representation_rng
                            .get_or_insert_with(ChaCha20Rng::from_entropy)
                            .r#gen::<[u8; 32]>()
                    } else {
                        [0; 32]
                    };
                    todo.push((*a, self.rng.r#gen::<[u8; 32]>(), representation_seed));
                }
            }
        }
        let outs: Vec<Out> = todo
            .par_iter()
            .map(|(a, seed, representation_seed)| {
                let mut out = self.act(eng, *a, &mut ChaCha20Rng::from_seed(*seed));
                if eng.lift_policy == LiftPolicy::Randomized {
                    let seed = sha256(&[
                        b"wod/v3/representation-torsion",
                        &eng.pp.ctx,
                        &(self.id as u64).to_be_bytes(),
                        &self.ctr.to_be_bytes(),
                        &bincode::serialize(a).unwrap(),
                        representation_seed,
                    ]);
                    let mut rr = ChaCha20Rng::from_seed(seed);
                    match &mut out {
                        Out::Item(i) => i.randomize_lifts(&mut rr),
                        Out::WithReveal(i, rev) => {
                            i.randomize_lifts(&mut rr);
                            rev.randomize_lifts(&mut rr);
                        }
                    }
                }
                out
            })
            .collect();
        for o in outs {
            match o {
                Out::Item(i) => items.push(i),
                Out::WithReveal(i, rev) => {
                    self.reveals.insert(i.slot(), rev);
                    items.push(i);
                }
            }
        }
        let m = Msg::sign_format(
            &self.sk,
            &eng.pp.ctx,
            self.id as u8,
            self.ctr,
            &items,
            eng.format(),
        );
        self.ctr += 1;
        Some(m)
    }
}

/// Co-located execution (the paper's reported mode): one process holds all
/// trustees and a single engine replica verifies every message once.
/// Returns the ordered board messages.
pub fn run_local(eng: &mut Engine, trustees: &mut [Trustee], verify: bool) -> Result<Vec<Msg>> {
    let mut log = Vec::new();
    while !eng.finished() {
        let mut progressed = false;
        for t in trustees.iter_mut() {
            if let Some(m) = t.produce(eng) {
                eng.process(&m, verify)?;
                log.push(m);
                progressed = true;
            }
        }
        ensure!(progressed, "protocol stalled");
    }
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    fn committee(a: usize) -> (F, Arc<Public>, Vec<Trustee>) {
        let mut rng = thread_rng();
        let (sk, shares) = shamir::deal(a - 1, a, &mut rng);
        let sks: Vec<SigningKey> = (0..a).map(|_| SigningKey::generate(&mut rng)).collect();
        let pp = Public::new(
            g() * sk,
            shares.iter().map(|s| g() * s).collect(),
            sks.iter().map(|k| k.verifying_key()).collect(),
            [3; 32],
        );
        let ts = shares
            .into_iter()
            .zip(sks)
            .enumerate()
            .map(|(i, (s, k))| Trustee::new(i, s, k))
            .collect();
        (sk, Arc::new(pp), ts)
    }

    #[test]
    fn single_conditional_gate_all_inputs() {
        let mut rng = thread_rng();
        for (x, y) in [(0u64, 0u64), (0, 1), (1, 0), (1, 1)] {
            let (sk, pp, mut ts) = committee(5);
            let inputs = [
                pp.key.enc(&F::from(x), &rand_scalar(&mut rng)),
                pp.key.enc(&F::from(y), &rand_scalar(&mut rng)),
            ];
            let mut eng =
                Engine::new(pp.clone(), Arc::new(Circuit::single_gate()), &inputs).unwrap();
            let log = run_local(&mut eng, &mut ts, true).unwrap();
            assert_eq!(
                decrypt_small(&sk, &eng.output_ct().unwrap(), 4),
                Some((x * y) as i64)
            );
            assert_eq!(eng.result, Some(x * y == 1));
            // independent replay of the transcript
            let mut v = Engine::new(pp.clone(), Arc::new(Circuit::single_gate()), &inputs).unwrap();
            for m in &log {
                v.process(m, true).unwrap();
            }
            assert_eq!(v.result, eng.result);
            assert_eq!(v.output_ct(), eng.output_ct());
        }
    }

    #[test]
    fn tampered_message_rejected() {
        let mut rng = thread_rng();
        let (_, pp, mut ts) = committee(5);
        let inputs = [
            pp.key.enc(&F::from(1u64), &rand_scalar(&mut rng)),
            pp.key.enc(&F::from(1u64), &rand_scalar(&mut rng)),
        ];
        let mut eng = Engine::new(pp.clone(), Arc::new(Circuit::single_gate()), &inputs).unwrap();
        let log = run_local(&mut eng, &mut ts, true).unwrap();
        // flip a byte in the first body: signature must fail
        let mut bad = log[0].clone();
        let k = bad.body.len() / 2;
        bad.body[k] ^= 1;
        let mut v = Engine::new(pp.clone(), Arc::new(Circuit::single_gate()), &inputs).unwrap();
        assert!(v.process(&bad, true).is_err());
        // out-of-order delivery is rejected
        let mut v = Engine::new(pp.clone(), Arc::new(Circuit::single_gate()), &inputs).unwrap();
        assert!(v.process(&log[1], true).is_err());
        // a correctly signed but invalid proof is rejected
        let mut v = Engine::new(pp, Arc::new(Circuit::single_gate()), &inputs).unwrap();
        let enc: Vec<Vec<u8>> = bincode::deserialize(&log[0].body).unwrap();
        let mut items: Vec<Item> = enc
            .iter()
            .map(|b| bincode::deserialize(b).unwrap())
            .collect();
        if let Item::Mask { x, .. } = &mut items[0] {
            *x = x.add(&Ct::trivial(1));
        }
        let forged = Msg::sign(&ts[0].sk, &v.pp.ctx, 0, 0, &items);
        assert!(v.process(&forged, true).is_err());
        // a point with a small-order component is rejected
        let mut items: Vec<Item> = enc
            .iter()
            .map(|b| bincode::deserialize(b).unwrap())
            .collect();
        let t2 = ark_ed_on_bn254::EdwardsAffine::new_unchecked(Fb::from(0u64), -Fb::from(1u64));
        if let Item::Mask { e, .. } = &mut items[0] {
            *e += t2;
        }
        let forged = Msg::sign(&ts[0].sk, &v.pp.ctx, 0, 0, &items);
        let err = v.process(&forged, true).unwrap_err().to_string();
        assert!(err.contains("subgroup"), "{err}");
    }

    #[test]
    fn small_election_circuit_n4() {
        let mut rng = thread_rng();
        let (sk, pp, mut ts) = committee(5);
        let (w, v) = ([3u64, 5, 200, 17], [1u64, 1, 0, 1]);
        let tau = 25;
        let circ = Arc::new(Circuit::build(4, 8, tau));
        let inputs: Vec<Ct> = (0..4)
            .flat_map(|i| (0..8).map(move |k| (v[i] * w[i] >> k) & 1))
            .map(|b| pp.key.enc(&F::from(b), &rand_scalar(&mut rng)))
            .collect();
        let mut eng = Engine::new(pp, circ.clone(), &inputs).unwrap();
        run_local(&mut eng, &mut ts, true).unwrap();
        assert_eq!(eng.gates_done, circ.n_gates());
        assert_eq!(eng.result, Some(25 >= tau));
        assert_eq!(decrypt_small(&sk, &eng.output_ct().unwrap(), 2), Some(1));
    }

    #[test]
    fn batched_verification_matches_inline_and_rejects_forgeries() {
        use crate::batch::{Cpu, Inline, MulBackend, Recorder};
        let mut rng = thread_rng();
        let (sk, pp, mut ts) = committee(5);
        let (w, v, tau) = ([3u64, 5, 200, 17], [1u64, 1, 0, 1], 25);
        let circ = Arc::new(Circuit::build(4, 8, tau));
        let inputs: Vec<Ct> = (0..4)
            .flat_map(|i| (0..8).map(move |k| (v[i] * w[i] >> k) & 1))
            .map(|b| pp.key.enc(&F::from(b), &rand_scalar(&mut rng)))
            .collect();
        // produce with a batched (CPU) verifier
        let rec = Recorder::new(Arc::new(Cpu));
        let mut eng = Engine::new(pp.clone(), circ.clone(), &inputs).unwrap();
        eng.set_batch_backend(Some(rec.clone()));
        let log = run_local(&mut eng, &mut ts, true).unwrap();
        assert_eq!(eng.result, Some(true));
        assert_eq!(decrypt_small(&sk, &eng.output_ct().unwrap(), 2), Some(1));
        let batches = rec.take();
        assert!(batches.iter().map(|b| b.jobs).max().unwrap() > 100);
        // replays: inline, batched on CPU, batched on the sequential backend
        let backends: [Option<Arc<dyn MulBackend>>; 3] =
            [None, Some(Arc::new(Cpu)), Some(Arc::new(Inline))];
        for b in backends {
            let mut r = Engine::new(pp.clone(), circ.clone(), &inputs).unwrap();
            r.set_batch_backend(b);
            for m in &log {
                r.process(m, true).unwrap();
            }
            assert_eq!(r.result, eng.result);
            assert_eq!(r.output_ct(), eng.output_ct());
            assert_eq!(r.gates_done, circ.n_gates());
        }
        // forged proof and small-order point are rejected by the batched path
        let enc: Vec<Vec<u8>> = bincode::deserialize(&log[0].body).unwrap();
        let items: Vec<Item> = enc
            .iter()
            .map(|b| bincode::deserialize(b).unwrap())
            .collect();
        let t2 = ark_ed_on_bn254::EdwardsAffine::new_unchecked(Fb::from(0u64), -Fb::from(1u64));
        for (k, tamper) in [0, 1].into_iter().enumerate() {
            let mut bad = items.clone();
            if let Item::Mask { x, e, .. } = &mut bad[0] {
                if tamper == 0 {
                    *x = x.add(&Ct::trivial(1))
                } else {
                    *e += t2
                }
            }
            let forged = Msg::sign(&ts[0].sk, &pp.ctx, 0, 0, &bad);
            let mut r = Engine::new(pp.clone(), circ.clone(), &inputs).unwrap();
            r.set_batch_backend(Some(Arc::new(Cpu)));
            let err = r.process(&forged, true).unwrap_err().to_string();
            assert!(
                err.contains(if k == 0 { "PoK-CSZ" } else { "subgroup" }),
                "{err}"
            );
        }
    }

    #[test]
    fn schedulers_share_circuit_and_reject_invalid_proofs() {
        let mut rng = thread_rng();
        let (_, pp, keys) = committee(5);
        for tau in [25, 26] {
            let circ = Arc::new(Circuit::build(4, 8, tau));
            let plan = circ.reference_schedule();
            let inputs: Vec<Ct> = [3u64, 5, 0, 17]
                .into_iter()
                .flat_map(|w| (0..8).map(move |bit| (w >> bit) & 1))
                .map(|b| pp.key.enc(&F::from(b), &rand_scalar(&mut rng)))
                .collect();
            for scheduler in [Scheduler::Reference, Scheduler::Dataflow] {
                let mut trustees: Vec<_> = keys
                    .iter()
                    .map(|k| Trustee::new(k.id, k.share, k.sk.clone()))
                    .collect();
                let mut engine = Engine::new(pp.clone(), circ.clone(), &inputs).unwrap();
                engine.select_scheduler(scheduler).unwrap();
                let log = run_local(&mut engine, &mut trustees, true).unwrap();
                assert_eq!(engine.result, Some(25 >= tau));
                assert_eq!(engine.gates_done, circ.n_gates());
                assert_eq!(engine.n_items, 15 * (circ.n_gates() + 1));
                assert!(
                    engine.max_gate_batch >= 2,
                    "independent adders were serialized globally"
                );
                assert!(engine.select_scheduler(Scheduler::Dataflow).is_err());
                let mut replay = Engine::new(pp.clone(), circ.clone(), &inputs).unwrap();
                for message in &log {
                    let enc: Vec<Vec<u8>> = bincode::deserialize(&message.body).unwrap();
                    for bytes in enc {
                        let item: Item = bincode::deserialize(&bytes).unwrap();
                        if scheduler == Scheduler::Reference
                            && message.from == 0
                            && matches!(item, Item::Mask { .. })
                        {
                            let gate = item.slot() as usize;
                            assert!(plan.previous[gate].is_none_or(|p| replay.slots[p].done));
                            assert!(plan.stage.iter().enumerate().all(|(g, stage)| *stage
                                >= plan.stage[gate]
                                || replay.slots[g].done));
                        }
                    }
                    replay.process(message, true).unwrap();
                }
                assert_eq!(replay.result, engine.result);
                assert_eq!(replay.output_ct(), engine.output_ct());
                let mut corrupted = log[0].clone();
                corrupted.body[0] ^= 1;
                let mut verifier = Engine::new(pp.clone(), circ.clone(), &inputs).unwrap();
                assert!(verifier.process(&corrupted, true).is_err());
                let enc: Vec<Vec<u8>> = bincode::deserialize(&log[0].body).unwrap();
                let mut items: Vec<Item> = enc
                    .iter()
                    .map(|b| bincode::deserialize(b).unwrap())
                    .collect();
                if let Item::Mask { x, .. } = &mut items[0] {
                    *x = x.add(&Ct::trivial(1));
                } else {
                    panic!("expected initial mask")
                }
                let forged = Msg::sign(&keys[0].sk, &pp.ctx, 0, 0, &items);
                let mut verifier = Engine::new(pp.clone(), circ.clone(), &inputs).unwrap();
                assert!(
                    verifier.process(&forged, true).is_err(),
                    "resigned invalid proof accepted"
                );
            }
        }
    }

    // ------------------------------------------------------- v2 (T007)

    fn v2_engine(
        pp: &Arc<Public>,
        circ: &Arc<Circuit>,
        inputs: &[Ct],
        individual: bool,
        fs: bool,
    ) -> Engine {
        let mut e = Engine::new(pp.clone(), circ.clone(), inputs).unwrap();
        e.v2 = true;
        e.v2_individual = individual;
        e.v2_coeff_fs = fs;
        e
    }

    fn items_of(m: &Msg) -> Vec<Item> {
        let enc: Vec<Vec<u8>> = bincode::deserialize(&m.body).unwrap();
        enc.iter()
            .map(|b| bincode::deserialize(b).unwrap())
            .collect()
    }

    #[test]
    fn v2_single_gate_and_replays() {
        let mut rng = thread_rng();
        for (x, y) in [(0u64, 1u64), (1, 0), (1, 1)] {
            let (sk, pp, mut ts) = committee(5);
            let inputs = [
                pp.key.enc(&F::from(x), &rand_scalar(&mut rng)),
                pp.key.enc(&F::from(y), &rand_scalar(&mut rng)),
            ];
            let circ = Arc::new(Circuit::single_gate());
            let mut eng = v2_engine(&pp, &circ, &inputs, false, false);
            let log = run_local(&mut eng, &mut ts, true).unwrap();
            assert_eq!(
                decrypt_small(&sk, &eng.output_ct().unwrap(), 4),
                Some((x * y) as i64)
            );
            assert_eq!(eng.result, Some(x * y == 1));
            assert!(
                log.iter()
                    .all(|m| items_of(m).iter().all(|i| i.is_v2() != Some(false)))
            );
            for (ind, fs) in [(true, false), (false, true), (false, false)] {
                let mut v = v2_engine(&pp, &circ, &inputs, ind, fs);
                for m in &log {
                    v.process(m, true).unwrap();
                }
                assert_eq!((v.result, v.output_ct()), (eng.result, eng.output_ct()));
            }
            // a v1 engine rejects the v2 transcript
            let mut v1 = Engine::new(pp.clone(), circ.clone(), &inputs).unwrap();
            assert!(v1.process(&log[0], true).is_err());
        }
    }

    #[test]
    fn v2_election_n4_matches_v1_semantics() {
        let mut rng = thread_rng();
        let (sk, pp, mut ts) = committee(5);
        let (w, v, tau) = ([3u64, 5, 200, 17], [1u64, 1, 0, 1], 25);
        let circ = Arc::new(Circuit::build(4, 8, tau));
        let inputs: Vec<Ct> = (0..4)
            .flat_map(|i| (0..8).map(move |k| (v[i] * w[i] >> k) & 1))
            .map(|b| pp.key.enc(&F::from(b), &rand_scalar(&mut rng)))
            .collect();
        let mut eng = v2_engine(&pp, &circ, &inputs, false, false);
        let log = run_local(&mut eng, &mut ts, true).unwrap();
        assert_eq!(eng.gates_done, circ.n_gates());
        assert_eq!(eng.result, Some(true));
        assert_eq!(decrypt_small(&sk, &eng.output_ct().unwrap(), 2), Some(1));
        assert!(eng.prof.max_batch > 100 && eng.prof.batches > 0);
        let mut ind = v2_engine(&pp, &circ, &inputs, true, false);
        for m in &log {
            ind.process(m, true).unwrap();
        }
        assert_eq!(ind.output_ct(), eng.output_ct());
    }

    #[test]
    fn v2_adversarial_messages_rejected() {
        let mut rng = thread_rng();
        let (_, pp, mut ts) = committee(5);
        let inputs = [
            pp.key.enc(&F::from(1u64), &rand_scalar(&mut rng)),
            pp.key.enc(&F::from(1u64), &rand_scalar(&mut rng)),
        ];
        let circ = Arc::new(Circuit::single_gate());
        let mut eng = v2_engine(&pp, &circ, &inputs, false, false);
        let log = run_local(&mut eng, &mut ts, true).unwrap();
        let t2: G =
            ark_ed_on_bn254::EdwardsAffine::new_unchecked(Fb::from(0u64), -Fb::from(1u64)).into();
        let fresh = || v2_engine(&pp, &circ, &inputs, false, false);
        let resign = |from: usize, ctr: u64, items: &[Item], ctx: &[u8; 32]| {
            Msg::sign(&ts[from].sk, ctx, from as u8, ctr, items)
        };
        let base = items_of(&log[0]);
        // (1) torsion-offset lifts: same canonical values, accepted
        let mut it = base.clone();
        if let Item::Mask2 { x, proof, e, .. } = &mut it[0] {
            x.a += t2;
            *e += t2;
            proof.c[3].b += t2;
        }
        let mut v = fresh();
        v.process(&resign(0, 0, &it, &pp.ctx), true).unwrap();
        // (2) altered commitment, response and challenge share, in both verifier modes
        for (k, tamper) in [0, 1, 2].into_iter().enumerate() {
            let mut it = base.clone();
            if let Item::Mask2 { proof, .. } = &mut it[0] {
                match tamper {
                    0 => proof.c[1].a += g(),
                    1 => proof.a[2] += F::from(1u64),
                    _ => proof.d1 += F::from(1u64),
                }
            }
            for individual in [false, true] {
                let mut v = v2_engine(&pp, &circ, &inputs, individual, false);
                let err = v
                    .process(&resign(0, 0, &it, &pp.ctx), true)
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("PoK-CSZ"), "case {k}: {err}");
            }
        }
        // (3) cross-poll: the same items under another session context
        let mut v = fresh();
        let mut other = (*pp).clone_with_ctx([9; 32]);
        other.ctx = [9; 32];
        let forged = resign(0, 0, &base, &[9; 32]);
        assert!(v.process(&forged, true).is_err()); // wrong signature context
        let mut v9 = Engine::new(Arc::new(other), circ.clone(), &inputs).unwrap();
        v9.v2 = true;
        assert!(
            v9.process(&forged, true)
                .unwrap_err()
                .to_string()
                .contains("PoK-CSZ")
        );
        // (4) cross-trustee: trustee 1 re-signs trustee 0's first mask as its own
        let mut v = fresh();
        assert!(v.process(&resign(1, 0, &base, &pp.ctx), true).is_err());
        // (5) a v1 message offered to a v2 engine (fresh committee)
        let (_, pp1, mut ts1) = committee(5);
        let in1 = [
            pp1.key.enc(&F::from(1u64), &rand_scalar(&mut rng)),
            pp1.key.enc(&F::from(0u64), &rand_scalar(&mut rng)),
        ];
        let mut e1 = Engine::new(pp1.clone(), circ.clone(), &in1).unwrap();
        let v1log = run_local(&mut e1, &mut ts1, true).unwrap();
        let mut v = v2_engine(&pp1, &circ, &in1, false, false);
        assert!(
            v.process(&v1log[0], true)
                .unwrap_err()
                .to_string()
                .contains("format")
        );
    }

    #[test]
    fn malicious_predecessor_tags_legacy_sign_and_secure_formats_replay() {
        use ark_ec::PrimeGroup;
        use ark_ff::PrimeField;
        let torsion = torsion8()[1];
        let tag = torsion.mul_bigint(F::MODULUS);
        assert_ne!(tag, -tag); // an order-two example would miss this leak
        for (policy, wide) in [
            (LiftPolicy::Legacy, false),
            (LiftPolicy::Canonical, false),
            (LiftPolicy::Randomized, false),
            (LiftPolicy::Randomized, true),
        ] {
            let (_, pp, mut ts) = committee(5);
            let inputs = [
                pp.key.enc(&F::from(1u64), &F::from(17u64)),
                pp.key.enc(&F::from(1u64), &F::from(29u64)),
            ];
            let circ = Arc::new(Circuit::single_gate());
            let mut eng = v2_engine(&pp, &circ, &inputs, false, false);
            eng.lift_policy = policy;
            eng.wide_points = wide;
            let version = eng.format();
            let first = ts[0].produce(&eng).unwrap();
            let encoded: Vec<Vec<u8>> = bincode::deserialize(&first.body).unwrap();
            let mut items: Vec<Item> = encoded
                .iter()
                .map(|b| message_wire(wide, || bincode::deserialize(b).unwrap()))
                .collect();
            if let Item::Mask2 { x, .. } = &mut items[0] {
                x.a += torsion;
            } else {
                panic!("mask required");
            }
            // The adversary changes the representation and signs it. The
            // canonical statement/proof is unchanged and correctly accepted.
            let tagged = Msg::sign_format(&ts[0].sk, &pp.ctx, 0, 0, &items, version);
            eng.process(&tagged, true).unwrap();
            if policy != LiftPolicy::Randomized {
                for seed in 0..16u64 {
                    let mut r = ChaCha20Rng::seed_from_u64(seed);
                    let sign = if r.clone().r#gen::<bool>() { 1 } else { -1 };
                    let out = ts[1].act2(&eng, Act::Mask(0), &mut r);
                    let Out::WithReveal(Item::Mask2 { x, .. }, _) = out else {
                        panic!("mask required");
                    };
                    let observed = x.a.mul_bigint(F::MODULUS);
                    if policy == LiftPolicy::Legacy {
                        assert_eq!(observed, small_mul(&tag, sign));
                    } else {
                        assert!(observed.is_zero());
                    }
                }
            }
            let mut log = vec![tagged];
            log.extend(run_local(&mut eng, &mut ts, true).unwrap());
            assert_eq!(eng.result, Some(true));
            for individual in [true, false] {
                let mut v = v2_engine(&pp, &circ, &inputs, individual, false);
                v.lift_policy = policy;
                v.wide_points = wide;
                for m in &log {
                    v.process(m, true).unwrap();
                }
                assert_eq!(v.result, eng.result);
            }
            if policy != LiftPolicy::Legacy {
                assert!(
                    log[0]
                        .verify_sig_format(&pp.vks[0], &pp.ctx, if wide { 3 } else { 4 })
                        .is_err()
                );
                let mut downgraded = v2_engine(&pp, &circ, &inputs, true, false);
                assert!(downgraded.process(&log[0], true).is_err());
                let mut bad = items.clone();
                if let Item::Mask2 { proof, .. } = &mut bad[0] {
                    proof.a[0] += F::from(1u64);
                }
                let bad = Msg::sign_format(&ts[0].sk, &pp.ctx, 0, 0, &bad, version);
                for individual in [true, false] {
                    let mut v = v2_engine(&pp, &circ, &inputs, individual, false);
                    v.lift_policy = policy;
                    v.wide_points = wide;
                    assert!(v.process(&bad, true).is_err());
                }
            }
        }
    }

    #[test]
    fn cold_public_tables_do_not_hold_a_lock_across_rayon_work() {
        let (_, pp, _) = committee(5);
        rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap()
            .install(|| {
                (0..8).into_par_iter().for_each(|_| {
                    assert_eq!(pp.v2().wb.len(), 5);
                    assert_eq!(
                        pp.v2().lk.enc0(&F::from(3u64)).clear8(),
                        pp.key.enc0(&F::from(3u64))
                    );
                });
            });
    }

    #[test]
    fn v2_cross_slot_substitution_rejected() {
        let mut rng = thread_rng();
        let (_, pp, mut ts) = committee(5);
        let circ = Arc::new(Circuit::build(2, 2, 1));
        let inputs: Vec<Ct> = (0..4)
            .map(|i| pp.key.enc(&F::from((i % 2) as u64), &rand_scalar(&mut rng)))
            .collect();
        let mut eng = v2_engine(&pp, &circ, &inputs, false, false);
        let log = run_local(&mut eng, &mut ts, true).unwrap();
        let first = items_of(&log[0]);
        let masks: Vec<usize> = (0..first.len())
            .filter(|i| matches!(first[*i], Item::Mask2 { .. }))
            .collect();
        assert!(masks.len() >= 2, "need two ready gates");
        let mut it = first.clone();
        // move gate A's proof to gate B (labels bind the slot)
        if let (Item::Mask2 { proof: pa, .. }, Item::Mask2 { .. }) =
            (first[masks[0]].clone(), first[masks[1]].clone())
        {
            if let Item::Mask2 { proof, .. } = &mut it[masks[1]] {
                *proof = pa;
            }
        }
        let forged = Msg::sign(&ts[0].sk, &pp.ctx, 0, 0, &it);
        let mut v = v2_engine(&pp, &circ, &inputs, false, false);
        assert!(
            v.process(&forged, true)
                .unwrap_err()
                .to_string()
                .contains("PoK-CSZ")
        );
    }
}
