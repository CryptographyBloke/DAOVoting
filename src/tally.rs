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

use crate::circuit::{Circuit, Node};
use crate::group::*;
use crate::shamir;
use crate::sigma::{Csz, CszStmt, Dleq, Zkp0};
use anyhow::{Result, anyhow, bail, ensure};
use ark_ff::{Field, Zero};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

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
}

impl Item {
    /// Every group element carried by the item lies in the prime-order
    /// subgroup (decoding only guarantees an on-curve point).
    pub fn points_valid(&self) -> bool {
        let cts_ok = |c: &[Ct]| c.iter().all(|c| in_subgroup(&c.a) && in_subgroup(&c.b));
        match self {
            Item::Mask { x, y, e, .. } => cts_ok(&[*x, *y]) && in_subgroup(e),
            Item::Commit { .. } => true,
            Item::Reveal { r, .. } => cts_ok(r),
            Item::Dec { w, .. } => in_subgroup(w),
        }
    }

    pub fn slot(&self) -> u32 {
        match self {
            Item::Mask { slot, .. }
            | Item::Commit { slot, .. }
            | Item::Reveal { slot, .. }
            | Item::Dec { slot, .. } => *slot,
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

impl Msg {
    pub fn sign(sk: &SigningKey, ctx: &[u8; 32], from: u8, ctr: u64, items: &[Item]) -> Msg {
        let enc: Vec<Vec<u8>> = items
            .par_iter()
            .map(|i| bincode::serialize(i).unwrap())
            .collect();
        let body = bincode::serialize(&enc).unwrap();
        let sig = sk
            .sign(&msg_digest(ctx, from, ctr, &body))
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
        let sig = Signature::from_slice(&self.sig)?;
        vk.verify(&msg_digest(ctx, self.from, self.ctr, &self.body), &sig)?;
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
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
        let pp = &*self.pp;
        let sid = it.slot();
        ensure!((sid as usize) < self.slots.len(), "bad slot");
        let s = &self.slots[sid as usize];
        ensure!(!s.done, "slot already closed");
        let label = Public::label(sid, from);
        match it {
            Item::Mask { x, y, e, proof, .. } => {
                ensure!(!self.is_release(sid), "mask on release slot");
                ensure!(s.chain.len() == from, "mask out of order");
                let (x0, y0) = if from == 0 {
                    (
                        s.x.as_ref().ok_or(anyhow!("gate not ready"))?,
                        s.y0.as_ref().unwrap(),
                    )
                } else {
                    let p = &s.chain[from - 1];
                    (&p.0, &p.1)
                };
                let st = CszStmt {
                    x0,
                    y0,
                    x1: x,
                    y1: y,
                    e,
                };
                ensure!(
                    proof.verify(&pp.key, &pp.tht, &pp.ctx, label, &st),
                    "PoK-CSZ rejected"
                );
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
                ensure!(proof.verify(&pp.key, &pp.ctx, label, r), "ZKP0 rejected");
            }
            Item::Dec { w, proof, .. } => {
                let d = s.dct.as_ref().ok_or(anyhow!("nothing to decrypt"))?;
                ensure!(s.dec[from].is_none(), "duplicate share");
                ensure!(
                    proof.verify(
                        &pp.key.tg,
                        &pp.thi[from],
                        &pp.ctx,
                        label,
                        &pp.hi[from],
                        &d.a,
                        w
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
            Item::Mask { x, y, commit, .. } => {
                s.chain.push((x, y));
                s.commits[from] = Some(commit);
            }
            Item::Commit { commit, .. } => s.commits[from] = Some(commit),
            Item::Reveal { r, .. } => {
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
            Item::Dec { w, .. } => {
                s.dec[from] = Some(w);
                s.n_dec += 1;
                if s.n_dec == a {
                    self.finish(sid)?;
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self, sid: u32) -> Result<()> {
        let pp = self.pp.clone();
        let set: Vec<usize> = (1..=pp.a).collect();
        let s = &mut self.slots[sid as usize];
        let w: Vec<G> = s.dec.iter().map(|w| w.unwrap()).collect();
        let m = shamir::combine(s.dct.as_ref().unwrap(), &set, &w, &pp.lam);
        s.done = true;
        self.active.remove(&sid);
        if self.is_release(sid) {
            self.result = Some(if m.is_zero() {
                false
            } else if m == g() {
                true
            } else {
                bail!("release decrypted to neither identity nor g")
            });
        } else {
            let s = &self.slots[sid as usize];
            let xp = s.xp.unwrap();
            let sum = if m == g() {
                s.x.unwrap().add(&xp)
            } else if m == -g() {
                s.x.unwrap().sub(&xp)
            } else {
                bail!("gate {sid}: opened value is not ±1");
            };
            // Z = (X · X'^{y'})^{1/2}
            let z = sum.scale(&inv2());
            self.gates_done += 1;
            let node = self.circ.gates[sid as usize];
            self.set_wire(node, z);
        }
        Ok(())
    }

    /// Authenticates, verifies (in parallel) and applies one board message.
    /// With `verify = false` only the signature and ordering are checked
    /// (used by a publisher that relies on the trustees' and verifier's checks).
    pub fn process(&mut self, msg: &Msg, verify: bool) -> Result<()> {
        let from = msg.from as usize;
        ensure!(from < self.pp.a, "unknown sender");
        ensure!(
            msg.ctr == self.next_ctr[from],
            "replayed or reordered message"
        );
        msg.verify_sig(&self.pp.vks[from], &self.pp.ctx)?;
        let enc: Vec<Vec<u8>> = bincode::deserialize(&msg.body)?;
        let items: Vec<Item> = enc
            .par_iter()
            .map(|b| bincode::deserialize(b))
            .collect::<Result<_, _>>()?;
        let mut seen = HashSet::new();
        for it in &items {
            ensure!(
                seen.insert((std::mem::discriminant(it), it.slot())),
                "duplicate item in batch"
            );
        }
        if verify {
            items.par_iter().try_for_each(|it| {
                ensure!(it.points_valid(), "point outside the prime-order subgroup");
                self.check(from, it)
            })?;
        }
        for it in items {
            self.n_items += 1;
            self.apply(from, it)?;
        }
        self.next_ctr[from] += 1;
        self.n_msgs += 1;
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

    fn act(&self, eng: &Engine, act: Act, rng: &mut ChaCha20Rng) -> Out {
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
                _ => todo.push((*a, self.rng.r#gen::<[u8; 32]>())),
            }
        }
        let outs: Vec<Out> = todo
            .par_iter()
            .map(|(a, seed)| self.act(eng, *a, &mut ChaCha20Rng::from_seed(*seed)))
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
        let m = Msg::sign(&self.sk, &eng.pp.ctx, self.id as u8, self.ctr, &items);
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
}
