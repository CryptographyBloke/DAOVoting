//! Independent public verifier (paper Eq. 3):
//! `Accept = Chain ∧ Snapshot ∧ Backend ∧ Binding ∧ Hash ∧ Bit ∧ Claim`.
//! Uses only `public/` files: no witness, trustee secret or oracle.

use crate::circuit::Circuit;
use crate::group::sha256;
use crate::ledger::{Contract, Event, sealed_board_hash};
use crate::setup::{Paths, Setup, read_bin, registry, write_json};
use crate::tally::{Engine, Public};
use crate::transcript;
use anyhow::{Result, anyhow, ensure};
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;

/// Session context bound into every trustee proof and signature.
pub fn context(setup_hash: &[u8; 32], board_hash: &[u8; 32]) -> [u8; 32] {
    sha256(&[b"wod/ctx/v1", setup_hash, board_hash])
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub accept: bool,
    pub chain: bool,
    pub snapshot: bool,
    pub backend: bool,
    pub binding: bool,
    pub hash: bool,
    pub bit: bool,
    pub claim: bool,
    pub decision: Option<bool>,
    pub transcript_hash: String,
    pub sealed_commitment: String,
    pub ballots: usize,
    pub ciphertexts: usize,
    pub gates_verified: usize,
    pub messages: usize,
    pub items: usize,
    pub seconds_chain: f64,
    pub seconds_backend: f64,
    pub seconds_total: f64,
    pub peak_rss_bytes: Option<u64>,
    /// verification backend (`inline` = original path) and its phase profile
    pub verify_backend: String,
    pub engine_prof: crate::tally::Prof,
    pub device_times: Option<serde_json::Value>,
    pub error: Option<String>,
}

pub fn verify_dir(p: &Paths) -> Report {
    let r = verify_with_events(p, None);
    let _ = write_json(&p.public("verify.json"), &r);
    r
}

/// Verify a chain-reconstructed board without reading a local ledger. The
/// caller authenticates the receipt source (A6); all cryptographic checks here
/// are identical to the ordinary public verifier.
pub fn verify_events(p: &Paths, events: &[Event]) -> Report {
    verify_with_events(p, Some(events))
}

fn verify_with_events(p: &Paths, events: Option<&[Event]>) -> Report {
    let t0 = Instant::now();
    let mut r = Report::default();
    if let Err(e) = run(p, &mut r, events) {
        r.error = Some(format!("{e:#}"));
    }
    r.accept = r.chain
        && r.snapshot
        && r.backend
        && r.binding
        && r.hash
        && r.bit
        && r.claim
        && r.error.is_none();
    r.seconds_total = t0.elapsed().as_secs_f64();
    r.peak_rss_bytes = crate::experiment::peak_rss_bytes();
    r
}

fn run(p: &Paths, r: &mut Report, supplied: Option<&[Event]>) -> Result<()> {
    let setup: Setup = read_bin(&p.public("setup.bin"))?;
    let events: Vec<Event> = match supplied {
        Some(events) => events.to_vec(),
        None => read_bin(&p.public("ledger.bin"))?,
    };

    // Snapshot: the registry root is the root of the published (credential, weight) list.
    r.snapshot = setup.creds.len() == setup.n
        && setup.weights.len() == setup.n
        && setup.weights.iter().all(|w| *w < 1 << setup.l_vote)
        && registry(&setup).root() == setup.root;
    ensure!(r.snapshot, "snapshot check failed");

    // Chain: replay the contract, re-verifying every Groth16 ballot proof.
    let t = Instant::now();
    let pvk = ark_groth16::prepare_verifying_key(&setup.vk);
    let mut c = Contract::new(&pvk, setup.root, setup.poll, setup.pk, setup.n);
    c.replay(&events, true)?;
    let commit = c.sealed.ok_or(anyhow!("board never sealed"))?;
    let (claim_commit, claim_hash, claim_bit) =
        c.claim.ok_or(anyhow!("no outcome claim recorded"))?;
    r.chain = true;
    r.seconds_chain = t.elapsed().as_secs_f64();
    r.sealed_commitment = hex::encode(commit);
    r.ballots = c.accepted.len();

    // Binding: tally inputs are exactly the sealed-board ciphertexts.
    let inputs = c.sealed_inputs()?;
    r.ciphertexts = inputs.len();
    let board_hash = sealed_board_hash(&commit, &inputs);
    let setup_hash = setup.hash();
    let mut tr = transcript::Reader::open(&p.public("transcript.bin"))?;
    r.binding = tr.board_hash == board_hash
        && tr.setup_hash == setup_hash
        && inputs.len() == setup.n * setup.l_vote;
    ensure!(
        r.binding,
        "transcript is not bound to the sealed board / setup"
    );

    // Backend: verify every gate message and the release, recomputing all outputs.
    let t = Instant::now();
    let pp = Arc::new(Public::new(
        setup.pk,
        setup.hi.clone(),
        setup.vks()?,
        context(&setup_hash, &board_hash),
    ));
    let circ = Arc::new(Circuit::build(setup.n, setup.l_vote, setup.tau));
    let mut eng = Engine::new(pp, circ.clone(), &inputs)?;
    // the transcript header fixes the format; no flag is trusted
    eng.v2 = tr.v2;
    while let Some(m) = tr.next()? {
        ensure!(!eng.finished(), "messages after the release");
        eng.process(&m, true)?;
    }
    r.messages = eng.n_msgs;
    r.items = eng.n_items;
    r.gates_verified = eng.gates_done;
    r.backend = eng.finished() && eng.gates_done == circ.n_gates();
    r.seconds_backend = t.elapsed().as_secs_f64();
    r.verify_backend = crate::batch::default_name();
    r.engine_prof = eng.prof.clone();
    r.device_times = crate::gpu::device_snapshot();
    ensure!(r.backend, "tally incomplete");
    r.decision = eng.result;

    // Hash, Bit, Claim.
    let h = tr.hash();
    r.transcript_hash = hex::encode(h);
    r.hash = h == claim_hash;
    r.bit = eng.result == Some(claim_bit);
    r.claim = claim_commit == commit;
    Ok(())
}
