//! **Isolated plaintext oracle — testing only.**
//!
//! Reads the private test votes and computes `W = Σ v_i w_i` and
//! `[W ≥ τ]` in the clear. It is never called by the protocol (setup, voting,
//! admission, tally, release, verification); the experiment runner calls it
//! only after the public verifier has finished, and only the agreement bit is
//! written to public artifacts. `W` itself is stored under `private/`.

use crate::setup::{Paths, Setup, VoterRecord, read_bin, write_json};
use anyhow::Result;

pub struct Oracle {
    pub total: u64,
    pub bit: bool,
}

pub fn evaluate(p: &Paths) -> Result<Oracle> {
    let setup: Setup = read_bin(&p.public("setup.bin"))?;
    let voters: Vec<VoterRecord> = read_bin(&p.private("voters.bin"))?;
    let total: u64 = voters.iter().map(|v| if v.vote { v.w } else { 0 }).sum();
    let o = Oracle {
        total,
        bit: total >= setup.tau,
    };
    write_json(
        &p.private("oracle.json"),
        &serde_json::json!({"W": o.total, "tau": setup.tau, "bit": o.bit}),
    )?;
    Ok(o)
}
