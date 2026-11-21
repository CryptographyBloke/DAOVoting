//! The admission contract (paper Sect. 4, "Contract"), simulated as a local
//! append-only event log. It binds the registry root, poll id and committee
//! key, verifies one Groth16 proof per ballot, rejects repeated nullifiers and
//! leading ciphertext components equal to the identity, records every
//! ciphertext coordinate in a domain-separated Keccak-256 hash chain, and seals
//! the board at the N-th accepted ballot. The outcome claim
//! `(commit, H(T), b)` is recorded after the tally; the contract checks only
//! that `commit` equals its sealed commitment, `H(T) ≠ 0` and `b ∈ {0,1}`.

use crate::ballot::{self, Ballot};
use crate::group::*;
use anyhow::{Result, bail, ensure};
use ark_bn254::Bn254;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::PreparedVerifyingKey;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    Accepted {
        index: u64,
        ballot: Ballot,
    },
    Sealed {
        count: u64,
        commitment: [u8; 32],
    },
    Claim {
        commitment: [u8; 32],
        transcript_hash: [u8; 32],
        bit: bool,
    },
}

pub struct Contract<'a> {
    pvk: &'a PreparedVerifyingKey<Bn254>,
    root: Fb,
    poll: u64,
    h: G,
    n: usize,
    acc: [u8; 32],
    nullifiers: HashSet<Vec<u8>>,
    pub accepted: Vec<Ballot>,
    pub sealed: Option<[u8; 32]>,
    pub claim: Option<([u8; 32], [u8; 32], bool)>,
    pub events: Vec<Event>,
}

fn be(x: &Fb) -> Vec<u8> {
    x.into_bigint().to_bytes_be()
}

impl<'a> Contract<'a> {
    pub fn new(pvk: &'a PreparedVerifyingKey<Bn254>, root: Fb, poll: u64, h: G, n: usize) -> Self {
        let ha = h.into_affine();
        let mut k = Keccak256::new();
        k.update(b"wod/accepted-ballots/v1");
        k.update(poll.to_be_bytes());
        k.update(be(&root));
        k.update(be(&ha.x));
        k.update(be(&ha.y));
        Contract {
            pvk,
            root,
            poll,
            h,
            n,
            acc: k.finalize().into(),
            nullifiers: HashSet::new(),
            accepted: Vec::new(),
            sealed: None,
            claim: None,
            events: Vec::new(),
        }
    }

    /// Stateless checks (proof, identity rule); parallelisable.
    pub fn precheck(&self, b: &Ballot) -> Result<()> {
        ensure!(
            ballot::identity_free(b),
            "leading ciphertext component is the identity"
        );
        ballot::verify(self.pvk, b, self.root, self.poll, self.h)
    }

    /// Stateful admission of a prechecked ballot.
    fn admit(&mut self, b: Ballot) -> Result<()> {
        ensure!(self.sealed.is_none(), "board is sealed");
        ensure!(
            self.nullifiers.insert(be(&b.nullifier)),
            "repeated nullifier"
        );
        let idx = self.accepted.len() as u64;
        let mut k = Keccak256::new();
        k.update(self.acc);
        k.update(idx.to_be_bytes());
        k.update(be(&b.nullifier));
        for p in G::normalize_batch(&b.cts.iter().flat_map(|c| [c.a, c.b]).collect::<Vec<_>>()) {
            k.update(be(&p.x));
            k.update(be(&p.y));
        }
        self.acc = k.finalize().into();
        self.events.push(Event::Accepted {
            index: idx,
            ballot: b.clone(),
        });
        self.accepted.push(b);
        if self.accepted.len() == self.n {
            let mut k = Keccak256::new();
            k.update(b"wod/seal/v1");
            k.update(self.acc);
            k.update((self.n as u64).to_be_bytes());
            let c: [u8; 32] = k.finalize().into();
            self.sealed = Some(c);
            self.events.push(Event::Sealed {
                count: self.n as u64,
                commitment: c,
            });
        }
        Ok(())
    }

    pub fn submit(&mut self, b: Ballot) -> Result<()> {
        self.precheck(&b)?;
        self.admit(b)
    }

    /// Submits a batch in order; proofs are verified in parallel first.
    /// Returns per-ballot outcomes.
    pub fn submit_all(&mut self, bs: Vec<Ballot>) -> Vec<Result<()>> {
        let pre: Vec<Result<()>> = bs.par_iter().map(|b| self.precheck(b)).collect();
        bs.into_iter()
            .zip(pre)
            .map(|(b, p)| p.and_then(|_| self.admit(b)))
            .collect()
    }

    pub fn post_claim(
        &mut self,
        commitment: [u8; 32],
        transcript_hash: [u8; 32],
        bit: bool,
    ) -> Result<()> {
        ensure!(self.claim.is_none(), "claim already recorded");
        ensure!(
            Some(commitment) == self.sealed,
            "claim commitment does not match the sealed board"
        );
        ensure!(transcript_hash != [0; 32], "zero transcript hash");
        self.claim = Some((commitment, transcript_hash, bit));
        self.events.push(Event::Claim {
            commitment,
            transcript_hash,
            bit,
        });
        Ok(())
    }

    /// Rebuilds the contract state from an event log; every accepted ballot is
    /// re-admitted (with proof verification if `verify_proofs`) and every
    /// recorded event must be reproduced exactly.
    pub fn replay(&mut self, events: &[Event], verify_proofs: bool) -> Result<()> {
        let ballots: Vec<&Ballot> = events
            .iter()
            .filter_map(|e| {
                if let Event::Accepted { ballot, .. } = e {
                    Some(ballot)
                } else {
                    None
                }
            })
            .collect();
        if verify_proofs {
            ballots.par_iter().try_for_each(|b| self.precheck(b))?;
        }
        for e in events {
            match e {
                Event::Accepted { index, ballot } => {
                    ensure!(
                        *index as usize == self.accepted.len(),
                        "ballot index mismatch"
                    );
                    if !verify_proofs {
                        ensure!(ballot::identity_free(ballot), "identity component");
                    }
                    self.admit(ballot.clone())?;
                }
                Event::Sealed { count, commitment } => {
                    ensure!(
                        self.sealed == Some(*commitment) && *count as usize == self.n,
                        "sealed commitment mismatch"
                    );
                }
                Event::Claim {
                    commitment,
                    transcript_hash,
                    bit,
                } => self.post_claim(*commitment, *transcript_hash, *bit)?,
            }
        }
        let regenerated = self.events.len();
        if regenerated != events.len() {
            bail!("event log mismatch");
        }
        Ok(())
    }

    /// Tally inputs: all ciphertexts of the sealed board, in board order.
    pub fn sealed_inputs(&self) -> Result<Vec<Ct>> {
        ensure!(self.sealed.is_some(), "board not sealed");
        Ok(self
            .accepted
            .iter()
            .flat_map(|b| b.cts.iter().copied())
            .collect())
    }
}

/// Canonical sealed-board hash bound into the tally context and `H(T)`.
pub fn sealed_board_hash(commitment: &[u8; 32], inputs: &[Ct]) -> [u8; 32] {
    sha256(&[
        b"wod/sealed-board/v1",
        commitment,
        &bincode::serialize(inputs).unwrap(),
    ])
}
