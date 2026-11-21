//! Arkworks proof export and public event replay for the optional EVM adapter.
//! All exported values are public: verifying key, ballot statements, proofs, and
//! the expected board commitment. Trustee shares, voter secrets, and oracle data
//! are never read by this module.

use crate::ballot::{Ballot, Statement};
use crate::group::{Ct, Fb, GA};
use crate::ledger::{Contract, Event};
use crate::setup::{Paths, Setup, read_bin};
use anyhow::{Result, anyhow, ensure};
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::path::Path;

fn be32<F: PrimeField>(x: &F) -> Result<[u8; 32]> {
    let bytes = x.into_bigint().to_bytes_be();
    ensure!(bytes.len() <= 32, "field element exceeds 32 bytes");
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

fn hex32<F: PrimeField>(x: &F) -> Result<String> {
    Ok(format!("0x{}", hex::encode(be32(x)?)))
}

fn g1_json(p: G1Affine) -> Result<Value> {
    Ok(json!([hex32(&p.x)?, hex32(&p.y)?]))
}

/// EIP-197 encodes each Fq2 coordinate as imaginary coefficient then real.
fn g2_json(p: G2Affine) -> Result<Value> {
    Ok(json!([
        [hex32(&p.x.c1)?, hex32(&p.x.c0)?],
        [hex32(&p.y.c1)?, hex32(&p.y.c0)?]
    ]))
}

fn proof_json(proof: &Proof<Bn254>) -> Result<Value> {
    Ok(json!({
        "a": g1_json(proof.a)?,
        "b": g2_json(proof.b)?,
        "c": g1_json(proof.c)?
    }))
}

fn vk_json(setup: &Setup) -> Result<Value> {
    let vk = &setup.vk;
    let ic = vk
        .gamma_abc_g1
        .iter()
        .map(|p| g1_json(*p))
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({
        "alpha": g1_json(vk.alpha_g1)?,
        "beta": g2_json(vk.beta_g2)?,
        "gamma": g2_json(vk.gamma_g2)?,
        "delta": g2_json(vk.delta_g2)?,
        "ic": ic
    }))
}

/// Export one poll and all genuine Rust-generated proofs as an ABI-ready public
/// JSON document. The destination must be new so earlier evidence is preserved.
pub fn export_run(paths: &Paths, destination: &Path) -> Result<Value> {
    ensure!(
        !destination.exists(),
        "refusing to overwrite {}",
        destination.display()
    );
    let setup: Setup = read_bin(&paths.public("setup.bin"))?;

    let events: Vec<Event> = read_bin(&paths.public("ledger.bin"))?;
    let ballots: Vec<Ballot> = events
        .iter()
        .filter_map(|event| match event {
            Event::Accepted { ballot, .. } => Some(ballot.clone()),
            _ => None,
        })
        .collect();
    ensure!(
        ballots.len() == setup.n,
        "ballot count does not match setup"
    );
    ensure!(
        setup.vk.gamma_abc_g1.len() == 38,
        "expected exactly 37 public inputs"
    );

    let mut exported = Vec::with_capacity(ballots.len());
    for ballot in &ballots {
        let input_fields = Statement {
            cts: &ballot.cts,
            nullifier: ballot.nullifier,
            root: setup.root,
            poll: setup.poll,
            h: setup.pk,
        }
        .public_inputs();
        let signals = input_fields.iter().map(hex32).collect::<Result<Vec<_>>>()?;
        ensure!(signals.len() == 37, "expected exactly 37 ballot inputs");
        let mut vk_x = setup.vk.gamma_abc_g1[0].into_group();
        for (point, signal) in setup.vk.gamma_abc_g1[1..].iter().zip(&input_fields) {
            vk_x += point.mul_bigint(signal.into_bigint());
        }
        exported.push(json!({
            "signals": signals,
            "proof": proof_json(&ballot.proof)?,
            "expectedVkX": g1_json(vk_x.into_affine())?
        }));
    }

    let expected_commitment = events.iter().find_map(|event| match event {
        Event::Sealed { commitment, .. } => Some(format!("0x{}", hex::encode(commitment))),
        _ => None,
    });
    ensure!(expected_commitment.is_some(), "run has no sealed board");
    let expected_claim = events.iter().find_map(|event| match event {
        Event::Claim {
            commitment,
            transcript_hash,
            bit,
        } => Some(json!({
            "commitment": format!("0x{}", hex::encode(commitment)),
            "transcriptHash": format!("0x{}", hex::encode(transcript_hash)),
            "decision": u8::from(*bit)
        })),
        _ => None,
    });
    ensure!(expected_claim.is_some(), "run has no decision claim");
    let vk = vk_json(&setup)?;
    let document = json!({
        "schema": "wod/arkworks-bn254-evm/v1",
        "pollId": setup.poll,
        "expectedBallots": setup.n,
        "threshold": setup.tau,
        "registryRoot": hex32(&setup.root)?,
        "committeeKey": [hex32(&setup.pk.into_affine().x)?, hex32(&setup.pk.into_affine().y)?],
        "verifyingKey": vk,
        "ballots": exported,
        "expectedSealedCommitment": expected_commitment,
        "expectedClaim": expected_claim
    });
    std::fs::write(destination, serde_json::to_vec_pretty(&document)?)?;
    Ok(
        json!({"export": "PASS", "ballots": setup.n, "publicInputsPerBallot": 37, "path": destination.display().to_string()}),
    )
}

fn word(data: &[u8], index: usize) -> Result<[u8; 32]> {
    let start = index
        .checked_mul(32)
        .ok_or_else(|| anyhow!("word index overflow"))?;
    let end = start
        .checked_add(32)
        .ok_or_else(|| anyhow!("word index overflow"))?;
    ensure!(data.len() >= end, "truncated ABI event frame");
    Ok(data[start..end].try_into()?)
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

fn parse_word_field<F: PrimeField>(raw: [u8; 32]) -> Result<F> {
    let value = F::from_be_bytes_mod_order(&raw);
    ensure!(be32(&value)? == raw, "ABI field element out of range");
    Ok(value)
}

fn word_u64(raw: [u8; 32]) -> Result<u64> {
    ensure!(
        raw[..24].iter().all(|byte| *byte == 0),
        "ABI uint64 overflow"
    );
    Ok(u64::from_be_bytes(raw[24..].try_into()?))
}

fn topic_hash(signature: &str) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(signature.as_bytes());
    h.finalize().into()
}

fn event_topics(log: &Value, signature: &str, poll: u64, contract: &str) -> Result<bool> {
    let address = log["address"]
        .as_str()
        .ok_or_else(|| anyhow!("log missing address"))?;
    ensure!(
        address.eq_ignore_ascii_case(contract),
        "log emitted by an unexpected contract"
    );
    let topics = log["topics"]
        .as_array()
        .ok_or_else(|| anyhow!("log missing topics"))?;
    let t0 = topics
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("log missing topic0"))?;
    if parse_hex(t0)?.as_slice() != topic_hash(signature) {
        return Ok(false);
    }
    ensure!(topics.len() == 2, "event has unexpected indexed fields");
    let t1 = topics[1]
        .as_str()
        .ok_or_else(|| anyhow!("log missing poll topic"))?;
    let poll_word: [u8; 32] = parse_hex(t1)?
        .try_into()
        .map_err(|_| anyhow!("bad poll topic size"))?;
    ensure!(word_u64(poll_word)? == poll, "event poll id mismatch");
    Ok(true)
}

fn make_ballot(data: &[u8]) -> Result<(u64, Ballot)> {
    ensure!(
        data.len() == 42 * 32,
        "malformed or truncated BallotAccepted frame"
    );
    let index = word_u64(word(data, 0)?)?;
    let nullifier = parse_word_field::<Fb>(word(data, 1)?)?;
    let mut cts = Vec::with_capacity(8);
    for i in 0..8 {
        let start = 2 + i * 4;
        let ax = parse_word_field::<Fb>(word(data, start)?)?;
        let ay = parse_word_field::<Fb>(word(data, start + 1)?)?;
        let bx = parse_word_field::<Fb>(word(data, start + 2)?)?;
        let by = parse_word_field::<Fb>(word(data, start + 3)?)?;
        let a = GA::new_unchecked(ax, ay).into_group();
        let b = GA::new_unchecked(bx, by).into_group();
        cts.push(Ct { a, b });
    }
    let proof_a = G1Affine::new_unchecked(
        parse_word_field::<Fq>(word(data, 34)?)?,
        parse_word_field::<Fq>(word(data, 35)?)?,
    );
    let bx_im = parse_word_field::<Fq>(word(data, 36)?)?;
    let bx_re = parse_word_field::<Fq>(word(data, 37)?)?;
    let by_im = parse_word_field::<Fq>(word(data, 38)?)?;
    let by_re = parse_word_field::<Fq>(word(data, 39)?)?;
    let proof_b = G2Affine::new_unchecked(Fq2::new(bx_re, bx_im), Fq2::new(by_re, by_im));
    let proof_c = G1Affine::new_unchecked(
        parse_word_field::<Fq>(word(data, 40)?)?,
        parse_word_field::<Fq>(word(data, 41)?)?,
    );
    Ok((
        index,
        Ballot {
            cts,
            nullifier,
            proof: Proof {
                a: proof_a,
                b: proof_b,
                c: proof_c,
            },
        },
    ))
}

/// Decode genuine EVM logs, replay them through the independent Rust ballot
/// verifier, and compare every event and ciphertext with the original run.
pub fn check_event_file(paths: &Paths, logs_path: &Path, contract: &str) -> Result<Value> {
    let setup: Setup = read_bin(&paths.public("setup.bin"))?;
    let expected_events: Vec<Event> = read_bin(&paths.public("ledger.bin"))?;
    let ballots: Vec<Ballot> = expected_events
        .iter()
        .filter_map(|event| match event {
            Event::Accepted { ballot, .. } => Some(ballot.clone()),
            _ => None,
        })
        .collect();

    let logs: Value = serde_json::from_slice(&std::fs::read(logs_path)?)?;
    let logs = logs
        .as_array()
        .ok_or_else(|| anyhow!("expected an array of RPC log objects"))?;
    let poll_registered_sig = "PollRegistered(uint64,uint256,uint256,uint256,uint64)";
    let accepted_sig =
        "BallotAccepted(uint64,uint64,uint256,uint256[32],uint256[2],uint256[2][2],uint256[2])";
    let sealed_sig = "PollSealed(uint64,uint64,bytes32)";
    let claim_sig = "DecisionClaimed(uint64,bytes32,bytes32,uint8)";
    let (mut registrations, mut sealed_count, mut claims) = (0usize, 0usize, 0usize);
    let mut events = Vec::new();
    for log in logs {
        let topics = log["topics"]
            .as_array()
            .ok_or_else(|| anyhow!("log missing topics"))?;
        let sig = topics
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("log missing topic0"))?;
        let data = parse_hex(
            log["data"]
                .as_str()
                .ok_or_else(|| anyhow!("log missing data"))?,
        )?;
        if event_topics(log, poll_registered_sig, setup.poll, contract)? {
            ensure!(data.len() == 4 * 32, "malformed PollRegistered frame");
            ensure!(
                parse_word_field::<Fb>(word(&data, 0)?)? == setup.root,
                "registered root mismatch"
            );
            let key = setup.pk.into_affine();
            ensure!(
                parse_word_field::<Fb>(word(&data, 1)?)? == key.x,
                "registered committee x mismatch"
            );
            ensure!(
                parse_word_field::<Fb>(word(&data, 2)?)? == key.y,
                "registered committee y mismatch"
            );
            ensure!(
                word_u64(word(&data, 3)?)? == setup.n as u64,
                "registered ballot count mismatch"
            );
            registrations += 1;
        } else if sig.eq_ignore_ascii_case(&format!("0x{}", hex::encode(topic_hash(accepted_sig))))
        {
            ensure!(
                event_topics(log, accepted_sig, setup.poll, contract)?,
                "bad accepted event topic"
            );
            let (index, ballot) = make_ballot(&data)?;
            ensure!(
                index as usize
                    == events
                        .iter()
                        .filter(|e| matches!(e, Event::Accepted { .. }))
                        .count(),
                "accepted event index mismatch"
            );
            events.push(Event::Accepted { index, ballot });
        } else if sig.eq_ignore_ascii_case(&format!("0x{}", hex::encode(topic_hash(sealed_sig)))) {
            ensure!(
                event_topics(log, sealed_sig, setup.poll, contract)?,
                "bad sealed event topic"
            );
            ensure!(data.len() == 2 * 32, "malformed PollSealed frame");
            let count = word_u64(word(&data, 0)?)?;
            let commitment: [u8; 32] = word(&data, 1)?;
            events.push(Event::Sealed { count, commitment });
            sealed_count += 1;
        } else if sig.eq_ignore_ascii_case(&format!("0x{}", hex::encode(topic_hash(claim_sig)))) {
            ensure!(
                event_topics(log, claim_sig, setup.poll, contract)?,
                "bad claim event topic"
            );
            ensure!(data.len() == 3 * 32, "malformed DecisionClaimed frame");
            let commitment = word(&data, 0)?;
            let transcript_hash = word(&data, 1)?;
            let decision = word_u64(word(&data, 2)?)?;
            ensure!(decision <= 1, "decision claim is not a bit");
            events.push(Event::Claim {
                commitment,
                transcript_hash,
                bit: decision == 1,
            });
            claims += 1;
        }
    }
    ensure!(
        registrations == 1,
        "expected one matching PollRegistered event"
    );
    ensure!(
        sealed_count == 1 && claims == 1,
        "missing or repeated seal/claim event"
    );
    ensure!(
        events
            .iter()
            .filter(|e| matches!(e, Event::Accepted { .. }))
            .count()
            == setup.n,
        "wrong accepted ballot count"
    );

    let pvk = ark_groth16::prepare_verifying_key(&setup.vk);
    let mut replay = Contract::new(&pvk, setup.root, setup.poll, setup.pk, setup.n);
    replay.replay(&events, true)?;
    ensure!(
        replay.accepted.len() == ballots.len(),
        "reconstructed board length mismatch"
    );
    for (actual, expected) in replay.accepted.iter().zip(&ballots) {
        ensure!(
            bincode::serialize(actual)? == bincode::serialize(expected)?,
            "on-chain ballot differs from Rust ballot"
        );
    }
    ensure!(
        bincode::serialize(&events)? == bincode::serialize(&expected_events)?,
        "EVM events differ from replayed Rust ledger"
    );
    let expected_seal = expected_events
        .iter()
        .find_map(|event| match event {
            Event::Sealed { commitment, .. } => Some(*commitment),
            _ => None,
        })
        .ok_or_else(|| anyhow!("original run has no sealed board"))?;
    ensure!(
        replay.sealed == Some(expected_seal),
        "EVM accepted-board commitment mismatch"
    );
    Ok(
        json!({"event_replay":"PASS","proofs_verified":replay.accepted.len(),"public_inputs_per_ballot":37,"ciphertexts_reconstructed":replay.accepted.iter().map(|b| b.cts.len()).sum::<usize>(),"sealed_commitment":hex::encode(expected_seal),"matches_original_run":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_event_parser_rejects_truncated_frames() {
        assert!(word(&[0u8; 31], 0).is_err());
        assert!(make_ballot(&[0u8; 42 * 32 - 1]).is_err());
    }

    #[test]
    fn public_event_parser_rejects_noncanonical_field_values() {
        let modulus = Fb::MODULUS.to_bytes_be();
        assert!(modulus.len() <= 32);
        let mut raw = [0u8; 32];
        raw[32 - modulus.len()..].copy_from_slice(&modulus);
        assert!(parse_word_field::<Fb>(raw).is_err());
    }

    #[test]
    fn public_event_parser_rejects_uint64_overflow() {
        let mut raw = [0u8; 32];
        raw[0] = 1;
        assert!(word_u64(raw).is_err());
    }
}
