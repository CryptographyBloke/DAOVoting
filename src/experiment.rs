//! Experiment pipeline: setup → ballot proving → admission → tally
//! (co-located or five trustee processes) → claim → independent public
//! verification (separate process) → isolated plaintext oracle.

use crate::ballot::{self, Ballot};
use crate::circuit::Circuit;
use crate::ledger::Contract;
use crate::net::{self, BoardStats, Session};
use crate::oracle;
use crate::setup::*;
use crate::tally::{Engine, Trustee};
use crate::transcript;
use anyhow::{Context, Result, anyhow, ensure};
use ed25519_dalek::SigningKey;
use rand::{Rng, rngs::OsRng};
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

/// Paper's hypothetical example weights for n = 8 (Sect. 3) with τ = 100.
pub const PAPER_WEIGHTS: [u64; 8] = [60, 45, 40, 30, 25, 20, 15, 10];

fn secs(t: Instant) -> f64 {
    t.elapsed().as_secs_f64()
}

/// Stage 1: dealer setup and reference string.
pub fn stage_setup(p: &Paths, n: usize, tau: Option<u64>, poll: u64) -> Result<Value> {
    p.create()?;
    let mut rng = OsRng;
    let weights: Vec<u64> = if n == 8 {
        PAPER_WEIGHTS.to_vec()
    } else {
        (0..n).map(|_| rng.gen_range(1..256)).collect()
    };
    let tau = tau.unwrap_or(if n == 8 {
        100
    } else {
        weights.iter().sum::<u64>() / 2
    });
    let votes: Vec<bool> = (0..n).map(|_| rng.r#gen()).collect();
    let t = Instant::now();
    let dummy_h = crate::group::g();
    let (pk, vk) = ballot::crs(dummy_h, &mut rng);
    let t_crs = secs(t);
    let t = Instant::now();
    let d = deal(&weights, &votes, tau, poll, 5, 4, vk, &mut rng);
    write_bin(&p.public("setup.bin"), &d.setup)?;
    for k in &d.trustees {
        write_bin(&p.private(&format!("trustee_{}.bin", k.id)), k)?;
    }
    write_bin(&p.private("voters.bin"), &d.voters)?;
    write_pk(&p.work("ballot_pk.bin"), &pk)?;
    Ok(
        json!({"seconds_crs": t_crs, "seconds_deal": secs(t), "tau": tau, "weights_public": weights}),
    )
}

/// Stage 2: every voter proves `R_ballot` (parallel across voters).
pub fn stage_vote(p: &Paths) -> Result<Value> {
    ensure!(
        !p.work("ballots.bin").exists(),
        "refusing to overwrite {}",
        p.work("ballots.bin").display()
    );
    let setup: Setup = read_bin(&p.public("setup.bin"))?;
    let voters: Vec<VoterRecord> = read_bin(&p.private("voters.bin"))?;
    let pk = read_pk(&p.work("ballot_pk.bin"))?;
    let key = crate::group::Key::new(setup.pk);
    let reg = registry(&setup);
    let t = Instant::now();
    let ballots: Vec<Ballot> = voters
        .par_iter()
        .map(|v| ballot::cast(&pk, &key, &reg, setup.poll, &v.voter(), v.vote, &mut OsRng))
        .collect();
    let s = secs(t);
    write_bin(&p.work("ballots.bin"), &ballots)?;
    Ok(json!({"seconds_proving": s, "seconds_per_ballot": s / ballots.len() as f64}))
}

/// Stage 3: admission contract (Groth16 verification, nullifiers, sealing).
pub fn stage_admit(p: &Paths) -> Result<Value> {
    ensure!(
        !p.public("ledger.bin").exists(),
        "refusing to overwrite {}",
        p.public("ledger.bin").display()
    );
    let setup: Setup = read_bin(&p.public("setup.bin"))?;
    let ballots: Vec<Ballot> = read_bin(&p.work("ballots.bin"))?;
    let pvk = ark_groth16::prepare_verifying_key(&setup.vk);
    let t = Instant::now();
    let mut c = Contract::new(&pvk, setup.root, setup.poll, setup.pk, setup.n);
    let res = c.submit_all(ballots.clone());
    let s = secs(t);
    for r in &res {
        r.as_ref().map_err(|e| anyhow!("ballot rejected: {e}"))?;
    }
    // a replayed ballot must be rejected (nullifier) after sealing as well
    ensure!(
        c.submit(ballots[0].clone()).is_err(),
        "duplicate ballot accepted"
    );
    ensure!(c.sealed.is_some(), "board not sealed");
    write_bin(&p.public("ledger.bin"), &c.events)?;
    Ok(
        json!({"seconds_admission": s, "accepted": c.accepted.len(), "sealed_commitment": hex::encode(c.sealed.unwrap())}),
    )
}

#[derive(Serialize, Default)]
pub struct TallyStats {
    pub mode: String,
    pub rtt_ms: u64,
    pub seconds_gates: f64,
    pub seconds_release: f64,
    pub seconds_tally: f64,
    pub messages: u64,
    pub items: u64,
    pub transcript_bytes: u64,
    pub decision: Option<bool>,
    pub board: Option<BoardStats>,
}

/// Stage 4a: co-located tally (one process, all five trustees, one verifying
/// replica), matching the paper's reported runs.
pub fn stage_tally_local(p: &Paths) -> Result<TallyStats> {
    let s = Session::load(p, false)?;
    let keys: Vec<TrusteeKey> = (0..s.setup.a)
        .map(|i| read_bin(&p.private(&format!("trustee_{i}.bin"))))
        .collect::<Result<_>>()?;
    let mut ts: Vec<Trustee> = keys
        .iter()
        .map(|k| Trustee::new(k.id, k.share, SigningKey::from_bytes(&k.signing)))
        .collect();
    let circ = Arc::new(s.circuit());
    let mut eng = Engine::new(Arc::new(s.public()?), circ.clone(), &s.inputs)?;
    let mut tw =
        transcript::Writer::create(&p.public("transcript.bin"), &s.setup.hash(), &s.board_hash)?;
    let t0 = Instant::now();
    let mut t_gates = None;
    while !eng.finished() {
        let mut progressed = false;
        for t in ts.iter_mut() {
            if let Some(m) = t.produce(&eng) {
                eng.process(&m, true)?;
                tw.append(&m)?;
                progressed = true;
                if t_gates.is_none() && eng.gates_done == circ.n_gates() {
                    t_gates = Some(secs(t0));
                }
            }
        }
        ensure!(progressed, "protocol stalled");
    }
    let total = secs(t0);
    let (messages, bytes, items) = (tw.msgs, tw.bytes, eng.n_items as u64);
    let h = tw.finish()?;
    let bit = eng.result.unwrap();
    net::publish_claim(p, &s, h, bit)?;
    let g = t_gates.unwrap_or(total);
    Ok(TallyStats {
        mode: "local".into(),
        seconds_gates: g,
        seconds_release: total - g,
        seconds_tally: total,
        messages,
        items,
        transcript_bytes: bytes,
        decision: Some(bit),
        ..Default::default()
    })
}

/// Stage 4b: five trustee processes + board (this process) over TCP.
pub fn stage_tally_dist(
    p: &Paths,
    rtt_ms: u64,
    threads_per_trustee: Option<usize>,
) -> Result<TallyStats> {
    let exe = std::env::current_exe()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    let a: usize = read_bin::<Setup>(&p.public("setup.bin"))?.a;
    let mut kids = Vec::new();
    for id in 0..a {
        let mut c = Command::new(&exe);
        c.args(["trustee", "--dir"]).arg(&p.root).args([
            "--id",
            &id.to_string(),
            "--addr",
            &addr,
            "--rtt-ms",
            &rtt_ms.to_string(),
        ]);
        if let Some(t) = threads_per_trustee {
            c.env("RAYON_NUM_THREADS", t.to_string());
        }
        kids.push(c.spawn().context("spawn trustee")?);
    }
    let b = net::run_board(p, listener, rtt_ms);
    for mut k in kids {
        let st = k.wait()?;
        ensure!(st.success() || b.is_err(), "trustee process failed: {st}");
    }
    let b = b?;
    Ok(TallyStats {
        mode: "dist".into(),
        rtt_ms,
        seconds_gates: b.seconds_gates,
        seconds_release: b.seconds_release,
        seconds_tally: b.seconds_total, // Start -> all trustees done; process start-up and connect: board.seconds_connect
        messages: b.messages,
        items: 0,
        transcript_bytes: b.transcript_bytes,
        decision: b.decision,
        board: Some(b),
    })
}

/// Stage 5: independent verifier in a separate process.
pub fn stage_verify(p: &Paths) -> Result<Value> {
    let t = Instant::now();
    let out = Command::new(std::env::current_exe()?)
        .args(["verify", "--dir"])
        .arg(&p.root)
        .output()?;
    let wall = secs(t);
    let rep: Value = serde_json::from_slice(&std::fs::read(p.public("verify.json"))?)?;
    ensure!(
        out.status.success(),
        "verifier rejected: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut rep = rep;
    rep["seconds_process_wall"] = json!(wall);
    Ok(rep)
}

/// Peak resident memory of the current process (Linux `VmHWM`, Windows peak
/// working set), in bytes.
pub fn peak_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        let l = s.lines().find(|l| l.starts_with("VmHWM:"))?;
        return l
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
            .map(|kb| kb * 1024);
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        #[derive(Default)]
        struct Pmc {
            cb: u32,
            faults: u32,
            peak_working_set: usize,
            rest: [usize; 7],
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> isize;
            fn K32GetProcessMemoryInfo(p: isize, c: *mut Pmc, cb: u32) -> i32;
        }
        let mut c = Pmc {
            cb: std::mem::size_of::<Pmc>() as u32,
            ..Default::default()
        };
        let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
        return (ok != 0).then_some(c.peak_working_set as u64);
    }
    #[allow(unreachable_code)]
    None
}

pub fn machine() -> Value {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        })
        .or_else(|| std::env::var("PROCESSOR_IDENTIFIER").ok())
        .unwrap_or_else(|| "unknown".into());
    let mem = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.to_string()));
    let rustc = Command::new("rustc")
        .arg("-V")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let kernel = std::fs::read_to_string("/proc/version")
        .ok()
        .map(|s| s.trim().to_string());
    let lock = include_str!("../Cargo.lock");
    let cargo_lock_sha256 = hex::encode(Sha256::digest(lock.as_bytes()));
    let ver = |name: &str| {
        lock.split("[[package]]")
            .find(|b| b.contains(&format!("name = \"{name}\"\n")))
            .and_then(|b| {
                b.lines()
                    .find(|l| l.starts_with("version"))
                    .map(|l| l.split('"').nth(1).unwrap_or("").to_string())
            })
    };
    json!({
        "cpu": cpu,
        "logical_cores": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "rayon_threads": rayon::current_num_threads(),
        "memory": mem,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "kernel": kernel,
        "rustc": rustc,
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "crates": {
            "ark-groth16": ver("ark-groth16"), "ark-ed-on-bn254": ver("ark-ed-on-bn254"), "ark-bn254": ver("ark-bn254"),
            "ark-r1cs-std": ver("ark-r1cs-std"), "ark-crypto-primitives": ver("ark-crypto-primitives"),
            "ed25519-dalek": ver("ed25519-dalek"), "tokio": ver("tokio"), "rayon": ver("rayon"), "sha2": ver("sha2"), "sha3": ver("sha3"),
        },
        "cargo_lock_sha256": cargo_lock_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_reports_standard_cargo_lock_sha256() {
        let expected = hex::encode(Sha256::digest(include_bytes!("../Cargo.lock")));
        assert_eq!(
            machine()["cargo_lock_sha256"].as_str(),
            Some(expected.as_str())
        );
    }
}

fn file_hashes(dir: &Path) -> Result<Value> {
    let mut m = serde_json::Map::new();
    let mut names: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    names.sort();
    for f in names {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        if name == "manifest.json" {
            continue;
        }
        let b = std::fs::read(&f)?;
        m.insert(name, json!({"bytes": b.len(), "sha256": hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&b))}));
    }
    Ok(Value::Object(m))
}

fn copy_base(base: &Paths, dst: &Paths) -> Result<()> {
    dst.create()?;
    for f in ["setup.bin", "ledger.bin"] {
        std::fs::copy(base.public(f), dst.public(f))?;
    }
    for e in std::fs::read_dir(base.root.join("private"))? {
        let e = e?;
        std::fs::copy(e.path(), dst.private(&e.file_name().to_string_lossy()))?;
    }
    Ok(())
}

pub struct Plan {
    pub n: usize,
    pub tau: Option<u64>,
    pub variants: Vec<(String, u64)>,
    pub reps: usize,
    pub out: PathBuf,
    pub threads_per_trustee: Option<usize>,
}

/// Runs `reps` fresh elections (setup, ballots) and, on each sealed board,
/// every tally variant (`local`, or `dist` with an injected RTT); each variant
/// is verified independently and checked against the oracle.
pub fn run(plan: &Plan) -> Result<Value> {
    let circ = Circuit::build(plan.n, ballot::L_VOTE, 0);
    let (df_depth, df_width) = circ.dataflow_shape();
    let shape = json!({
        "gates": circ.n_gates(), "paper_gate_formula": Circuit::paper_gate_count(plan.n, ballot::L_VOTE),
        "aggregate_gates": circ.n_gates() - (2 * circ.l_agg - 1), "compare_gates": 2 * circ.l_agg - 1,
        "l_vote": circ.l_vote, "l_agg": circ.l_agg,
        "paper_schedule_depth": circ.paper_schedule_depth(), "dataflow_depth": df_depth, "dataflow_max_width": df_width,
        "ballot_constraints": ballot::constraint_count(crate::group::g()).0,
    });
    let mut runs = Vec::new();
    for rep in 0..plan.reps {
        let base = Paths::new(
            plan.out
                .join(format!("n{}", plan.n))
                .join(format!("rep{rep}"))
                .join("base"),
        );
        eprintln!("[n={} rep={rep}] setup", plan.n);
        let poll = 900_000 + rep as u64;
        let s_setup = stage_setup(&base, plan.n, plan.tau, poll)?;
        eprintln!("[n={} rep={rep}] proving {} ballots", plan.n, plan.n);
        let s_vote = stage_vote(&base)?;
        let s_admit = stage_admit(&base)?;
        eprintln!("[n={} rep={rep}] admitted: {s_admit}", plan.n);
        for (mode, rtt) in &plan.variants {
            let name = if mode == "local" {
                "local".to_string()
            } else {
                format!("dist-rtt{rtt}")
            };
            let v = Paths::new(base.root.parent().unwrap().join(&name));
            copy_base(&base, &v)?;
            eprintln!("[n={} rep={rep}] tally {name}", plan.n);
            let tally = if mode == "local" {
                stage_tally_local(&v)?
            } else {
                stage_tally_dist(&v, *rtt, plan.threads_per_trustee)?
            };
            eprintln!(
                "[n={} rep={rep}] {name}: tally {:.2}s; verifying",
                plan.n, tally.seconds_tally
            );
            let ver = stage_verify(&v)?;
            let o = oracle::evaluate(&v)?;
            let accept = ver["accept"].as_bool() == Some(true);
            let agrees = ver["decision"].as_bool() == Some(o.bit) && tally.decision == Some(o.bit);
            ensure!(accept, "verifier rejected {}", v.root.display());
            ensure!(agrees, "decision disagrees with the plaintext oracle");
            let setup: Setup = read_bin(&v.public("setup.bin"))?;
            let manifest = json!({
                "protocol": PROTOCOL, "n": plan.n, "rep": rep, "variant": name, "mode": mode, "rtt_ms": rtt,
                "params": {"a": setup.a, "t": setup.t, "q_dec": setup.t + 1, "tau": setup.tau, "poll": setup.poll, "l_vote": setup.l_vote, "weights": setup.weights},
                "circuit": shape, "machine": machine(),
                "setup": s_setup, "voting": s_vote, "admission": s_admit, "tally": tally, "verification": ver,
                "decision": tally.decision, "oracle_agrees": agrees,
                "runner_peak_rss_bytes": peak_rss_bytes(),
                "public_files": file_hashes(&v.root.join("public"))?,
            });
            write_json(&v.public("manifest.json"), &manifest)?;
            runs.push(manifest);
        }
        let _ = std::fs::remove_file(base.work("ballot_pk.bin"));
    }
    Ok(json!({"n": plan.n, "circuit": shape, "runs": runs}))
}

/// Median / min / max helper for summaries.
pub fn stats(mut v: Vec<f64>) -> Value {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() {
        return Value::Null;
    }
    let med = if v.len() % 2 == 1 {
        v[v.len() / 2]
    } else {
        (v[v.len() / 2 - 1] + v[v.len() / 2]) / 2.0
    };
    json!({"median": med, "min": v[0], "max": v[v.len() - 1], "runs": v.len()})
}
