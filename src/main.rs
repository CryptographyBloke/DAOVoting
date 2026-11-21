//! `wod` — command-line entry point. Run `wod help`.

use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Value, json};
use std::path::PathBuf;
use wod::experiment::{self, Plan};
use wod::setup::{Paths, write_json};
use wod::{bench, evm, net, oracle, verify};

const HELP: &str = "wod — verifiable winner-only weighted voting (Li-Li / CGY)

Pipeline (one poll in DIR):
  wod setup   --dir DIR --n N [--tau T] [--poll P]   test-only dealer + Groth16 CRS
  wod vote    --dir DIR                              prove all ballots
  wod admit   --dir DIR                              admission contract, seal board
  wod tally   --dir DIR                              co-located tally (5 trustees, 1 process)
  wod board   --dir DIR --addr HOST:PORT [--rtt-ms R]   public coordinator (TCP board)
  wod trustee --dir DIR --id I --addr HOST:PORT [--rtt-ms R]   one trustee process
  wod verify  --dir DIR                              independent public verifier
  wod oracle  --dir DIR                              plaintext oracle (testing only)
  wod evm-export --dir DIR --out FILE                export public Arkworks proofs for the EVM
  wod evm-check-events --dir DIR --logs FILE --contract ADDRESS  verify EVM events with Rust

Experiments:
  wod gate       [--reps 20] [--out results]         single conditional gate
  wod bench      [--iters 200] [--groth-iters 5] [--out results]
  wod experiment --n 8[,64,...] [--modes local,dist] [--rtt-ms 0[,20,...]]
                 [--reps 3] [--tau T] [--threads-per-trustee K] [--out results]
";

struct Args(Vec<String>);

impl Args {
    fn get(&self, k: &str) -> Option<String> {
        self.0
            .iter()
            .position(|a| a == k)
            .and_then(|i| self.0.get(i + 1).cloned())
    }
    fn req(&self, k: &str) -> Result<String> {
        self.get(k).ok_or_else(|| anyhow!("missing {k}"))
    }
    fn num<T: std::str::FromStr>(&self, k: &str, d: T) -> Result<T> {
        match self.get(k) {
            Some(v) => v.parse().map_err(|_| anyhow!("bad value for {k}")),
            None => Ok(d),
        }
    }
    fn list(&self, k: &str, d: &str) -> Vec<String> {
        self.get(k)
            .unwrap_or_else(|| d.to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
    fn dir(&self) -> Result<Paths> {
        Ok(Paths::new(self.req("--dir")?))
    }
}

fn print(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = argv.first().cloned().unwrap_or_else(|| "help".into());
    let a = Args(argv);
    match cmd.as_str() {
        "setup" => print(&experiment::stage_setup(
            &a.dir()?,
            a.num("--n", 8)?,
            a.get("--tau").map(|t| t.parse()).transpose()?,
            a.num("--poll", 910004)?,
        )?),
        "vote" => print(&experiment::stage_vote(&a.dir()?)?),
        "admit" => print(&experiment::stage_admit(&a.dir()?)?),
        "tally" => print(&serde_json::to_value(experiment::stage_tally_local(
            &a.dir()?,
        )?)?),
        "board" => {
            let l = std::net::TcpListener::bind(a.req("--addr")?)?;
            print(&serde_json::to_value(net::run_board(
                &a.dir()?,
                l,
                a.num("--rtt-ms", 0)?,
            )?)?)
        }
        "trustee" => {
            let st = net::run_trustee(
                &a.dir()?,
                a.num("--id", 0)?,
                &a.req("--addr")?,
                a.num("--rtt-ms", 0)?,
            )?;
            eprintln!("trustee {} done: {}", st.id, serde_json::to_string(&st)?);
        }
        "verify" => {
            let r = verify::verify_dir(&a.dir()?);
            print(&serde_json::to_value(&r)?);
            if !r.accept {
                bail!("REJECT");
            }
        }
        "oracle" => {
            let o = oracle::evaluate(&a.dir()?)?;
            println!("oracle bit = {} (W written to private/oracle.json)", o.bit);
        }
        "gate" => gate(&a)?,
        "bench" => {
            let v = bench::run(a.num("--iters", 200)?, a.num("--groth-iters", 5)?);
            let out = PathBuf::from(a.get("--out").unwrap_or_else(|| "results".into()));
            ensure!(
                !out.join("bench.json").exists(),
                "refusing to overwrite {}",
                out.join("bench.json").display()
            );
            std::fs::create_dir_all(&out)?;
            let v = json!({"machine": experiment::machine(), "bench": v});
            write_json(&out.join("bench.json"), &v)?;
            print(&v["bench"]["sizes"]);
        }
        "evm-export" => print(&evm::export_run(
            &a.dir()?,
            &PathBuf::from(a.req("--out")?),
        )?),
        "evm-check-events" => print(&evm::check_event_file(
            &a.dir()?,
            &PathBuf::from(a.req("--logs")?),
            &a.req("--contract")?,
        )?),
        "experiment" => run_experiments(&a)?,
        _ => print!("{HELP}"),
    }
    Ok(())
}

/// Single conditional gate: real five-trustee CGY gate, independent replay,
/// and a check against the dealer key (test only) for random bit inputs.
fn gate(a: &Args) -> Result<()> {
    use std::sync::Arc;
    use std::time::Instant;
    use wod::circuit::Circuit;
    use wod::group::*;
    use wod::tally::{Engine, Public, Trustee, run_local};
    let reps: usize = a.num("--reps", 20)?;
    let mut rng = rand::rngs::OsRng;
    let mut t_run = Vec::new();
    let mut t_ver = Vec::new();
    let mut bytes = 0;
    for _ in 0..reps {
        let (sk, shares) = wod::shamir::deal(4, 5, &mut rng);
        let sks: Vec<ed25519_dalek::SigningKey> = (0..5)
            .map(|_| ed25519_dalek::SigningKey::generate(&mut rng))
            .collect();
        let pp = Arc::new(Public::new(
            g() * sk,
            shares.iter().map(|s| g() * s).collect(),
            sks.iter().map(|k| k.verifying_key()).collect(),
            rand::random(),
        ));
        let mut ts: Vec<Trustee> = shares
            .into_iter()
            .zip(sks)
            .enumerate()
            .map(|(i, (s, k))| Trustee::new(i, s, k))
            .collect();
        let (x, y): (u64, u64) = (rand::random::<bool>() as u64, rand::random::<bool>() as u64);
        let ins = [
            pp.key.enc(&F::from(x), &rand_scalar(&mut rng)),
            pp.key.enc(&F::from(y), &rand_scalar(&mut rng)),
        ];
        let circ = Arc::new(Circuit::single_gate());
        let mut e = Engine::new(pp.clone(), circ.clone(), &ins)?;
        let t = Instant::now();
        let log = run_local(&mut e, &mut ts, true)?;
        t_run.push(t.elapsed().as_secs_f64() * 1e3);
        let t = Instant::now();
        let mut v = Engine::new(pp, circ, &ins)?;
        for m in &log {
            v.process(m, true)?;
        }
        t_ver.push(t.elapsed().as_secs_f64() * 1e3);
        anyhow::ensure!(
            v.output_ct() == e.output_ct() && v.result == Some(x * y == 1),
            "replay mismatch"
        );
        anyhow::ensure!(
            decrypt_small(&sk, &e.output_ct().unwrap(), 2) == Some((x * y) as i64),
            "wrong product"
        );
        bytes = log
            .iter()
            .map(|m| bincode::serialize(m).unwrap().len())
            .sum();
    }
    let v = json!({
        "experiment": "single CGY conditional gate (gate + release of its output), 5 trustees, q_dec = 5",
        "reps": reps, "all_correct_and_verified": true,
        "ms_protocol": experiment::stats(t_run), "ms_independent_replay": experiment::stats(t_ver),
        "transcript_bytes": bytes, "machine": experiment::machine(),
    });
    let out = PathBuf::from(a.get("--out").unwrap_or_else(|| "results".into()));
    ensure!(
        !out.join("gate.json").exists(),
        "refusing to overwrite {}",
        out.join("gate.json").display()
    );
    std::fs::create_dir_all(&out)?;
    write_json(&out.join("gate.json"), &v)?;
    print(&v);
    Ok(())
}

fn run_experiments(a: &Args) -> Result<()> {
    let out = PathBuf::from(a.get("--out").unwrap_or_else(|| "results".into()));
    ensure!(
        !out.exists(),
        "refusing to reuse experiment output path {}; choose a new --out directory",
        out.display()
    );
    let reps: usize = a.num("--reps", 3)?;
    let tau = a.get("--tau").map(|t| t.parse()).transpose()?;
    let tpt = a
        .get("--threads-per-trustee")
        .map(|t| t.parse())
        .transpose()?;
    let mut variants = Vec::new();
    for m in a.list("--modes", "local,dist") {
        match m.as_str() {
            "local" => variants.push(("local".to_string(), 0)),
            "dist" => {
                for r in a.list("--rtt-ms", "0") {
                    variants.push(("dist".to_string(), r.parse()?));
                }
            }
            _ => bail!("unknown mode {m}"),
        }
    }
    let mut all = Vec::new();
    for n in a.list("--n", "8") {
        let n: usize = n.parse()?;
        let plan = Plan {
            n,
            tau,
            variants: variants.clone(),
            reps,
            out: out.clone(),
            threads_per_trustee: tpt,
        };
        let r = experiment::run(&plan)?;
        write_json(&out.join(format!("n{n}")).join("results.json"), &r)?;
        all.push(r);
    }
    let summary = summarize(&all);
    write_json(&out.join("summary.json"), &summary)?;
    std::fs::write(out.join("summary.md"), summary_md(&summary))?;
    println!("{}", summary_md(&summary));
    Ok(())
}

fn summarize(all: &[Value]) -> Value {
    let f = |r: &Value, p: &[&str]| -> Option<f64> {
        let mut v = r;
        for k in p {
            v = v.get(*k)?;
        }
        v.as_f64()
    };
    let mut rows = Vec::new();
    for res in all {
        let runs = res["runs"].as_array().cloned().unwrap_or_default();
        let mut names: Vec<String> = runs
            .iter()
            .map(|r| r["variant"].as_str().unwrap().to_string())
            .collect();
        names.dedup();
        names.sort();
        names.dedup();
        for name in names {
            let rs: Vec<&Value> = runs
                .iter()
                .filter(|r| r["variant"] == json!(name))
                .collect();
            let col = |p: &[&str]| experiment::stats(rs.iter().filter_map(|r| f(r, p)).collect());
            rows.push(json!({
                "n": res["n"], "variant": name, "circuit": res["circuit"],
                "proving_s": col(&["voting", "seconds_proving"]),
                "admission_s": col(&["admission", "seconds_admission"]),
                "gates_s": col(&["tally", "seconds_gates"]),
                "release_s": col(&["tally", "seconds_release"]),
                "tally_s": col(&["tally", "seconds_tally"]),
                "verify_s": col(&["verification", "seconds_total"]),
                "verify_chain_s": col(&["verification", "seconds_chain"]),
                "verify_backend_s": col(&["verification", "seconds_backend"]),
                "messages": col(&["tally", "messages"]),
                "transcript_bytes": col(&["tally", "transcript_bytes"]),
                "relayed_bytes": col(&["tally", "board", "bytes_relayed"]),
                "all_accepted": rs.iter().all(|r| r["verification"]["accept"] == json!(true)),
                "all_oracle_agree": rs.iter().all(|r| r["oracle_agrees"] == json!(true)),
                "decisions": rs.iter().map(|r| r["decision"].clone()).collect::<Vec<_>>(),
            }));
        }
    }
    json!({"machine": experiment::machine(), "rows": rows})
}

fn summary_md(s: &Value) -> String {
    let m = |v: &Value| {
        v["median"]
            .as_f64()
            .map(|x| format!("{x:.2}"))
            .unwrap_or("-".into())
    };
    let r = |v: &Value| match (v["min"].as_f64(), v["max"].as_f64()) {
        (Some(a), Some(b)) => format!("{a:.2}–{b:.2}"),
        _ => "-".into(),
    };
    let mut o = String::from(
        "| n | variant | gates | depth (paper/dataflow) | proving s | admission s | gates s | release s | tally s (range) | verify s | msgs | transcript MB | accept | oracle |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for row in s["rows"].as_array().unwrap() {
        let c = &row["circuit"];
        o += &format!(
            "| {} | {} | {} | {}/{} | {} | {} | {} | {} | {} ({}) | {} | {} | {:.2} | {} | {} |\n",
            row["n"],
            row["variant"].as_str().unwrap(),
            c["gates"],
            c["paper_schedule_depth"],
            c["dataflow_depth"],
            m(&row["proving_s"]),
            m(&row["admission_s"]),
            m(&row["gates_s"]),
            m(&row["release_s"]),
            m(&row["tally_s"]),
            r(&row["tally_s"]),
            m(&row["verify_s"]),
            m(&row["messages"]),
            row["transcript_bytes"]["median"].as_f64().unwrap_or(0.0) / 1e6,
            row["all_accepted"],
            row["all_oracle_agree"],
        );
    }
    o
}
