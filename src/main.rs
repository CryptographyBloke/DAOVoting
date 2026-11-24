//! `wod` — command-line entry point. Run `wod help`.

use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Value, json};
use std::path::PathBuf;
use wod::circuit::Scheduler;
use wod::experiment::{self, Plan};
use wod::setup::{Paths, write_json};
use wod::{bench, evm, net, oracle, verify};

const HELP: &str = "wod — verifiable winner-only weighted voting (Li-Li / CGY)

Pipeline (one poll in DIR):
  wod setup   --dir DIR --n N [--tau T] [--poll P]   test-only dealer + Groth16 CRS
  wod vote    --dir DIR                              prove all ballots
  wod admit   --dir DIR                              admission contract, seal board
  wod tally   --dir DIR [--mode local|dist] [--scheduler dataflow|reference]
  wod board   --dir DIR --addr HOST:PORT [--rtt-ms R]   public coordinator (TCP board)
  wod trustee --dir DIR --id I --addr HOST:PORT [--rtt-ms R]   one trustee process
  wod verify  --dir DIR                              independent public verifier
  wod oracle  --dir DIR                              plaintext oracle (testing only)
  wod export-node --dir DIR --out DIR [--id I]        isolated board/trustee provisioning
  wod evm-export --dir DIR --out FILE                export public Arkworks proofs for the EVM
  wod evm-check-events --dir DIR --logs FILE --contract ADDRESS  verify EVM events with Rust
  wod evm-verify-chain --dir DIR --receipts FILE --contract ADDRESS --chain-id ID
                      --setup-hash HASH --source-commit SHA   full receipt-derived public replay

Experiments:
  wod gate       [--reps 20] [--out results]         single conditional gate
  wod bench      [--iters 200] [--groth-iters 5] [--out results]
  wod experiment --n 8[,64,...] [--modes local,dist] [--rtt-ms 0[,20,...]]
                 [--reps 3] [--tau T] [--threads-per-trustee K] [--out results]
                 [--scheduler dataflow|reference|both] [--order-offset K] [--machine-json FILE]
                 reference/both require --modes local; both alternates paired order

GPU research (T005; see reports/T005.md):
  --format v1|v2|v3|v4    transcript format for new runs (v2 = historical lifts,
                          commitment-form proofs, pre-weighted shares; the verifier
                          reads the format from the transcript header)
                          v3 = secure randomized lifts; v4 = validated affine wire points
  --lift-policy canonical|randomized   v3/v4 honest producer policy (default randomized)
  --v2-verify batch|individual   v2 verification: one MSM per message (default) or per relation
  --v2-coeff random|fs    v2 batch coefficients: verifier randomness (default) or
                          derived from the message (reproducible)
  --verify-backend SPEC   on any command: verify trustee messages in message-level
                          batches on cpu | cuda[:DEV] | cuda-msm[:DEV] | auto:MIN_BATCH[:DEV] | auto-msm:N[:DEV] | cert:SPEC | emu
                          (default: original inline verification)
  wod profile    [--n 8,64,256,1024] [--groth-reps 5] [--out DIR]   CPU hotspot profile
  wod gpu-check  [--arch compute_89] [--device 0]    build features, NVRTC compile, device info,
                                                     vectors on the device
  wod gpu-bench  --backend SPEC [--sizes 1,16,...] [--reps 5] [--n 8,64] [--out DIR]
                                                     batch sweep + end-to-end CPU vs SPEC
  wod gpu-vectors --check FILE --backend SPEC | --write FILE   deterministic [k]P vectors
  wod msm-vectors --check FILE --backend SPEC | --write FILE   T007 MSM and lift vectors
  wod format-bench [--n 8,64,256] [--reps 3] [--out DIR]   T007: v1 vs v2 verification, paired
  wod proof-sweep  [--sizes 1,...,4096] [--reps 5] [--out DIR]  T007: CSZ verification per batch size
  wod secure-bench [--n 8,64] [--reps 3] [--configs LIST] [--out DIR]  T008 paired engine comparison
  wod mixed-proof-sweep [--sizes 1,4,...,16384] [--reps 3] [--backends cpu,cuda-msm] [--out DIR]
  wod msm-sweep [--sizes 1,4,...,81920] [--reps 3] [--backends cpu,cuda,cuda-msm] [--out DIR]
  wod codec-bench [--points 81920] [--reps 3] [--out DIR]  validated compressed/affine comparison
  wod gpu-summary --dir DIR                           summary.md for a reproduce_gpu.ps1 run
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
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    // global option, accepted before or after the command
    let mut take = |flag: &str| {
        argv.iter().position(|x| x == flag).map(|i| {
            let v = argv.get(i + 1).cloned().unwrap_or_default();
            argv.drain(i..(i + 2).min(argv.len()));
            v
        })
    };
    let backend = take("--verify-backend");
    // T007 global options, exported so board/trustee/verifier subprocesses inherit them
    for (flag, var, ok) in [
        ("--format", "WOD_FORMAT", &["v1", "v2", "v3", "v4"][..]),
        (
            "--lift-policy",
            "WOD_LIFT_POLICY",
            &["canonical", "randomized"][..],
        ),
        ("--v2-verify", "WOD_V2_VERIFY", &["batch", "individual"][..]),
        ("--v2-coeff", "WOD_V2_COEFF", &["random", "fs"][..]),
    ] {
        if let Some(v) = take(flag) {
            ensure!(ok.contains(&v.as_str()), "{flag} must be one of {ok:?}");
            unsafe { std::env::set_var(var, &v) };
        }
    }
    let cmd = argv.first().cloned().unwrap_or_else(|| "help".into());
    let a = Args(argv);
    if let Some(spec) = backend {
        // validated here; exported so trustee/verifier subprocesses inherit it
        if spec != "inline" {
            wod::batch::backend(&spec)?;
        }
        unsafe { std::env::set_var("WOD_VERIFY_BACKEND", &spec) };
    }
    ensure!(
        a.get("--scheduler").is_none() || matches!(cmd.as_str(), "tally" | "experiment"),
        "--scheduler is supported by tally and experiment only; TCP commands retain dataflow"
    );
    match cmd.as_str() {
        "setup" => print(&experiment::stage_setup(
            &a.dir()?,
            a.num("--n", 8)?,
            a.get("--tau").map(|t| t.parse()).transpose()?,
            a.num("--poll", 910004)?,
        )?),
        "vote" => print(&experiment::stage_vote(&a.dir()?)?),
        "admit" => print(&experiment::stage_admit(&a.dir()?)?),
        "tally" => {
            let scheduler = a
                .get("--scheduler")
                .unwrap_or_else(|| "dataflow".into())
                .parse::<Scheduler>()
                .map_err(anyhow::Error::msg)?;
            let stats = match a.get("--mode").as_deref().unwrap_or("local") {
                "local" => experiment::stage_tally_local(&a.dir()?, scheduler)?,
                "dist" => {
                    ensure!(
                        scheduler == Scheduler::Dataflow,
                        "TCP mode requires dataflow"
                    );
                    experiment::stage_tally_dist(
                        &a.dir()?,
                        a.num("--rtt-ms", 0)?,
                        Some(a.num("--threads-per-trustee", 4)?),
                    )?
                }
                mode => anyhow::bail!("unknown tally mode {mode}"),
            };
            print(&serde_json::to_value(stats)?);
        }
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
            print(&serde_json::to_value(&st)?);
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
        "export-node" => print(&wod::setup::export_node(
            &a.dir()?,
            &Paths::new(a.req("--out")?),
            a.get("--id").map(|v| v.parse()).transpose()?,
        )?),
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
        "evm-verify-chain" => print(&evm::verify_chain_receipts(
            &a.dir()?,
            &PathBuf::from(a.req("--receipts")?),
            &a.req("--contract")?,
            a.num("--chain-id", 421614)?,
            &a.req("--setup-hash")?,
            &a.req("--source-commit")?,
        )?),
        "experiment" => run_experiments(&a)?,
        "profile" => {
            let out = fresh_out(&a, "profile.json")?;
            let ns: Vec<usize> = a
                .list("--n", "8,64,256,1024")
                .iter()
                .map(|n| n.parse())
                .collect::<Result<_, _>>()?;
            let v = bench::profile(&ns, a.num("--groth-reps", 5)?);
            write_json(
                &out,
                &json!({"machine": experiment::machine(), "provenance": bench::provenance(), "profile": v}),
            )?;
            println!("wrote {}", out.display());
        }
        "gpu-check" => print(&bench::gpu_check(
            a.get("--arch"),
            a.num("--device", 0usize)?,
        )),
        "gpu-bench" => {
            let out = fresh_out(&a, "gpu_bench.json")?;
            let target = wod::batch::backend(&a.req("--backend")?)?;
            let sizes: Vec<usize> = a
                .list("--sizes", "1,4,16,64,256,1024,4096,16384,65536")
                .iter()
                .map(|n| n.parse())
                .collect::<Result<_, _>>()?;
            let ns: Vec<usize> = a
                .list("--n", "8,64")
                .iter()
                .map(|n| n.parse())
                .collect::<Result<_, _>>()?;
            let v = bench::gpu_bench(target.clone(), &sizes, a.num("--reps", 5)?, &ns);
            let dev = bench::device_times(&target);
            write_json(
                &out,
                &json!({"machine": experiment::machine(), "provenance": bench::provenance(), "device_times": dev, "gpu_bench": v}),
            )?;
            println!("wrote {}", out.display());
        }
        "format-bench" => {
            let out = fresh_out(&a, "format_bench.json")?;
            let ns: Vec<usize> = a
                .list("--n", "8,64,256")
                .iter()
                .map(|n| n.parse())
                .collect::<Result<_, _>>()?;
            let v = bench::format_bench(&ns, a.num("--reps", 3)?);
            write_json(
                &out,
                &json!({"machine": experiment::machine(), "provenance": bench::provenance(), "format_bench": v}),
            )?;
            println!("wrote {}", out.display());
        }
        "secure-bench" => {
            let out = fresh_out(&a, "secure_bench.json")?;
            let ns = a
                .list("--n", "8,64")
                .iter()
                .map(|n| n.parse())
                .collect::<Result<Vec<usize>, _>>()?;
            let names = a.list("--configs", "v1-inline,v1-cpu,v1-gpu,v1-certified,v2-individual,v2-cpu,v2-gpu,v3-canonical,v3-cpu,v3-gpu-msm,v4-cpu,v4-gpu-msm");
            let v = bench::secure_bench(&ns, a.num("--reps", 3)?, &names);
            write_json(
                &out,
                &json!({"machine":experiment::machine(),"provenance":bench::provenance(),"secure_bench":v}),
            )?;
            println!("wrote {}", out.display());
        }
        "mixed-proof-sweep" | "msm-sweep" => {
            let out = fresh_out(
                &a,
                if cmd == "msm-sweep" {
                    "msm_sweep.json"
                } else {
                    "mixed_proof_sweep.json"
                },
            )?;
            let sizes = a
                .list("--sizes", "1,4,16,64,256,1024,4096,16384")
                .iter()
                .map(|n| n.parse())
                .collect::<Result<Vec<usize>, _>>()?;
            let specs = a.list("--backends", "cpu");
            let v = if cmd == "msm-sweep" {
                bench::msm_sweep(&sizes, a.num("--reps", 3)?, &specs)
            } else {
                bench::mixed_proof_sweep(&sizes, a.num("--reps", 3)?, &specs)
            };
            write_json(
                &out,
                &json!({"machine":experiment::machine(),"provenance":bench::provenance(),"results":v}),
            )?;
            println!("wrote {}", out.display());
        }
        "codec-bench" => {
            let out = fresh_out(&a, "codec_bench.json")?;
            let v = bench::codec_bench(a.num("--points", 81920)?, a.num("--reps", 3)?);
            write_json(
                &out,
                &json!({"machine":experiment::machine(),"provenance":bench::provenance(),"codec":v}),
            )?;
            println!("wrote {}", out.display());
        }
        "proof-sweep" => {
            let out = fresh_out(&a, "proof_sweep.json")?;
            let sizes: Vec<usize> = a
                .list("--sizes", "1,4,16,64,256,1024,4096")
                .iter()
                .map(|n| n.parse())
                .collect::<Result<_, _>>()?;
            let v = bench::proof_sweep(&sizes, a.num("--reps", 5)?);
            write_json(
                &out,
                &json!({"machine": experiment::machine(), "provenance": bench::provenance(), "proof_sweep": v}),
            )?;
            println!("wrote {}", out.display());
        }
        "msm-vectors" => {
            if let Some(f) = a.get("--write") {
                let v = if a.get("--suite").as_deref() == Some("secure-lifts") {
                    wod::gpu::make_secure_lift_vectors()
                } else {
                    wod::gpu::make_msm_vectors(20261124)
                };
                std::fs::write(&f, serde_json::to_string_pretty(&v)? + "\n")?;
                println!("wrote {} MSM/lift vectors to {f}", v.len());
            } else {
                let f = a.req("--check")?;
                let v: Vec<wod::gpu::MsmVector> = serde_json::from_slice(&std::fs::read(&f)?)?;
                let b = wod::batch::backend(&a.req("--backend")?)?;
                let bad = wod::gpu::check_msm_vectors(&*b, &v)?;
                println!(
                    "{}: {} vectors, {} mismatches on {}",
                    f,
                    v.len(),
                    bad.len(),
                    b.name()
                );
                ensure!(bad.is_empty(), "MSM vector check failed: {bad:?}");
            }
        }
        "gpu-summary" => print!("{}", bench::gpu_summary(&PathBuf::from(a.req("--dir")?))?),
        "gpu-vectors" => {
            if let Some(f) = a.get("--write") {
                let v = wod::gpu::make_vectors(20261123, 64);
                std::fs::write(&f, serde_json::to_string_pretty(&v)? + "\n")?;
                println!("wrote {} vectors to {f}", v.len());
            } else {
                let f = a.req("--check")?;
                let v: Vec<wod::gpu::Vector> = serde_json::from_slice(&std::fs::read(&f)?)?;
                let b = wod::batch::backend(&a.req("--backend")?)?;
                let bad = wod::gpu::check_vectors(&*b, &v)?;
                println!(
                    "{}: {} vectors, {} mismatches on {}",
                    f,
                    v.len(),
                    bad.len(),
                    b.name()
                );
                for i in &bad {
                    println!("  mismatch #{i}: {}", v[*i].note);
                }
                ensure!(bad.is_empty(), "vector check failed");
            }
        }
        _ => print!("{HELP}"),
    }
    Ok(())
}

/// `--out DIR` (default `results/local/t005-<unix time>`) joined with `file`,
/// refusing to overwrite existing results.
fn fresh_out(a: &Args, file: &str) -> Result<PathBuf> {
    let dir = PathBuf::from(a.get("--out").unwrap_or_else(|| {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("results/local/t005-{t}")
    }));
    let out = dir.join(file);
    ensure!(!out.exists(), "refusing to overwrite {}", out.display());
    std::fs::create_dir_all(&dir)?;
    Ok(out)
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
    let selection = a.get("--scheduler").unwrap_or_else(|| "dataflow".into());
    let schedulers = if selection == "both" {
        vec![Scheduler::Reference, Scheduler::Dataflow]
    } else {
        vec![selection.parse::<Scheduler>().map_err(anyhow::Error::msg)?]
    };
    let host = a
        .get("--machine-json")
        .map(|path| -> Result<Value> { Ok(serde_json::from_slice(&std::fs::read(path)?)?) })
        .transpose()?;
    for (index, n) in a.list("--n", "8").into_iter().enumerate() {
        let n: usize = n.parse()?;
        let plan = Plan {
            n,
            tau,
            variants: variants.clone(),
            reps,
            out: out.clone(),
            threads_per_trustee: tpt,
            schedulers: schedulers.clone(),
            order_offset: a.num("--order-offset", 0usize)? + index * reps,
            host: host.clone(),
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
                "scheduler": rs[0]["scheduler"],
                "scheduler_depth": rs[0]["tally"]["scheduler_depth"],
                "scheduler_max_width": rs[0]["tally"]["scheduler_max_width"],
                "gate_batches": col(&["tally", "gate_batches"]),
                "max_gate_batch": col(&["tally", "max_gate_batch"]),
                "items": col(&["tally", "items"]),
                "initialization_s": col(&["tally", "seconds_initialization"]),
                "finalize_transcript_s": col(&["tally", "seconds_finalize_transcript"]),
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
