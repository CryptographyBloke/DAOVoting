//! Micro-benchmarks of the individual operations (release build).
//! Reports the median and min/max over `iters` runs, in microseconds.

use crate::ballot;
use crate::circuit::Circuit;
use crate::group::*;
use crate::shamir;
use crate::sigma::{Csz, CszStmt, Dleq, Zkp0};
use crate::tally::{Engine, Item, Public, Trustee, run_local};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use rand::rngs::OsRng;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Instant;

fn time<T>(iters: usize, mut f: impl FnMut() -> T) -> Value {
    for _ in 0..(iters / 10).max(1) {
        std::hint::black_box(f());
    }
    let mut v: Vec<f64> = (0..iters)
        .map(|_| {
            let t = Instant::now();
            std::hint::black_box(f());
            t.elapsed().as_secs_f64() * 1e6
        })
        .collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    json!({"median_us": v[v.len() / 2], "min_us": v[0], "max_us": v[v.len() - 1], "iters": iters})
}

fn committee() -> (Arc<Public>, Vec<(F, SigningKey)>) {
    let mut rng = OsRng;
    let (sk, shares) = shamir::deal(4, 5, &mut rng);
    let sks: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut rng)).collect();
    let pp = Public::new(
        g() * sk,
        shares.iter().map(|s| g() * s).collect(),
        sks.iter().map(|k| k.verifying_key()).collect(),
        [5; 32],
    );
    (Arc::new(pp), shares.into_iter().zip(sks).collect())
}

fn trustees(keys: &[(F, SigningKey)]) -> Vec<Trustee> {
    keys.iter()
        .enumerate()
        .map(|(i, (s, k))| Trustee::new(i, *s, k.clone()))
        .collect()
}

pub fn run(iters: usize, groth_iters: usize) -> Value {
    let mut rng = OsRng;
    let mut out = serde_json::Map::new();
    let mut put = |k: &str, v: Value| {
        eprintln!(
            "{k:<44} {:>12.1} us median {:>12.1} us min",
            v["median_us"].as_f64().unwrap_or(0.0),
            v["min_us"].as_f64().unwrap_or(0.0)
        );
        out.insert(k.to_string(), v);
    };
    let s = rand_scalar(&mut rng);
    let p = g() * rand_scalar(&mut rng);
    let tg = FixedBase::new(g());
    put(
        "group/fixed_base_mul (8-bit comb)",
        time(iters, || tg.mul(&s)),
    );
    put(
        "group/var_base_mul (wNAF w=5)",
        time(iters, || vmul(&p, &s)),
    );
    put(
        "group/var_base_mul (arkworks default)",
        time(iters, || p * s),
    );
    put("group/point_add", time(iters * 10, || p + p));
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    put(
        "group/compress",
        time(iters, || {
            let mut b = Vec::with_capacity(32);
            p.serialize_compressed(&mut b).unwrap();
            b
        }),
    );
    put(
        "group/decompress_unchecked (sqrt)",
        time(iters, || {
            G::deserialize_compressed_unchecked(&buf[..]).unwrap()
        }),
    );
    put(
        "group/subgroup_check (wNAF [q]P)",
        time(iters, || in_subgroup(&p)),
    );
    put("group/uncompressed_decode+on_curve", {
        let mut ub = Vec::new();
        p.serialize_uncompressed(&mut ub).unwrap();
        time(iters, move || {
            GA::deserialize_uncompressed(&ub[..]).unwrap()
        })
    });
    put(
        "group/decompress+validate (arkworks checked)",
        time(iters, || G::deserialize_compressed(&buf[..]).unwrap()),
    );
    let (pp, keys) = committee();
    let key = &pp.key;
    put("elgamal/enc", time(iters, || key.enc(&F::from(1u64), &s)));
    let x0 = key.enc(&F::from(1u64), &rand_scalar(&mut rng));
    let y0 = key
        .enc(&F::from(1u64), &rand_scalar(&mut rng))
        .small(2)
        .add(&Ct::trivial(-1));
    let (r1, r2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
    let x1 = key.reenc(&x0.neg(), &r1);
    let y1 = key.reenc(&y0.neg(), &r2);
    let e = pp.tht.mul(&r1);
    let st = CszStmt {
        x0: &x0,
        y0: &y0,
        x1: &x1,
        y1: &y1,
        e: &e,
    };
    let pr = Csz::prove(key, &pp.tht, &pp.ctx, 1, &st, -1, &r1, &r2, &mut rng);
    put(
        "proof/csz_mask_prove (incl. masking)",
        time(iters, || {
            let a = key.reenc(&x0.neg(), &r1);
            let b = key.reenc(&y0.neg(), &r2);
            (
                a,
                b,
                Csz::prove(key, &pp.tht, &pp.ctx, 1, &st, -1, &r1, &r2, &mut OsRng),
            )
        }),
    );
    put(
        "proof/csz_verify",
        time(iters, || assert!(pr.verify(key, &pp.tht, &pp.ctx, 1, &st))),
    );
    let rs = [rand_scalar(&mut rng), rand_scalar(&mut rng)];
    let a = [key.enc0(&rs[0]), key.enc0(&rs[1])];
    let z0 = Zkp0::prove(key, &pp.ctx, 1, &a, &rs, &mut rng);
    put(
        "proof/zkp0x2_prove (incl. A,B)",
        time(iters, || {
            let a = [key.enc0(&rs[0]), key.enc0(&rs[1])];
            Zkp0::prove(key, &pp.ctx, 1, &a, &rs, &mut OsRng)
        }),
    );
    put(
        "proof/zkp0x2_verify",
        time(iters, || assert!(z0.verify(key, &pp.ctx, 1, &a))),
    );
    let (sk_i, hi) = (s, g() * s);
    let thi = FixedBase::new(hi);
    let w = vmul(&p, &sk_i);
    let dl = Dleq::prove(&tg, &pp.ctx, 2, &sk_i, &hi, &p, &w, &mut rng);
    put(
        "proof/dleq_prove (incl. share)",
        time(iters, || {
            (
                vmul(&p, &sk_i),
                Dleq::prove(&tg, &pp.ctx, 2, &sk_i, &hi, &p, &w, &mut OsRng),
            )
        }),
    );
    put(
        "proof/dleq_verify",
        time(iters, || {
            assert!(dl.verify(&tg, &thi, &pp.ctx, 2, &hi, &p, &w))
        }),
    );
    let item = Item::Mask {
        slot: 1,
        x: x1,
        y: y1,
        e,
        proof: pr.clone(),
        commit: [0; 32],
    };
    let bytes = bincode::serialize(&item).unwrap();
    put(
        "serde/mask_item_serialize",
        time(iters, || bincode::serialize(&item).unwrap()),
    );
    put(
        "serde/mask_item_decode (subgroup check excluded)",
        time(iters, || bincode::deserialize::<Item>(&bytes).unwrap()),
    );
    let sk = SigningKey::generate(&mut rng);
    let body = vec![7u8; 1024];
    let sig = sk.sign(&body);
    put("auth/ed25519_sign_1KiB", time(iters, || sk.sign(&body)));
    put(
        "auth/ed25519_verify_1KiB",
        time(iters, || sk.verifying_key().verify(&body, &sig).unwrap()),
    );
    put(
        "hash/poseidon_2",
        time(iters, || {
            ballot::poseidon(&[Fb::from(1u64), Fb::from(2u64)])
        }),
    );

    // one complete conditional gate, co-located, verified once
    let gate_iters = (iters / 10).max(5);
    let ins = [
        key.enc(&F::from(1u64), &rand_scalar(&mut rng)),
        key.enc(&F::from(1u64), &rand_scalar(&mut rng)),
    ];
    let circ = Arc::new(Circuit::single_gate());
    put(
        "gate/full_cgate_5_trustees_verified_once",
        time(gate_iters, || {
            let mut ts = trustees(&keys);
            let mut e = Engine::new(pp.clone(), circ.clone(), &ins).unwrap();
            run_local(&mut e, &mut ts, true).unwrap()
        }),
    );
    put(
        "gate/full_cgate_5_trustees_unverified",
        time(gate_iters, || {
            let mut ts = trustees(&keys);
            let mut e = Engine::new(pp.clone(), circ.clone(), &ins).unwrap();
            run_local(&mut e, &mut ts, false).unwrap()
        }),
    );
    // per-gate cost of one replica verifying a gate (each trustee does this in distributed mode)
    let mut eng = Engine::new(pp.clone(), circ.clone(), &ins).unwrap();
    let log = run_local(&mut eng, &mut trustees(&keys), true).unwrap();
    put(
        "gate/replay_verify_one_gate",
        time(gate_iters, || {
            let mut v = Engine::new(pp.clone(), circ.clone(), &ins).unwrap();
            for m in &log {
                v.process(m, true).unwrap();
            }
        }),
    );
    put(
        "gate/replay_apply_only_one_gate",
        time(gate_iters, || {
            let mut v = Engine::new(pp.clone(), circ.clone(), &ins).unwrap();
            for m in &log {
                v.process(m, false).unwrap();
            }
        }),
    );
    let gate_bytes: usize = log
        .iter()
        .map(|m| bincode::serialize(m).unwrap().len())
        .sum();

    // Groth16 ballot
    let (pkey, vk) = ballot::crs(g(), &mut rng);
    let pvk = ark_groth16::prepare_verifying_key(&vk);
    let sv = Fb::from(42u64);
    let reg = ballot::Registry::new(&[(ballot::poseidon(&[sv]), 77)]);
    let voter = ballot::Voter {
        index: 0,
        s: sv,
        w: 77,
    };
    let b = ballot::cast(&pkey, key, &reg, 1, &voter, true, &mut rng);
    put(
        "ballot/groth16_prove",
        time(groth_iters, || {
            ballot::cast(&pkey, key, &reg, 1, &voter, true, &mut OsRng)
        }),
    );
    put(
        "ballot/groth16_verify",
        time(iters.min(50), || {
            ballot::verify(&pvk, &b, reg.root(), 1, key.h).unwrap()
        }),
    );
    let (nc, ni, nw) = ballot::constraint_count(key.h);
    let mut v = Value::Object(out);
    v["sizes"] = json!({
        "ballot_constraints": nc, "ballot_public_inputs": ni, "ballot_witness_vars": nw,
        "ballot_bytes": bincode::serialize(&b).unwrap().len(),
        "mask_item_bytes": bytes.len(),
        "one_gate_transcript_bytes": gate_bytes,
        "one_gate_messages": log.len(),
    });
    v
}

// ---------------------------------------------------------------- T005
//
// Profiling and CPU/GPU comparison drivers. Elections here use real
// ciphertexts, trustees, proofs and verification, but random encrypted input
// bits instead of Groth16 ballots (ballot proving is profiled separately), so
// the tally workload is identical to the protocol's for the same n.

use crate::batch::{BatchRecord, Cpu, MulBackend, Recorder};

fn med(mut v: Vec<f64>) -> Value {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() {
        return Value::Null;
    }
    json!({"median": v[v.len() / 2], "min": v[0], "max": v[v.len() - 1], "runs": v.len()})
}

/// Encrypted inputs of a random weighted election with `τ = ⌊Σw/2⌋`.
fn election(pp: &Public, n: usize) -> (Arc<Circuit>, Vec<Ct>, bool) {
    use rand::Rng;
    let mut rng = OsRng;
    let w: Vec<u64> = (0..n).map(|_| rng.gen_range(1..256)).collect();
    let v: Vec<u64> = (0..n).map(|_| rng.gen_range(0..2)).collect();
    let tau = w.iter().sum::<u64>() / 2;
    let total: u64 = w.iter().zip(&v).map(|(a, b)| a * b).sum();
    let bits: Vec<u64> = (0..n)
        .flat_map(|i| (0..8).map(|k| (v[i] * w[i] >> k) & 1).collect::<Vec<_>>())
        .collect();
    let inputs = bits
        .iter()
        .map(|b| pp.key.enc(&F::from(*b), &rand_scalar(&mut rng)))
        .collect();
    (Arc::new(Circuit::build(n, 8, tau)), inputs, total >= tau)
}

fn histogram(recs: &[BatchRecord]) -> Value {
    let mut b: std::collections::BTreeMap<u32, (u64, u64, f64)> = Default::default();
    for r in recs {
        let k = usize::BITS - r.jobs.max(1).leading_zeros();
        let e = b.entry(k).or_default();
        e.0 += 1;
        e.1 += r.jobs as u64;
        e.2 += r.seconds;
    }
    let rows: Vec<Value> = b
        .into_iter()
        .map(|(k, (c, j, s))| json!({"jobs_lo": 1u64 << (k - 1), "jobs_hi": (1u64 << k) - 1, "batches": c, "jobs": j, "seconds": s}))
        .collect();
    let jobs: u64 = recs.iter().map(|r| r.jobs as u64).sum();
    json!({"batches": recs.len(), "jobs": jobs, "max_batch": recs.iter().map(|r| r.jobs).max(), "by_size": rows})
}

/// Co-located tally (all five trustees, one verifying engine) with the given
/// verification backend; separates producing and processing time.
fn tally_once(
    pp: &Arc<Public>,
    keys: &[(F, SigningKey)],
    circ: &Arc<Circuit>,
    inputs: &[Ct],
    b: Option<Arc<dyn MulBackend>>,
) -> (Vec<crate::tally::Msg>, Value) {
    let t0 = Instant::now();
    let mut ts = trustees(keys);
    let mut eng = Engine::new(pp.clone(), circ.clone(), inputs).unwrap();
    eng.set_batch_backend(b);
    let (mut prod, mut proc) = (0.0, 0.0);
    let mut log = Vec::new();
    while !eng.finished() {
        let mut progressed = false;
        for t in ts.iter_mut() {
            let s = Instant::now();
            let m = t.produce(&eng);
            prod += s.elapsed().as_secs_f64();
            if let Some(m) = m {
                let s = Instant::now();
                eng.process(&m, true).unwrap();
                proc += s.elapsed().as_secs_f64();
                log.push(m);
                progressed = true;
            }
        }
        assert!(progressed, "protocol stalled");
    }
    let v = json!({
        "seconds_total": t0.elapsed().as_secs_f64(), "seconds_produce": prod, "seconds_process": proc,
        "messages": log.len(), "gates": eng.gates_done, "decision": eng.result,
        "output": format!("{:?}", eng.output_ct().map(|c| (c.a.into_affine(), c.b.into_affine()))), "prof": eng.prof,
    });
    (log, v)
}

/// Public replay (the independent verifier's backend check) of a transcript.
fn replay(
    pp: &Arc<Public>,
    circ: &Arc<Circuit>,
    inputs: &[Ct],
    log: &[crate::tally::Msg],
    b: Option<Arc<dyn MulBackend>>,
) -> Value {
    let t0 = Instant::now();
    let mut eng = Engine::new(pp.clone(), circ.clone(), inputs).unwrap();
    eng.set_batch_backend(b);
    for m in log {
        eng.process(m, true).unwrap();
    }
    json!({"seconds_total": t0.elapsed().as_secs_f64(), "accepted": eng.finished() && eng.gates_done == circ.n_gates(),
           "decision": eng.result, "output": format!("{:?}", eng.output_ct().map(|c| (c.a.into_affine(), c.b.into_affine()))), "prof": eng.prof})
}

/// Phase I profile: Groth16 stages and the encrypted tally for each `n`.
pub fn profile(ns: &[usize], groth_reps: usize) -> Value {
    let mut rng = OsRng;
    let mut out = serde_json::Map::new();
    // A. Groth16 ballot proving by stage
    let key = Key::new(g() * rand_scalar(&mut rng));
    let sv = Fb::from(42u64);
    let reg = ballot::Registry::new(&[(ballot::poseidon(&[sv]), 77)]);
    let (pk, _vk) = ballot::crs(key.h, &mut rng);
    let voter = ballot::Voter {
        index: 0,
        s: sv,
        w: 77,
    };
    let mut stages: Vec<ballot::ProveTimes> = Vec::new();
    for _ in 0..groth_reps {
        let (c, _, _) = ballot::ballot_circuit(&key, &reg, 1, &voter, true, &mut rng);
        stages.push(ballot::prove_staged(&pk, c, &mut rng).unwrap().1);
    }
    let col = |f: fn(&ballot::ProveTimes) -> f64| med(stages.iter().map(f).collect());
    eprintln!(
        "groth16 staged total median {:?}",
        col(|t| t.total)["median"]
    );
    let par_k = 2 * rayon::current_num_threads();
    let t = Instant::now();
    {
        use rayon::prelude::*;
        (0..par_k).into_par_iter().for_each(|_| {
            ballot::cast(&pk, &key, &reg, 1, &voter, true, &mut OsRng);
        });
    }
    let par = t.elapsed().as_secs_f64();
    out.insert("groth16".into(), json!({
        "reps": groth_reps, "constraints": stages[0].constraints, "msm_sizes_h_l_a_bg1_bg2": stages[0].msm_sizes,
        "synthesis": col(|t| t.synthesis), "finalize": col(|t| t.finalize), "witness_map_fft": col(|t| t.witness_map_fft),
        "msm_h_g1": col(|t| t.msm_h_g1), "msm_l_g1": col(|t| t.msm_l_g1), "msm_a_g1": col(|t| t.msm_a_g1),
        "msm_b_g1": col(|t| t.msm_b_g1), "msm_b_g2": col(|t| t.msm_b_g2), "assemble": col(|t| t.assemble), "total": col(|t| t.total),
        "parallel_throughput": {"proofs": par_k, "seconds": par, "proofs_per_second": par_k as f64 / par},
    }));
    // B/C. encrypted tally and public replay, inline vs batched CPU
    let (pp, keys) = committee();
    let mut tallies = Vec::new();
    for &n in ns {
        let (circ, inputs, want) = election(&pp, n);
        eprintln!("profile tally n={n}: inline");
        let (_, inline) = tally_once(&pp, &keys, &circ, &inputs, None);
        eprintln!("profile tally n={n}: batched cpu");
        let rec = Recorder::new(Arc::new(Cpu));
        let (log, batched) = tally_once(&pp, &keys, &circ, &inputs, Some(rec.clone()));
        let tally_hist = histogram(&rec.take());
        let r_inline = replay(&pp, &circ, &inputs, &log, None);
        let r_batched = replay(&pp, &circ, &inputs, &log, Some(rec.clone()));
        let replay_hist = histogram(&rec.take());
        assert_eq!(inline["decision"], json!(want));
        assert_eq!(batched["decision"], json!(want));
        assert!(r_inline["accepted"] == json!(true) && r_batched["accepted"] == json!(true));
        assert_eq!(r_inline["output"], r_batched["output"]);
        let (depth, width) = circ.dataflow_shape();
        tallies.push(json!({
            "n": n, "gates": circ.n_gates(), "dataflow_depth": depth, "dataflow_max_width": width,
            "tally_inline": inline, "tally_batched_cpu": batched, "tally_batches": tally_hist,
            "replay_inline": r_inline, "replay_batched_cpu": r_batched, "replay_batches": replay_hist,
        }));
    }
    out.insert("tally".into(), Value::Array(tallies));
    Value::Object(out)
}

/// Batch-size sweep and end-to-end comparison: CPU vs `target` backend.
pub fn gpu_bench(target: Arc<dyn MulBackend>, sizes: &[usize], reps: usize, ns: &[usize]) -> Value {
    let mut rng = OsRng;
    let cpu: Arc<dyn MulBackend> = Arc::new(Cpu);
    let pool: Vec<G> = (0..1024).map(|_| g() * rand_scalar(&mut rng)).collect();
    let mut sweep = Vec::new();
    for &n in sizes {
        // protocol-like mix: one subgroup check per three proof multiplications
        let jobs: Vec<crate::batch::Job> = (0..n)
            .map(|i| {
                let p = pool[i % pool.len()];
                if i % 4 == 3 {
                    crate::batch::Job::subgroup(p)
                } else {
                    crate::batch::Job::mul(p, &rand_scalar(&mut OsRng))
                }
            })
            .collect();
        let want = cpu.run(&jobs).unwrap();
        let got = target.run(&jobs).unwrap();
        let equal = want.iter().zip(&got).all(|(a, b)| a == b);
        assert!(equal, "backend result mismatch at batch size {n}");
        let tc: Vec<f64> = (0..reps)
            .map(|_| {
                let t = Instant::now();
                cpu.run(&jobs).unwrap();
                t.elapsed().as_secs_f64()
            })
            .collect();
        let tg: Vec<f64> = (0..reps)
            .map(|_| {
                let t = Instant::now();
                target.run(&jobs).unwrap();
                t.elapsed().as_secs_f64()
            })
            .collect();
        let (mc, mg) = (med(tc), med(tg));
        let s = mc["median"].as_f64().unwrap() / mg["median"].as_f64().unwrap();
        eprintln!(
            "batch {n:>7}: cpu {:.6}s  target {:.6}s  S = {s:.2}",
            mc["median"].as_f64().unwrap(),
            mg["median"].as_f64().unwrap()
        );
        sweep.push(
            json!({"jobs": n, "equal": equal, "cpu_s": mc, "target_s": mg, "speedup": s,
                          "target_jobs_per_s": n as f64 / mg["median"].as_f64().unwrap()}),
        );
    }
    let (pp, keys) = committee();
    let mut e2e = Vec::new();
    for &n in ns {
        let (circ, inputs, want) = election(&pp, n);
        let mut runs = Vec::new();
        for r in 0..reps.min(3).max(1) {
            // alternate order to reduce order bias
            let order: [(&str, Arc<dyn MulBackend>); 2] = if r % 2 == 0 {
                [("cpu", cpu.clone()), ("target", target.clone())]
            } else {
                [("target", target.clone()), ("cpu", cpu.clone())]
            };
            let mut row = serde_json::Map::new();
            let mut log0 = None;
            for (name, b) in order {
                eprintln!("e2e n={n} rep={r}: tally {name}");
                let (log, t) = tally_once(&pp, &keys, &circ, &inputs, Some(b.clone()));
                assert_eq!(t["decision"], json!(want));
                row.insert(format!("tally_{name}"), t);
                log0.get_or_insert(log);
            }
            let log = log0.unwrap();
            let rc = replay(&pp, &circ, &inputs, &log, Some(cpu.clone()));
            let rt = replay(&pp, &circ, &inputs, &log, Some(target.clone()));
            assert!(
                rc["accepted"] == json!(true)
                    && rt["accepted"] == json!(true)
                    && rc["output"] == rt["output"]
            );
            row.insert("replay_cpu".into(), rc);
            row.insert("replay_target".into(), rt);
            runs.push(Value::Object(row));
        }
        e2e.push(json!({"n": n, "gates": circ.n_gates(), "runs": runs}));
    }
    json!({"target": target.name(), "cpu": cpu.name(), "reps": reps, "sweep": sweep, "end_to_end": e2e})
}

/// Source revision and compiled features, recorded in every T005 output.
pub fn provenance() -> Value {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    json!({
        "source_commit": git(&["rev-parse", "HEAD"]),
        "source_dirty": git(&["status", "--porcelain", "--untracked-files=no"]).map(|s| !s.is_empty()),
        "features": {"gpu": cfg!(feature = "gpu"), "cuda12": cfg!(feature = "cuda"), "cuda13": cfg!(feature = "cuda13"), "cuda_emu": cfg!(feature = "cuda-emu")},
        "verify_backend_default": crate::batch::default_name(),
        "rayon_threads": rayon::current_num_threads(),
    })
}

/// Device-side timing breakdown if `b` is (or wraps) the CUDA backend.
#[allow(unused_variables)]
pub fn device_times(b: &Arc<dyn MulBackend>) -> Value {
    #[cfg(feature = "gpu")]
    if let Some(c) = crate::gpu::last_cuda() {
        return json!({"device": c.device, "compute_capability": c.compute_capability, "total_mem": c.total_mem,
                      "nvrtc_compile_seconds": c.compile_seconds, "times": *c.times.lock().unwrap()});
    }
    Value::Null
}

/// Build features, NVRTC compilation of the kernel, device properties and the
/// committed vectors on the device (whatever is available on this machine).
#[allow(unused_variables, unused_mut)]
pub fn gpu_check(arch: Option<String>, device: usize) -> Value {
    let mut v = json!({"provenance": provenance()});
    #[cfg(feature = "gpu")]
    {
        let arch: &'static str =
            Box::leak(arch.unwrap_or_else(|| "compute_89".into()).into_boxed_str());
        v["nvrtc"] = match crate::gpu::nvrtc_compile_check(arch) {
            Ok(n) => json!({"ok": true, "arch": arch, "ptx_bytes": n}),
            Err(e) => json!({"ok": false, "arch": arch, "error": format!("{e:#}")}),
        };
        let sm = arch.replace("compute_", "sm_");
        v["sass"] = match crate::gpu::nvrtc_sass_report(&sm) {
            Ok((log, n)) => json!({"ok": true, "arch": sm, "cubin_bytes": n, "ptxas_log": log}),
            Err(e) => json!({"ok": false, "arch": sm, "error": format!("{e:#}")}),
        };
        v["device"] = match crate::batch::backend(&format!("cuda:{device}")) {
            Ok(b) => {
                let vecs: Vec<crate::gpu::Vector> =
                    serde_json::from_str(include_str!("../tests/vectors/bjj_mul_v1.json")).unwrap();
                let bad = crate::gpu::check_vectors(&*b, &vecs);
                json!({"ok": true, "backend": b.name(), "vectors": vecs.len(),
                       "vector_mismatches": bad.as_ref().map(|b| b.len()).map_err(|e| format!("{e:#}")).ok(),
                       "times": device_times(&b)})
            }
            Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
        };
    }
    #[cfg(not(feature = "gpu"))]
    {
        v["nvrtc"] = json!("built without the cuda feature");
    }
    v
}

fn read_json(p: &std::path::Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(p).ok()?).ok()
}

fn f(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v["median"].as_f64())
}

fn fmt(x: Option<f64>, d: usize) -> String {
    x.map(|x| format!("{x:.d$}")).unwrap_or_else(|| "-".into())
}

/// Renders `summary.md` (and `summary.json`) for a `reproduce_gpu.ps1` output
/// directory: sweep, crossover, end-to-end S and R, full-protocol runs, GPU
/// monitor peaks. Only measured values are reported.
pub fn gpu_summary(dir: &std::path::Path) -> anyhow::Result<String> {
    let mut md = String::from("# T005 local GPU results\n\n");
    let mut js = serde_json::Map::new();
    if let Some(m) = read_json(&dir.join("machine.json")) {
        md += &format!(
            "Machine: {} | CPU: {} ({} logical) | {} | {} | feature `{}` | source {} (dirty: {})\n\n",
            m["gpu_nvidia_smi"].as_str().unwrap_or("-"),
            m["cpu"].as_str().unwrap_or("-"),
            m["logical"],
            m["os"].as_str().unwrap_or("-"),
            m["rustc"].as_str().unwrap_or("-"),
            m["cargo_feature"].as_str().unwrap_or("-"),
            m["source_revision"].as_str().unwrap_or("-"),
            m["source_dirty"]
        );
        js.insert("machine".into(), m);
    }
    for (label, sub) in [("CUDA", "bench-cuda"), ("Adaptive", "bench-auto")] {
        let Some(b) = read_json(&dir.join(sub).join("gpu_bench.json")) else {
            continue;
        };
        let g = &b["gpu_bench"];
        md += &format!(
            "## {label} backend: `{}`\n\nBatch sweep (median of {} reps; S = T_CPU / T_target, R = 100(1 - T_target/T_CPU)):\n\n| jobs | CPU s | target s | S | R % | target jobs/s |\n|---:|---:|---:|---:|---:|---:|\n",
            g["target"].as_str().unwrap_or("-"),
            g["reps"]
        );
        let mut cross = None;
        for r in g["sweep"].as_array().into_iter().flatten() {
            let (c, t) = (f(&r["cpu_s"]["median"]), f(&r["target_s"]["median"]));
            let s = r["speedup"].as_f64();
            if cross.is_none() && s.unwrap_or(0.0) >= 1.0 {
                cross = r["jobs"].as_u64();
            }
            md += &format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                r["jobs"],
                fmt(c, 6),
                fmt(t, 6),
                fmt(s, 2),
                fmt(s.map(|s| 100.0 * (1.0 - 1.0 / s)), 1),
                fmt(r["target_jobs_per_s"].as_f64(), 0)
            );
        }
        md += &format!(
            "\nCrossover (smallest measured batch with S >= 1): {}\n\n",
            cross.map(|c| c.to_string()).unwrap_or("none".into())
        );
        if !b["device_times"].is_null() {
            md += &format!(
                "Device time breakdown (cumulative, s): {}\n\n",
                b["device_times"]["times"]
            );
        }
        md += "End-to-end (in-memory election, real trustees/proofs; medians over runs):\n\n| n | gates | tally CPU s | tally target s | S | R % | replay CPU s | replay target s | S | R % | replay batch_run CPU/target s |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n";
        for e in g["end_to_end"].as_array().into_iter().flatten() {
            let runs = e["runs"].as_array().cloned().unwrap_or_default();
            let m = |k: &str, p: &str| -> Option<f64> {
                let mut v: Vec<f64> = runs.iter().filter_map(|r| r[k][p].as_f64()).collect();
                v.sort_by(|a, b| a.partial_cmp(b).unwrap());
                v.get(v.len() / 2).copied()
            };
            let mb = |k: &str| -> Option<f64> {
                let mut v: Vec<f64> = runs
                    .iter()
                    .filter_map(|r| r[k]["prof"]["batch_run"].as_f64())
                    .collect();
                v.sort_by(|a, b| a.partial_cmp(b).unwrap());
                v.get(v.len() / 2).copied()
            };
            let (tc, tt, rc, rt) = (
                m("tally_cpu", "seconds_total"),
                m("tally_target", "seconds_total"),
                m("replay_cpu", "seconds_total"),
                m("replay_target", "seconds_total"),
            );
            let s1 = tc.zip(tt).map(|(a, b)| a / b);
            let s2 = rc.zip(rt).map(|(a, b)| a / b);
            md += &format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} / {} |\n",
                e["n"],
                e["gates"],
                fmt(tc, 3),
                fmt(tt, 3),
                fmt(s1, 2),
                fmt(s1.map(|s| 100.0 * (1.0 - 1.0 / s)), 1),
                fmt(rc, 3),
                fmt(rt, 3),
                fmt(s2, 2),
                fmt(s2.map(|s| 100.0 * (1.0 - 1.0 / s)), 1),
                fmt(mb("replay_cpu"), 3),
                fmt(mb("replay_target"), 3)
            );
        }
        md += "\n";
        js.insert(sub.into(), b);
    }
    // full protocol runs
    let mut prot: Vec<_> = std::fs::read_dir(dir)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("protocol-")
                })
                .collect()
        })
        .unwrap_or_default();
    prot.sort();
    if !prot.is_empty() {
        md += "## Full protocol (Groth16 ballots, admission, tally, TCP trustees, separate public verifier, oracle)\n\n| verify backend | n | variant | runs | tally s | trustee verify s (mean) | public verifier backend s | accepted | oracle |\n|---|---:|---|---:|---:|---:|---:|---|---|\n";
        for p in &prot {
            let vb = p
                .file_name()
                .unwrap()
                .to_string_lossy()
                .trim_start_matches("protocol-")
                .to_string();
            let mut ns: Vec<_> = std::fs::read_dir(p)
                .map(|d| {
                    d.filter_map(|e| e.ok())
                        .map(|e| e.path().join("results.json"))
                        .filter(|r| r.exists())
                        .collect()
                })
                .unwrap_or_default();
            ns.sort();
            for rj in ns {
                let Some(r) = read_json(&rj) else { continue };
                let runs = r["runs"].as_array().cloned().unwrap_or_default();
                let mut vars: Vec<String> = runs
                    .iter()
                    .filter_map(|x| x["variant"].as_str().map(String::from))
                    .collect();
                vars.sort();
                vars.dedup();
                for v in vars {
                    let rs: Vec<&Value> =
                        runs.iter().filter(|x| x["variant"] == json!(v)).collect();
                    let medv = |g: &dyn Fn(&Value) -> Option<f64>| {
                        let mut x: Vec<f64> = rs.iter().filter_map(|r| g(r)).collect();
                        x.sort_by(|a, b| a.partial_cmp(b).unwrap());
                        x.get(x.len() / 2).copied()
                    };
                    let tv = medv(&|r| {
                        let t = r["tally"]["board"]["trustees"].as_array()?;
                        Some(
                            t.iter()
                                .filter_map(|x| x["seconds_verify"].as_f64())
                                .sum::<f64>()
                                / t.len() as f64,
                        )
                    });
                    md += &format!(
                        "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                        vb,
                        r["n"],
                        v,
                        rs.len(),
                        fmt(medv(&|r| r["tally"]["seconds_tally"].as_f64()), 3),
                        fmt(tv, 3),
                        fmt(medv(&|r| r["verification"]["seconds_backend"].as_f64()), 3),
                        rs.iter()
                            .all(|r| r["verification"]["accept"] == json!(true)),
                        rs.iter().all(|r| r["oracle_agrees"] == json!(true))
                    );
                }
            }
        }
        md += "\n";
    }
    // GPU monitor
    if let Ok(csv) = std::fs::read_to_string(dir.join("gpu_monitor.csv")) {
        let num = |s: &str| {
            s.trim()
                .split(' ')
                .next()
                .and_then(|x| x.parse::<f64>().ok())
        };
        let rows: Vec<Vec<String>> = csv
            .lines()
            .skip(1)
            .map(|l| l.split(',').map(|x| x.to_string()).collect())
            .filter(|r: &Vec<String>| r.len() >= 4)
            .collect();
        let util: Vec<f64> = rows.iter().filter_map(|r| num(&r[1])).collect();
        let mem: Vec<f64> = rows.iter().filter_map(|r| num(&r[3])).collect();
        if !util.is_empty() {
            let busy: Vec<f64> = util.iter().copied().filter(|u| *u > 0.0).collect();
            md += &format!(
                "GPU monitor (nvidia-smi, 200 ms): {} samples, peak utilization {:.0} %, mean utilization while busy {:.1} %, peak memory used {:.0} MiB\n\n",
                util.len(),
                util.iter().cloned().fold(0.0, f64::max),
                busy.iter().sum::<f64>() / busy.len().max(1) as f64,
                mem.iter().cloned().fold(0.0, f64::max)
            );
        }
    }
    js.insert("summary_md".into(), json!(md));
    std::fs::write(dir.join("summary.md"), &md)?;
    crate::setup::write_json(&dir.join("summary.json"), &Value::Object(js))?;
    Ok(md)
}
