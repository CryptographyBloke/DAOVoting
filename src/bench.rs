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
    let raw = v.clone();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() {
        return Value::Null;
    }
    json!({"median": v[v.len() / 2], "min": v[0], "max": v[v.len() - 1], "runs": v.len(), "raw": raw})
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
    tally_cfg(pp, keys, circ, inputs, &|e: &mut Engine| {
        e.set_batch_backend(b.clone())
    })
}

fn tally_cfg(
    pp: &Arc<Public>,
    keys: &[(F, SigningKey)],
    circ: &Arc<Circuit>,
    inputs: &[Ct],
    cfg: &dyn Fn(&mut Engine),
) -> (Vec<crate::tally::Msg>, Value) {
    let t0 = Instant::now();
    let mut ts = trustees(keys);
    let mut eng = Engine::new(pp.clone(), circ.clone(), inputs).unwrap();
    cfg(&mut eng);
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
    let bytes: usize = log
        .iter()
        .map(|m| bincode::serialize(m).unwrap().len())
        .sum();
    let v = json!({
        "seconds_total": t0.elapsed().as_secs_f64(), "seconds_produce": prod, "seconds_process": proc,
        "messages": log.len(), "items": eng.n_items, "transcript_message_bytes": bytes, "gates": eng.gates_done, "decision": eng.result,
        "stream": stream_profile(&log, eng.wide_points),
        "output": format!("{:?}", eng.output_ct().map(|c| (c.a.into_affine(), c.b.into_affine()))), "prof": eng.prof,
    });
    (log, v)
}

/// T009: per-family composition of a transcript: items, serialized item
/// bytes (exact, from the signed bodies) and transmitted group elements.
pub fn stream_profile(log: &[crate::tally::Msg], wide: bool) -> Value {
    use crate::tally::Item;
    let mut m: std::collections::BTreeMap<&'static str, (u64, u64, u64)> = Default::default();
    let mut framing = 0u64;
    for msg in log {
        let total = bincode::serialize(msg).unwrap().len() as u64;
        let enc: Vec<Vec<u8>> = bincode::deserialize(&msg.body).unwrap();
        let mut inner = 0;
        for b in &enc {
            let it: Item = message_wire(wide, || bincode::deserialize(b).unwrap());
            let fam = match &it {
                Item::Mask { .. } | Item::Mask2 { .. } => "mask+CSZ",
                Item::Commit { .. } => "commit",
                Item::Reveal { .. } | Item::Reveal2 { .. } => "reveal+ZKP0",
                Item::Reveal5 { .. } => "reveal (batched)",
                Item::Dec { .. } | Item::Dec2 { .. } => "share+DLEQ",
                Item::Dec5 { .. } => "share (batched)",
                Item::Lin5 { .. } => "linear batch proof",
            };
            let pts = (it.points().len() + it.v2_points().len()) as u64;
            let e = m.entry(fam).or_default();
            e.0 += 1;
            e.1 += b.len() as u64;
            e.2 += pts;
            inner += b.len() as u64;
        }
        framing += total - inner;
    }
    let fams: serde_json::Map<String, Value> = m
        .into_iter()
        .map(|(k, (n, b, p))| (k.to_string(), json!({"items": n, "bytes": b, "points": p})))
        .collect();
    json!({"families": fams, "framing_and_signature_bytes": framing})
}

/// Public replay (the independent verifier's backend check) of a transcript.
fn replay(
    pp: &Arc<Public>,
    circ: &Arc<Circuit>,
    inputs: &[Ct],
    log: &[crate::tally::Msg],
    b: Option<Arc<dyn MulBackend>>,
) -> Value {
    replay_cfg(pp, circ, inputs, log, &|e: &mut Engine| {
        e.set_batch_backend(b.clone())
    })
}

fn replay_cfg(
    pp: &Arc<Public>,
    circ: &Arc<Circuit>,
    inputs: &[Ct],
    log: &[crate::tally::Msg],
    cfg: &dyn Fn(&mut Engine),
) -> Value {
    let t0 = Instant::now();
    let mut eng = Engine::new(pp.clone(), circ.clone(), inputs).unwrap();
    cfg(&mut eng);
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
        let equal = want.len() == got.len() && want.iter().zip(&got).all(|(a, b)| a == b);
        assert!(equal, "backend result mismatch at batch size {n}");
        let mut tc = Vec::new();
        let mut tg = Vec::new();
        let before = device_times(&target);
        let mut execution_order = Vec::new();
        for r in 0..reps {
            let order = if r % 2 == 0 {
                ["cpu", "target"]
            } else {
                ["target", "cpu"]
            };
            execution_order.push(order);
            for label in order {
                let t = Instant::now();
                if label == "cpu" {
                    cpu.run(&jobs).unwrap();
                    tc.push(t.elapsed().as_secs_f64());
                } else {
                    target.run(&jobs).unwrap();
                    tg.push(t.elapsed().as_secs_f64());
                }
            }
        }
        let after = device_times(&target);
        let (mc, mg) = (med(tc), med(tg));
        let s = mc["median"].as_f64().unwrap() / mg["median"].as_f64().unwrap();
        eprintln!(
            "batch {n:>7}: cpu {:.6}s  target {:.6}s  S = {s:.2}",
            mc["median"].as_f64().unwrap(),
            mg["median"].as_f64().unwrap()
        );
        sweep.push(
            json!({"jobs": n, "equal": equal, "cpu_s": mc, "target_s": mg, "speedup": s,
                          "target_jobs_per_s": n as f64 / mg["median"].as_f64().unwrap(),
                          "execution_order": execution_order, "device_before": before, "device_after": after}),
        );
    }
    let (pp, keys) = committee();
    let mut e2e = Vec::new();
    for &n in ns {
        let (circ, inputs, want) = election(&pp, n);
        let mut runs = Vec::new();
        for r in 0..reps.min(3).max(1) {
            // alternate order to reduce order bias
            let mut order: Vec<(&str, Option<Arc<dyn MulBackend>>)> = vec![
                ("inline", None),
                ("cpu", Some(cpu.clone())),
                ("target", Some(target.clone())),
            ];
            order.rotate_left(r % 3);
            let mut row = serde_json::Map::new();
            let mut log0 = None;
            row.insert(
                "execution_order".into(),
                json!(order.iter().map(|(n, _)| *n).collect::<Vec<_>>()),
            );
            for (name, b) in order {
                eprintln!("e2e n={n} rep={r}: tally {name}");
                let (log, t) = tally_once(&pp, &keys, &circ, &inputs, b);
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
            let ri = replay(&pp, &circ, &inputs, &log, None);
            assert!(ri["accepted"] == json!(true) && ri["output"] == rc["output"]);
            row.insert("replay_inline".into(), ri);
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
                json!({"ok": bad.as_ref().is_ok_and(|b| b.is_empty()), "backend": b.name(), "vectors": vecs.len(),
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

fn prepared_protocol_summary(rows: &Value) -> anyhow::Result<Value> {
    use anyhow::{Context, ensure};
    let mut groups = std::collections::BTreeMap::<(u64, String, String), Vec<f64>>::new();
    for r in rows.as_array().context("expected protocol result array")? {
        let n = r["n"].as_u64().context("missing electorate size")?;
        let mode = r["mode"].as_str().context("missing tally mode")?;
        let backend = r["backend"].as_str().context("missing backend")?;
        ensure!(r["oracle_agrees"] == true, "oracle did not agree");
        for label in ["cpu", "selected"] {
            let v = &r["verification"][label];
            ensure!(
                v["accept"] == true
                    && v["ballots"] == n
                    && v["decision"].is_boolean()
                    && v["decision"] == r["tally"]["decision"],
                "public verification failed: {label}"
            );
        }
        let seconds = match mode {
            "local" => r["tally"]["seconds_tally"].as_f64(),
            "dist" => r["tally"]["board"]["seconds_total"].as_f64(),
            _ => None,
        }
        .context("missing tally measurement")?;
        ensure!(seconds.is_finite() && seconds > 0.0, "invalid tally time");
        groups
            .entry((n, mode.into(), backend.into()))
            .or_default()
            .push(seconds);
    }
    ensure!(!groups.is_empty(), "no verified protocol results");
    Ok(json!(
        groups
            .into_iter()
            .map(|((n, mode, backend), times)| {
                json!({"n": n, "mode": mode, "backend": backend, "tally_s": med(times),
               "cpu_accept": true, "selected_accept": true, "oracle_agrees": true})
            })
            .collect::<Vec<_>>()
    ))
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
    let prepared = dir.join("protocol-results.json");
    if prepared.exists() {
        // PowerShell writes UTF-8 with a BOM on Windows PowerShell 5.1.
        let text = std::fs::read_to_string(&prepared)?;
        let rows: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))?;
        let summary = prepared_protocol_summary(&rows)?;
        md += "## Paired full protocol\n\nTally excludes proving and independent replay. Distributed time is Board START to completion; process startup is excluded.\n\n| n | mode | backend | runs | tally median s | min s | max s | CPU / selected / oracle |\n|---:|---|---|---:|---:|---:|---:|---|\n";
        for r in summary.as_array().unwrap() {
            md += &format!(
                "| {} | {} | {} | {} | {} | {} | {} | PASS / PASS / PASS |\n",
                r["n"],
                r["mode"].as_str().unwrap(),
                r["backend"].as_str().unwrap(),
                r["tally_s"]["runs"],
                fmt(f(&r["tally_s"]["median"]), 3),
                fmt(f(&r["tally_s"]["min"]), 3),
                fmt(f(&r["tally_s"]["max"]), 3)
            );
        }
        md += "\n";
        js.insert("paired_protocol".into(), summary);
    }
    let mut prot: Vec<_> = std::fs::read_dir(dir)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.is_dir()
                        && p.file_name()
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

#[cfg(test)]
mod gpu_summary_tests {
    use super::*;

    #[test]
    fn prepared_results_require_both_verifiers_and_oracle() {
        let v = json!({"accept": true, "ballots": 8, "decision": false});
        let local = json!({"n": 8, "mode": "local", "backend": "cpu",
            "tally": {"decision": false, "seconds_tally": 2.0},
            "verification": {"cpu": v, "selected": v}, "oracle_agrees": true});
        let mut dist = local.clone();
        dist["mode"] = json!("dist");
        dist["tally"]["board"] = json!({"seconds_total": 3.0});
        let result = prepared_protocol_summary(&json!([local.clone(), dist])).unwrap();
        assert_eq!(result.as_array().unwrap().len(), 2);
        assert_eq!(result[0]["tally_s"]["median"], 3.0);
        for field in ["cpu", "selected"] {
            let mut bad = local.clone();
            bad["verification"][field]["accept"] = json!(false);
            assert!(prepared_protocol_summary(&json!([bad])).is_err());
        }
        let mut bad = local.clone();
        bad["oracle_agrees"] = json!(false);
        assert!(prepared_protocol_summary(&json!([bad])).is_err());
        let mut bad = local;
        bad["tally"]["decision"] = json!(true);
        assert!(prepared_protocol_summary(&json!([bad])).is_err());
        assert!(prepared_protocol_summary(&json!([])).is_err());
    }
}

// ---------------------------------------------------------------- T007

fn setv2(individual: bool, b: Option<Arc<dyn MulBackend>>) -> impl Fn(&mut Engine) {
    move |e: &mut Engine| {
        e.set_batch_backend(b.clone());
        e.select_format(2);
        e.v2_individual = individual;
        e.v2_coeff_fs = false;
    }
}

/// Paired engine-level comparison of verification architectures on the same
/// election inputs (real trustees, proofs and verification; encrypted input
/// bits instead of Groth16 ballots): v1 inline, v1 batched CPU, v2 individual,
/// v2 batch (one MSM per message); public replay additionally with the
/// certified-offload backend (device = CPU, to measure the check overhead).
pub fn format_bench(ns: &[usize], reps: usize) -> Value {
    use crate::batch::Certified;
    let (pp, keys) = committee();
    let mut out = Vec::new();
    for &n in ns {
        let (circ, inputs, want) = election(&pp, n);
        let mut runs = Vec::new();
        for r in 0..reps {
            // batched configurations use `--verify-backend` if given (CPU otherwise)
            let dev = crate::batch::default_backend();
            let v1i = |e: &mut Engine| e.set_batch_backend(None);
            let d1 = dev.clone().unwrap_or_else(|| Arc::new(Cpu));
            let v1b = move |e: &mut Engine| e.set_batch_backend(Some(d1.clone()));
            let (v2i, v2b) = (setv2(true, None), setv2(false, dev.clone()));
            let mut cfgs: Vec<(&str, &dyn Fn(&mut Engine))> = vec![
                ("v1_inline", &v1i),
                ("v1_batched_cpu", &v1b),
                ("v2_individual", &v2i),
                ("v2_batch", &v2b),
            ];
            if r % 2 == 1 {
                cfgs.reverse();
            }
            let mut row = serde_json::Map::new();
            let (mut log1, mut log2) = (None, None);
            for (name, cfg) in &cfgs {
                eprintln!("format-bench n={n} rep={r}: tally {name}");
                let (log, t) = tally_cfg(&pp, &keys, &circ, &inputs, *cfg);
                assert_eq!(t["decision"], json!(want));
                if name.starts_with("v1") {
                    log1.get_or_insert(log);
                } else {
                    log2.get_or_insert(log);
                }
                row.insert(format!("tally_{name}"), t);
            }
            let (log1, log2) = (log1.unwrap(), log2.unwrap());
            for (name, cfg) in &cfgs {
                eprintln!("format-bench n={n} rep={r}: replay {name}");
                let lg = if name.starts_with("v1") { &log1 } else { &log2 };
                let v = replay_cfg(&pp, &circ, &inputs, lg, *cfg);
                assert_eq!(v["accepted"], json!(true));
                row.insert(format!("replay_{name}"), v);
            }
            let cert = Certified::new(Arc::new(Cpu));
            let c2 = cert.clone();
            let v = replay_cfg(&pp, &circ, &inputs, &log1, &move |e: &mut Engine| {
                e.set_batch_backend(Some(c2.clone()))
            });
            assert_eq!(v["accepted"], json!(true));
            row.insert(
                "replay_v1_certified_cpu".into(),
                json!({"replay": v, "cert": *cert.stats.lock().unwrap()}),
            );
            runs.push(Value::Object(row));
        }
        out.push(json!({"n": n, "gates": circ.n_gates(), "runs": runs}));
    }
    json!({"reps": reps, "batched_backend": crate::batch::default_name(), "results": out})
}

/// CSZ verification only, for `k` independent proofs: v1 (5 subgroup checks +
/// 10 multiplications each), v2 individual (cofactor-image decode of 15 points
/// + 10 multiplications) and v2 batch (decode + one MSM); medians of `reps`.
pub fn proof_sweep(sizes: &[usize], reps: usize) -> Value {
    use crate::sigma::{Acc, Bases, Csz, Csz2, CszStmt};
    use rayon::prelude::*;
    let mut rng = OsRng;
    let k = Key::new(g() * rand_scalar(&mut rng));
    let lk = LiftKey::new(k.h);
    let (tht, tht8) = (
        FixedBase::new(h_tilde()),
        FixedBase::new(lift_of(&h_tilde())),
    );
    let max = *sizes.iter().max().unwrap_or(&1);
    struct Inst {
        x0: Ct,
        y0: Ct,
        x1: Ct,
        y1: Ct,
        e: G,
        p1: Csz,
        p2: Csz2,
        l: (Ct, Ct, G),
    }
    let insts: Vec<Inst> = (0..max)
        .into_par_iter()
        .map(|i| {
            let mut rng = OsRng;
            let x0 = k.enc(&F::from(i as u64), &rand_scalar(&mut rng));
            let y0 = k.enc(&F::from(1u64), &rand_scalar(&mut rng));
            let s: i64 = if i % 2 == 0 { 1 } else { -1 };
            let (r1, r2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
            let (lx1, ly1, le) = (
                x0.lift_of().small(s).add(&lk.enc0(&r1)),
                y0.lift_of().small(s).add(&lk.enc0(&r2)),
                tht8.mul(&r1),
            );
            let (x1, y1, e) = (lx1.clear8(), ly1.clear8(), clear8(&le));
            let st = CszStmt {
                x0: &x0,
                y0: &y0,
                x1: &x1,
                y1: &y1,
                e: &e,
            };
            let p1 = Csz::prove(&k, &tht, &[0; 32], i as u64, &st, s, &r1, &r2, &mut rng);
            let p2 = Csz2::prove(
                &k, &lk, &tht8, &[0; 32], i as u64, &st, s, &r1, &r2, &mut rng,
            );
            Inst {
                x0,
                y0,
                x1,
                y1,
                e,
                p1,
                p2,
                l: (lx1, ly1, le),
            }
        })
        .collect();
    let b = Bases {
        g: &k.tg,
        h: &k.th,
        ht: &tht,
        w: None,
    };
    let mut rows = Vec::new();
    for &n in sizes {
        let set = &insts[..n];
        let timed = |f: &dyn Fn() -> bool| {
            let mut v: Vec<f64> = (0..reps)
                .map(|_| {
                    let t = Instant::now();
                    assert!(f());
                    t.elapsed().as_secs_f64()
                })
                .collect();
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        let v1 = timed(&|| {
            set.par_iter().enumerate().all(|(i, x)| {
                [x.x1.a, x.x1.b, x.y1.a, x.y1.b, x.e]
                    .iter()
                    .all(in_subgroup)
                    && x.p1.verify(
                        &k,
                        &tht,
                        &[0; 32],
                        i as u64,
                        &CszStmt {
                            x0: &x.x0,
                            y0: &x.y0,
                            x1: &x.x1,
                            y1: &x.y1,
                            e: &x.e,
                        },
                    )
            })
        });
        let decode = |x: &Inst| {
            let (x1, y1, e) = (x.l.0.clear8(), x.l.1.clear8(), clear8(&x.l.2));
            let p = Csz2 {
                c: x.p2.c.map(|c| c.clear8()),
                ce: x.p2.ce.map(|c| clear8(&c)),
                ..x.p2.clone()
            };
            (x1, y1, e, p)
        };
        let v2i = timed(&|| {
            set.par_iter().enumerate().all(|(i, x)| {
                let (x1, y1, e, p) = decode(x);
                p.rels(
                    &k,
                    &[0; 32],
                    i as u64,
                    &CszStmt {
                        x0: &x.x0,
                        y0: &x.y0,
                        x1: &x1,
                        y1: &y1,
                        e: &e,
                    },
                )
                .map(|r| r.check_each(&b))
                .unwrap_or(false)
            })
        });
        let v2b = timed(&|| {
            use ark_ff::Zero;
            let acc = set
                .par_iter()
                .enumerate()
                .map(|(i, x)| {
                    let (x1, y1, e, p) = decode(x);
                    let r = p
                        .rels(
                            &k,
                            &[0; 32],
                            i as u64,
                            &CszStmt {
                                x0: &x.x0,
                                y0: &x.y0,
                                x1: &x1,
                                y1: &y1,
                                e: &e,
                            },
                        )
                        .unwrap();
                    let mut a = Acc::default();
                    a.add(&r, &mut rand::thread_rng());
                    a
                })
                .reduce(Acc::default, |mut a, b| {
                    a.merge(b);
                    a
                });
            (acc.fixed_part(&b) + crate::batch::msm_cpu(&acc.pts, &acc.sc)).is_zero()
        });
        eprintln!(
            "proof-sweep {n:>5}: v1 {v1:.4}s  v2-ind {v2i:.4}s  v2-batch {v2b:.4}s  S(v1/v2b) {:.2}",
            v1 / v2b
        );
        rows.push(json!({"proofs": n, "v1_s": v1, "v2_individual_s": v2i, "v2_batch_s": v2b,
            "v1_us_per_proof": 1e6 * v1 / n as f64, "v2_individual_us_per_proof": 1e6 * v2i / n as f64, "v2_batch_us_per_proof": 1e6 * v2b / n as f64,
            "speedup_v1_over_v2_batch": v1 / v2b, "speedup_v1_over_v2_individual": v1 / v2i}));
    }
    json!({"reps": reps, "rows": rows,
           "bytes": {"csz_v1": bincode::serialize(&insts[0].p1).unwrap().len(), "csz_v2": bincode::serialize(&insts[0].p2).unwrap().len()}})
}

/// T008 proof algebra comparison. Points are already curve-validated in memory;
/// wire parsing is deliberately measured by codec_bench and complete replay.
pub fn mixed_proof_sweep(sizes: &[usize], reps: usize, specs: &[String]) -> Value {
    use crate::sigma::{Acc, Bases, Csz2, Dleq2, Rels, Zkp02};
    use ark_ff::{BigInteger, PrimeField, Zero};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rayon::prelude::*;
    #[derive(Clone, serde::Serialize)]
    enum Case {
        C {
            x0: Ct,
            y0: Ct,
            x: Ct,
            y: Ct,
            #[serde(with = "crate::group::arkser_fast")]
            e: G,
            old: Csz,
            new: Csz2,
        },
        Z {
            a: [Ct; 2],
            old: Zkp0,
            new: Zkp02,
        },
        D {
            #[serde(with = "crate::group::arkser_fast")]
            u: G,
            #[serde(with = "crate::group::arkser_fast")]
            w: G,
            old: Dleq,
            new: Dleq2,
        },
    }
    impl Case {
        fn transform(&mut self, mut point: impl FnMut(&mut G)) {
            let mut ct = |c: &mut Ct| {
                point(&mut c.a);
                point(&mut c.b);
            };
            match self {
                Case::C { x, y, e, new, .. } => {
                    ct(x);
                    ct(y);
                    for c in &mut new.c {
                        ct(c);
                    }
                    point(e);
                    for p in &mut new.ce {
                        point(p);
                    }
                }
                Case::Z { a, new, .. } => {
                    for c in a {
                        ct(c);
                    }
                    for c in &mut new.e {
                        ct(c);
                    }
                }
                Case::D { w, new, .. } => {
                    point(w);
                    point(&mut new.e1);
                    point(&mut new.e2);
                }
            }
        }
        fn canonical(&self) -> Self {
            let mut c = self.clone();
            c.transform(|p| *p = clear8(p));
            c
        }
        fn rels(&self, key: &Key, ctx: &[u8; 32], label: u64, wb: &G) -> Rels {
            match self {
                Case::C {
                    x0,
                    y0,
                    x,
                    y,
                    e,
                    new,
                    ..
                } => new
                    .rels(
                        key,
                        ctx,
                        label,
                        &CszStmt {
                            x0,
                            y0,
                            x1: x,
                            y1: y,
                            e,
                        },
                    )
                    .unwrap(),
                Case::Z { a, new, .. } => new.rels(ctx, label, a).unwrap(),
                Case::D { u, w, new, .. } => new.rels(ctx, label, wb, u, w),
            }
        }
        fn v1(
            &self,
            key: &Key,
            ht: &FixedBase,
            tw: &FixedBase,
            ctx: &[u8; 32],
            label: u64,
            wb: &G,
        ) -> bool {
            match self {
                Case::C {
                    x0,
                    y0,
                    x,
                    y,
                    e,
                    old,
                    ..
                } => {
                    [x.a, x.b, y.a, y.b, *e].iter().all(in_subgroup)
                        && old.verify(
                            key,
                            ht,
                            ctx,
                            label,
                            &CszStmt {
                                x0,
                                y0,
                                x1: x,
                                y1: y,
                                e,
                            },
                        )
                }
                Case::Z { a, old, .. } => {
                    a.iter().flat_map(|c| [c.a, c.b]).all(|p| in_subgroup(&p))
                        && old.verify(key, ctx, label, a)
                }
                Case::D { u, w, old, .. } => {
                    in_subgroup(w) && old.verify(&key.tg, tw, ctx, label, wb, u, w)
                }
            }
        }
    }
    assert!(reps > 0 && !sizes.is_empty());
    let mut rng = OsRng;
    let ctx = sha256(&[b"wod/t008/proof-sweep"]);
    let key = Key::new(g() * rand_scalar(&mut rng));
    let lk = LiftKey::new(key.h);
    let ht = FixedBase::new(h_tilde());
    let ht8 = FixedBase::new(lift_of(&h_tilde()));
    let secret = rand_scalar(&mut rng);
    let wb = key.tg.mul(&secret);
    let tw = FixedBase::new(wb);
    let bases = Bases {
        g: &key.tg,
        h: &key.th,
        ht: &ht,
        w: Some(&tw),
    };
    let max = *sizes.iter().max().unwrap();
    assert!(max > 0);
    let mut pools = Vec::new();
    let mut generation = Vec::new();
    for family in 0..3usize {
        let start = Instant::now();
        let samples: Vec<_> = (0..max)
            .into_par_iter()
            .map(|i| {
                let mut rng = OsRng;
                let label = ((family as u64) << 48) | i as u64;
                let (case, t1, t2) = match family {
                    0 => {
                        let x0 = key.enc(&F::from(i as u64), &rand_scalar(&mut rng));
                        let y0 = key.enc(&F::from(1u64), &rand_scalar(&mut rng));
                        let sign = if i % 2 == 0 { 1 } else { -1 };
                        let r1 = rand_scalar(&mut rng);
                        let r2 = rand_scalar(&mut rng);
                        let x = x0.lift_of().small(sign).add(&lk.enc0(&r1));
                        let y = y0.lift_of().small(sign).add(&lk.enc0(&r2));
                        let e = ht8.mul(&r1);
                        let (xc, yc, ec) = (x.clear8(), y.clear8(), clear8(&e));
                        let st = CszStmt {
                            x0: &x0,
                            y0: &y0,
                            x1: &xc,
                            y1: &yc,
                            e: &ec,
                        };
                        let t = Instant::now();
                        let old = Csz::prove(&key, &ht, &ctx, label, &st, sign, &r1, &r2, &mut rng);
                        let t1 = t.elapsed().as_secs_f64();
                        let t = Instant::now();
                        let new = Csz2::prove(
                            &key, &lk, &ht8, &ctx, label, &st, sign, &r1, &r2, &mut rng,
                        );
                        let t2 = t.elapsed().as_secs_f64();
                        (
                            Case::C {
                                x0,
                                y0,
                                x,
                                y,
                                e,
                                old,
                                new,
                            },
                            t1,
                            t2,
                        )
                    }
                    1 => {
                        let rs = [rand_scalar(&mut rng), rand_scalar(&mut rng)];
                        let a = rs.map(|r| lk.enc0(&r));
                        let ac = a.map(|c| c.clear8());
                        let t = Instant::now();
                        let old = Zkp0::prove(&key, &ctx, label, &ac, &rs, &mut rng);
                        let t1 = t.elapsed().as_secs_f64();
                        let t = Instant::now();
                        let new = Zkp02::prove(&key, &lk, &ctx, label, &ac, &rs, &mut rng);
                        let t2 = t.elapsed().as_secs_f64();
                        (Case::Z { a, old, new }, t1, t2)
                    }
                    _ => {
                        let u = g() * rand_scalar(&mut rng);
                        let w = vmul(&u, &secret);
                        let t = Instant::now();
                        let old = Dleq::prove(&key.tg, &ctx, label, &secret, &wb, &u, &w, &mut rng);
                        let t1 = t.elapsed().as_secs_f64();
                        let t = Instant::now();
                        let (w, new) =
                            Dleq2::prove(&key.tg, &lk, &ctx, label, &secret, &wb, &u, &mut rng);
                        let t2 = t.elapsed().as_secs_f64();
                        (Case::D { u, w, old, new }, t1, t2)
                    }
                };
                let t = Instant::now();
                let mut secure = case.clone();
                secure.transform(|p| randomize_lift(p, &mut rng));
                let refresh = t.elapsed().as_secs_f64();
                let canonical = case.canonical();
                (case, secure, canonical, t1, t2, refresh)
            })
            .collect();
        generation.push(json!({"family":(["csz","zkp0","dleq"][family]),"instances":max,"prepare_wall_seconds":start.elapsed().as_secs_f64(),
            "public_instance_sha256":hex::encode(sha256(&[&bincode::serialize(&samples.iter().map(|s|&s.0).collect::<Vec<_>>()).unwrap()])),
            "v1_proof_worker_seconds":med(samples.iter().map(|s|s.3).collect()),"commitment_proof_worker_seconds":med(samples.iter().map(|s|s.4).collect()),
            "representation_refresh_worker_seconds":med(samples.iter().map(|s|s.5).collect()),
            "proof_bytes":match &samples[0].0 {
                Case::C{old,new,..}=>json!({"v1":bincode::serialize(old).unwrap().len(),"commitment_form":bincode::serialize(new).unwrap().len()}),
                Case::Z{old,new,..}=>json!({"v1":bincode::serialize(old).unwrap().len(),"commitment_form":bincode::serialize(new).unwrap().len()}),
                Case::D{old,new,..}=>json!({"v1":bincode::serialize(old).unwrap().len(),"commitment_form":bincode::serialize(new).unwrap().len()})
            }}));
        pools.push(samples);
    }
    let cpu_start = Instant::now();
    let cpu_backend = crate::batch::backend("cpu").unwrap();
    let mut targets = vec![(
        "cpu".to_string(),
        cpu_backend,
        cpu_start.elapsed().as_secs_f64(),
    )];
    for spec in specs {
        if spec == "cpu" {
            continue;
        }
        let t = Instant::now();
        let b = crate::batch::backend(spec).unwrap();
        targets.push((spec.clone(), b, t.elapsed().as_secs_f64()));
    }
    let init: Vec<_> = targets
        .iter()
        .map(|(s, _, t)| json!({"backend":s,"initialization_seconds":t}))
        .collect();
    let mut output = Vec::new();
    for family in 0..4usize {
        for &n in sizes {
            let selected: Vec<_> = (0..n)
                .map(|i| {
                    if family == 3 {
                        (i % 3, i / 3)
                    } else {
                        (family, i)
                    }
                })
                .collect();
            let mut all = Vec::new();
            let methods: Vec<String> = ["v1-individual", "lift-individual", "secure-individual"]
                .iter()
                .map(|s| s.to_string())
                .chain(targets.iter().map(|(s, _, _)| format!("secure-batch-{s}")))
                .collect();
            for rep in 0..reps {
                let seed: [u8; 32] = rng.r#gen();
                let order: Vec<_> = (0..methods.len())
                    .map(|i| methods[(i + rep + family) % methods.len()].clone())
                    .collect();
                for method in &order {
                    let telemetry_before = method
                        .strip_prefix("secure-batch-")
                        .map(|spec| {
                            targets
                                .iter()
                                .find(|(s, _, _)| s == spec)
                                .unwrap()
                                .1
                                .telemetry()
                        })
                        .unwrap_or(Value::Null);
                    let total = Instant::now();
                    let mut decode = 0.0;
                    let mut relation = 0.0;
                    let mut accumulation = 0.0;
                    let mut msm = 0.0;
                    let mut fixed = 0.0;
                    let mut individual = 0.0;
                    let mut rows = 0;
                    let mut terms = 0;
                    let mut bitstats = Value::Null;
                    if method == "v1-individual" {
                        let t = Instant::now();
                        assert!(selected.par_iter().all(|&(f, i)| pools[f][i].2.v1(
                            &key,
                            &ht,
                            &tw,
                            &ctx,
                            ((f as u64) << 48) | i as u64,
                            &wb
                        )));
                        individual = t.elapsed().as_secs_f64();
                    } else {
                        let secure = method != "lift-individual";
                        let t = Instant::now();
                        let canonical: Vec<_> = selected
                            .par_iter()
                            .map(|&(f, i)| {
                                if secure {
                                    pools[f][i].1.canonical()
                                } else {
                                    pools[f][i].0.canonical()
                                }
                            })
                            .collect();
                        decode = t.elapsed().as_secs_f64();
                        let t = Instant::now();
                        let relations: Vec<_> = canonical
                            .par_iter()
                            .zip(&selected)
                            .map(|(c, &(f, i))| {
                                c.rels(&key, &ctx, ((f as u64) << 48) | i as u64, &wb)
                            })
                            .collect();
                        relation = t.elapsed().as_secs_f64();
                        rows = relations.iter().map(|r| r.rows.len()).sum();
                        if method.ends_with("individual") {
                            let t = Instant::now();
                            assert!(relations.par_iter().all(|r| r.check_each(&bases)));
                            individual = t.elapsed().as_secs_f64();
                        } else {
                            let t = Instant::now();
                            let acc = relations
                                .par_iter()
                                .enumerate()
                                .map(|(i, r)| {
                                    let mut random = ChaCha20Rng::from_seed(sha256(&[
                                        b"wod/t008/proof-coefficients",
                                        &seed,
                                        &(i as u64).to_be_bytes(),
                                    ]));
                                    let mut a = Acc::default();
                                    a.add(r, &mut random);
                                    a
                                })
                                .reduce(Acc::default, |mut a, b| {
                                    a.merge(b);
                                    a
                                });
                            accumulation = t.elapsed().as_secs_f64();
                            let t = Instant::now();
                            let constant = acc.fixed_part(&bases);
                            fixed = t.elapsed().as_secs_f64();
                            let spec = method.strip_prefix("secure-batch-").unwrap();
                            let b = &targets.iter().find(|(s, _, _)| s == spec).unwrap().1;
                            let t = Instant::now();
                            let sum = b.msm(&acc.pts, &acc.sc).unwrap();
                            msm = t.elapsed().as_secs_f64();
                            assert!((constant + sum).is_zero());
                            terms = acc.pts.len();
                            // Instrumentation is outside the timed verification boundary.
                            let verified_elapsed = total.elapsed().as_secs_f64();
                            let positive = acc
                                .sc
                                .iter()
                                .filter(|s| s.into_bigint().num_bits() <= 128)
                                .count();
                            let negative = acc
                                .sc
                                .iter()
                                .filter(|s| (-**s).into_bigint().num_bits() <= 128)
                                .count();
                            bitstats = json!({"unsigned_bits_le128":positive,"negative_magnitude_bits_le128":negative,"other_terms":terms-positive-negative,"max_unsigned_bits":acc.sc.iter().map(|s|s.into_bigint().num_bits()).max().unwrap_or(0),"max_min_signed_magnitude_bits":acc.sc.iter().map(|s|s.into_bigint().num_bits().min((-*s).into_bigint().num_bits())).max().unwrap_or(0)});
                            all.push(json!({"rep":rep,"method":method,"execution_order":order,"total_seconds":verified_elapsed,"canonical_decode_seconds":decode,"relation_seconds":relation,"accumulate_seconds":accumulation,"fixed_seconds":fixed,"msm_seconds":msm,"individual_seconds":individual,"relations":rows,"msm_terms":terms,"scalar_distribution":bitstats,"backend_telemetry_before":telemetry_before,"backend_telemetry_after":b.telemetry(),"accept":true}));
                            continue;
                        }
                    }
                    all.push(json!({"rep":rep,"method":method,"execution_order":order,"total_seconds":total.elapsed().as_secs_f64(),"canonical_decode_seconds":decode,"relation_seconds":relation,"accumulate_seconds":accumulation,"fixed_seconds":fixed,"msm_seconds":msm,"individual_seconds":individual,"relations":rows,"msm_terms":terms,"scalar_distribution":bitstats,"accept":true}));
                }
            }
            let summary:Vec<_>=methods.iter().map(|m|json!({"method":m,"seconds":med(all.iter().filter(|r|r["method"]==m.as_str()).map(|r|r["total_seconds"].as_f64().unwrap()).collect())})).collect();
            eprintln!(
                "mixed-proof-sweep family={} proofs={n}: PASS",
                ["csz", "zkp0", "dleq", "mixed"][family]
            );
            output.push(json!({"family":(["csz","zkp0","dleq","mixed"][family]),"proofs":n,"summary":summary,"runs":all}));
        }
    }
    json!({"scope":"Proof algebra only: validated in-memory points; no serialization/decompression/signatures/admission. V1 subgroup checks cover new received statement points (CSZ5/ZKP04/DLEQ1); setup/prior bases already validated. Individual equation checker is the reference.","reps":reps,"generation":generation,"initialization":init,"results":output,"equations_per_proof":{"csz":10,"zkp0":4,"dleq":2},"v1_variable_multiplications_per_proof":{"csz":10,"zkp0":4,"dleq":2},"received_point_counts":{"v1":[5,4,1],"commitment_form":[15,8,3]}})
}

/// Separately measures point codec/validation/cofactor-clear cost. Input is
/// already a lifted public point; every receiver explicitly validates the
/// on-curve affine representation before clear8, with exact byte consumption.
pub fn codec_bench(n: usize, reps: usize) -> Value {
    use rayon::prelude::*;
    assert!(n > 0 && reps > 0);
    let mut rng = OsRng;
    let pool: Vec<G> = (0..256).map(|_| g() * rand_scalar(&mut rng)).collect();
    let mut points: Vec<G> = (0..n).map(|i| pool[i % pool.len()]).collect();
    points
        .par_iter_mut()
        .for_each(|p| randomize_lift(p, &mut OsRng));
    let want: Vec<G> = points.par_iter().map(clear8).collect();
    let mut all = Vec::new();
    for rep in 0..reps {
        let t = Instant::now();
        let normalized = G::normalize_batch(&points);
        let normalization = t.elapsed().as_secs_f64();
        let mut modes = vec![false, true];
        if rep % 2 == 1 {
            modes.reverse();
        }
        for wide in &modes {
            let t = Instant::now();
            let bytes: Vec<Vec<u8>> = normalized
                .par_iter()
                .map(|p| {
                    let mut b = Vec::new();
                    if *wide {
                        p.serialize_uncompressed(&mut b).unwrap();
                    } else {
                        p.serialize_compressed(&mut b).unwrap();
                    }
                    b
                })
                .collect();
            let encode = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let decoded: Vec<G> = bytes
                .par_iter()
                .map(|b| {
                    let mut slice = &b[..];
                    let p = if *wide {
                        crate::group::GA::deserialize_uncompressed_unchecked(&mut slice).unwrap()
                    } else {
                        crate::group::GA::deserialize_compressed_unchecked(&mut slice).unwrap()
                    };
                    assert!(slice.is_empty() && p.is_on_curve());
                    G::from(p)
                })
                .collect();
            let decode = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let canonical: Vec<G> = decoded.par_iter().map(clear8).collect();
            let cofactor = t.elapsed().as_secs_f64();
            assert_eq!(canonical, want);
            all.push(json!({"rep":rep,"wire":if *wide {"uncompressed-affine"}else{"compressed"},"order":modes,"points":n,"bytes":bytes.iter().map(Vec::len).sum::<usize>(),"batch_normalize_seconds":normalization,"encode_seconds":encode,"decode_validate_seconds":decode,"cofactor_seconds":cofactor,"decode_and_clear_seconds":decode+cofactor,"equal":true}));
        }
    }
    json!({"scope":"Public lifted point codec only. Normalization measured once per pair and separate from encode. Canonical field parsing, exact byte length, on-curve, then clear8; subgroup checks are intentionally replaced by image decoding.","n":n,"reps":reps,"peak_rss_bytes":crate::experiment::peak_rss_bytes(),"runs":all})
}

#[cfg(test)]
mod t008_bench_tests {
    use super::*;
    #[test]
    fn heterogeneous_proof_and_codec_smoke() {
        let proofs = mixed_proof_sweep(&[1, 4], 1, &[]);
        assert_eq!(proofs["results"].as_array().unwrap().len(), 8);
        for row in proofs["results"].as_array().unwrap() {
            assert!(
                row["runs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|r| r["accept"] == true)
            );
        }
        let codec = codec_bench(16, 1);
        assert_eq!(codec["runs"][0]["bytes"], 16 * 32);
        assert_eq!(codec["runs"][1]["bytes"], 16 * 64);
        assert!(
            codec["runs"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["equal"] == true)
        );
    }
}

/// Same-election engine experiments. Full public admission/file replay is a
/// separate CLI measurement. Every fresh tally gets individual CPU replay.
pub fn secure_bench(ns: &[usize], reps: usize, names: &[String]) -> Value {
    use crate::tally::LiftPolicy;
    let (pp, keys) = committee();
    let mut output = Vec::new();
    for &n in ns {
        let (circ, inputs, want) = election(&pp, n);
        let mut runs = Vec::new();
        for rep in 0..reps {
            let order: Vec<_> = (0..names.len())
                .map(|i| names[(i + rep) % names.len()].clone())
                .collect();
            for name in &order {
                let tate = name.contains("tate");
                let (version, individual, canonical, spec) = match name.as_str() {
                    "v1-inline" => (1, false, false, "inline"),
                    "v1-tate" => (1, false, false, "cpu"),
                    "v1-tate-inline" => (1, false, false, "inline"),
                    "v5-cpu" => (5, false, false, "cpu"),
                    "v5-individual" => (5, true, false, "inline"),
                    "v6-cpu" => (6, false, false, "cpu"),
                    "v7-cpu" => (7, false, false, "cpu"),
                    "v7-individual" => (7, true, false, "inline"),
                    "v8-cpu" => (8, false, false, "cpu"),
                    "v9-cpu" => (9, false, false, "cpu"),
                    "v9-gpu" => (9, false, false, "auto:4096:0"),
                    "v5-gpu-msm" => (5, false, false, "auto-msm:4096:0"),
                    "v6-gpu-msm" => (6, false, false, "auto-msm:4096:0"),
                    "v1-cpu" => (1, false, false, "cpu"),
                    "v1-gpu" => (1, false, false, "auto:4096:0"),
                    "v1-certified" => (1, false, false, "cert:auto:4096:0"),
                    "v2-individual" => (2, true, false, "inline"),
                    "v2-cpu" => (2, false, false, "cpu"),
                    "v2-gpu" => (2, false, false, "auto:4096:0"),
                    "v3-canonical" => (3, false, true, "cpu"),
                    "v3-individual" => (3, true, false, "inline"),
                    "v3-cpu" => (3, false, false, "cpu"),
                    "v3-gpu" => (3, false, false, "auto:4096:0"),
                    "v3-gpu-msm" => (3, false, false, "auto-msm:4096:0"),
                    "v3-gpu-signed" => (3, false, false, "auto-msm-signed:4096:0"),
                    "v4-cpu" => (4, false, false, "cpu"),
                    "v4-gpu-msm" => (4, false, false, "auto-msm:4096:0"),
                    "v4-gpu-signed" => (4, false, false, "auto-msm-signed:4096:0"),
                    _ => panic!("unknown secure-bench configuration {name}"),
                };
                let init = Instant::now();
                let backend = if spec == "inline" {
                    None
                } else {
                    Some(crate::batch::backend(spec).unwrap())
                };
                let init_seconds = init.elapsed().as_secs_f64();
                let recorder = backend.clone().map(Recorder::new);
                let backend: Option<Arc<dyn MulBackend>> =
                    recorder.as_ref().map(|b| b.clone() as Arc<dyn MulBackend>);
                let cfg = |e: &mut Engine| {
                    e.select_format(version);
                    if canonical {
                        e.lift_policy = LiftPolicy::Canonical;
                    }
                    e.v2_individual = individual;
                    e.v2_coeff_fs = false;
                    e.tate = tate;
                    e.set_batch_backend(backend.clone());
                };
                let telemetry = || {
                    backend
                        .as_ref()
                        .map(|b| b.telemetry())
                        .unwrap_or(Value::Null)
                };
                eprintln!("secure-bench n={n} rep={rep} {name}: tally");
                let before = telemetry();
                let (log, tally) = tally_cfg(&pp, &keys, &circ, &inputs, &cfg);
                assert_eq!(tally["decision"], json!(want));
                let after_tally = telemetry();
                let tally_batches = recorder.as_ref().map(|r| histogram(&r.take()));
                let replay = replay_cfg(&pp, &circ, &inputs, &log, &cfg);
                assert_eq!(replay["accepted"], true);
                let after_replay = telemetry();
                let replay_batches = recorder.as_ref().map(|r| histogram(&r.take()));
                let reference = replay_cfg(&pp, &circ, &inputs, &log, &|e: &mut Engine| {
                    e.select_format(version);
                    e.v2_individual = version >= 2;
                    e.set_batch_backend(None);
                });
                assert_eq!(reference["accepted"], true);
                assert_eq!(reference["decision"], json!(want));
                assert_eq!(reference["output"], tally["output"]);
                runs.push(json!({"rep":rep,"configuration":name,"format":version,"canonical_reference":canonical,
                    "backend":spec,"execution_order":order,"initialization_seconds":init_seconds,
                    "tally":tally,"replay":replay,"independent_cpu_individual":reference,
                    "tally_batches":tally_batches,"replay_batches":replay_batches,"oracle_agrees":true,
                    "telemetry_before":before,"telemetry_after_tally":after_tally,"telemetry_after_replay":after_replay}));
            }
        }
        output.push(json!({"n":n,"threshold":circ.tau,"gates":circ.n_gates(),"runs":runs}));
    }
    json!({"scope":"Engine only, genuine encrypted inputs and trustee proofs. Setup/Groth16/admission/file IO excluded. Independent CPU individual verification outside selected timings.","reps":reps,"results":output})
}

/// Controlled real MSM backend sweep, including all packing/transfer/reduction
/// costs. Initialization and the correctness/warmup call are recorded separately.
pub fn msm_sweep(sizes: &[usize], reps: usize, specs: &[String]) -> Value {
    use ark_ff::{BigInteger, PrimeField};
    use rand::{Rng, SeedableRng};
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(20261124008);
    let tb = FixedBase::new(g());
    let max = *sizes.iter().max().unwrap();
    let points: Vec<G> = (0..max).map(|_| tb.mul(&rand_scalar(&mut rng))).collect();
    let scalars: Vec<F> = (0..max)
        .map(|i| match i % 4 {
            0 => F::from(rng.r#gen::<u128>()),
            1 => -F::from(rng.r#gen::<u128>()),
            _ => rand_scalar(&mut rng),
        })
        .collect();
    let mut targets = Vec::new();
    let mut initialization = Vec::new();
    for s in specs {
        let t = Instant::now();
        let b = crate::batch::backend(s).unwrap();
        initialization.push(json!({"backend":s,"seconds":t.elapsed().as_secs_f64()}));
        targets.push((s, b));
    }
    let mut rows = Vec::new();
    for &n in sizes {
        let (p, s) = (&points[..n], &scalars[..n]);
        let expected = crate::batch::msm_cpu(p, s);
        for (_, b) in &targets {
            assert_eq!(b.msm(p, s).unwrap(), expected);
        }
        let mut samples = Vec::new();
        for rep in 0..reps {
            let order: Vec<_> = (0..targets.len())
                .map(|i| (i + rep) % targets.len())
                .collect();
            for &idx in &order {
                let (spec, b) = &targets[idx];
                let before = b.telemetry();
                let t = Instant::now();
                let got = b.msm(p, s).unwrap();
                let elapsed = t.elapsed().as_secs_f64();
                assert_eq!(got, expected);
                samples.push(json!({"rep":rep,"backend":spec,"seconds":elapsed,"equal":true,
                    "execution_order":order.iter().map(|i|targets[*i].0).collect::<Vec<_>>(),"telemetry_before":before,"telemetry_after":b.telemetry()}));
            }
        }
        let short = s
            .iter()
            .filter(|s| s.into_bigint().num_bits() <= 128)
            .count();
        let short_negative = s
            .iter()
            .filter(|s| (-**s).into_bigint().num_bits() <= 128)
            .count();
        eprintln!("msm-sweep n={n}: all backends PASS");
        rows.push(json!({"terms":n,"unsigned_short_128":short,"negative_short_128":short_negative,"samples":samples}));
    }
    json!({"scope":"Real MSM; mixed positive128/negative128/fullwidth scalars, same bases/scalars per backend, warmup equality check outside measured repetitions.","public_input_seed":20261124008u64,"reps":reps,"initialization":initialization,"rows":rows})
}

/// T009: per-point validation costs on identical prime-order points:
/// compressed and affine decoding, `[q]P`, the order-8 Tate test and the
/// cofactor clearing `[8]Q` (single thread, so per-operation latencies).
pub fn subgroup_bench(npts: usize, reps: usize) -> Value {
    use ark_ff::Zero;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(20261124091);
    let tb = FixedBase::new(g());
    let pts: Vec<G> = (0..npts).map(|_| tb.mul(&rand_scalar(&mut rng))).collect();
    let comp: Vec<Vec<u8>> = pts
        .iter()
        .map(|p| {
            let mut v = Vec::new();
            p.serialize_compressed(&mut v).unwrap();
            v
        })
        .collect();
    let wide: Vec<Vec<u8>> = pts
        .iter()
        .map(|p| {
            let mut v = Vec::new();
            p.serialize_uncompressed(&mut v).unwrap();
            v
        })
        .collect();
    let mut rows = Vec::new();
    for rep in 0..reps {
        let mut time = |name: &str, f: &dyn Fn(usize) -> bool| {
            let t = Instant::now();
            let ok = (0..npts).all(f);
            let s = t.elapsed().as_secs_f64();
            assert!(ok, "{name}");
            rows.push(json!({"rep":rep,"op":name,"seconds":s,"us_per_point":s*1e6/npts as f64}));
        };
        time("decode_compressed", &|i| {
            G::deserialize_compressed_unchecked(&comp[i][..]).unwrap() == pts[i]
        });
        time("decode_affine_with_curve_check", &|i| {
            let p = G::deserialize_uncompressed_unchecked(&wide[i][..]).unwrap();
            on_curve_ext(&p) && p == pts[i]
        });
        time("subgroup_q_mul", &|i| in_subgroup(&pts[i]));
        time("subgroup_tate", &|i| {
            crate::subgroup::in_subgroup_tate(&pts[i])
        });
        time("cofactor_clear8", &|i| !clear8(&pts[i]).is_zero());
    }
    json!({"scope":"single thread, identical random prime-order points; decode includes equality with the original","points":npts,"reps":reps,"rows":rows})
}

/// T009 proof-level sweep for the Enc(0) family (rerandomizers): per-item
/// challenge-response ZKP0 (v1), per-item commitment-form ZKP0 in one RLC
/// MSM (v3), and one constant-size batched proof (v5 `Lin`).
pub fn lin_sweep(sizes: &[usize], reps: usize) -> Value {
    use crate::sigma::{Acc, Bases, Lin, LinStmt, Zkp0, Zkp02};
    use ark_ff::Zero;
    use rand::SeedableRng;
    use rayon::prelude::*;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(20261124092);
    let key = Key::new(g() * rand_scalar(&mut rng));
    let lk = LiftKey::new(key.h);
    let tht = FixedBase::new(h_tilde());
    let ctx = [9u8; 32];
    let max = *sizes.iter().max().unwrap();
    let rho: Vec<F> = (0..max).map(|_| rand_scalar(&mut rng)).collect();
    let cts: Vec<Ct> = rho.iter().map(|r| key.enc0(r)).collect();
    let b = Bases {
        g: &key.tg,
        h: &key.th,
        ht: &tht,
        w: None,
    };
    let mut rows = Vec::new();
    for &k in sizes {
        let (c, r) = (&cts[..k], &rho[..k]);
        let mut samples = Vec::new();
        for rep in 0..reps {
            // v1: one AND-proof per ciphertext (as in CGY: per item)
            let t = Instant::now();
            let p1: Vec<Zkp0> = (0..k)
                .into_par_iter()
                .map(|j| {
                    Zkp0::prove(
                        &key,
                        &ctx,
                        j as u64,
                        &c[j..j + 1],
                        &r[j..j + 1],
                        &mut rand::thread_rng(),
                    )
                })
                .collect();
            let tp = t.elapsed().as_secs_f64();
            let t = Instant::now();
            assert!((0..k).into_par_iter().all(|j| p1[j].verify(
                &key,
                &ctx,
                j as u64,
                &c[j..j + 1]
            )));
            let tv = t.elapsed().as_secs_f64();
            samples.push(json!({"rep":rep,"method":"zkp0-cr","prove_seconds":tp,"verify_seconds":tv,"proof_bytes":k*64}));
            // v3: commitment form, one RLC MSM
            let t = Instant::now();
            let p2: Vec<Zkp02> = (0..k)
                .into_par_iter()
                .map(|j| {
                    let p = Zkp02::prove(
                        &key,
                        &lk,
                        &ctx,
                        j as u64,
                        &c[j..j + 1],
                        &r[j..j + 1],
                        &mut rand::thread_rng(),
                    );
                    Zkp02 {
                        e: p.e.iter().map(|x| x.clear8()).collect(),
                        z: p.z,
                    }
                })
                .collect();
            let tp = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let acc = (0..k)
                .into_par_iter()
                .map(|j| {
                    let mut a = Acc::default();
                    a.add(
                        &p2[j].rels(&ctx, j as u64, &c[j..j + 1]).unwrap(),
                        &mut rand::thread_rng(),
                    );
                    a
                })
                .reduce(Acc::default, |mut a, x| {
                    a.merge(x);
                    a
                });
            assert!((acc.fixed_part(&b) + crate::batch::msm_cpu(&acc.pts, &acc.sc)).is_zero());
            let tv = t.elapsed().as_secs_f64();
            samples.push(json!({"rep":rep,"method":"zkp0-msm","prove_seconds":tp,"verify_seconds":tv,"proof_bytes":k*96,"msm_terms":acc.pts.len()}));
            // v5: one batched proof
            let st = LinStmt {
                enc: (0..k).map(|j| (j as u64, c[j])).collect(),
                dec: vec![],
            };
            let t = Instant::now();
            let mut p3 = Lin::prove(&lk, &ctx, 5, 0, &g(), &st, r, &F::from(0u64), &mut rng);
            p3.t.iter_mut().for_each(|p| *p = clear8(p));
            let tp = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let rels = p3.rels(&ctx, 5, 0, &g(), &st).unwrap();
            let mut acc = Acc::default();
            acc.add(&rels, &mut rng);
            assert!((acc.fixed_part(&b) + crate::batch::msm_cpu(&acc.pts, &acc.sc)).is_zero());
            let tv = t.elapsed().as_secs_f64();
            samples.push(json!({"rep":rep,"method":"lin","prove_seconds":tp,"verify_seconds":tv,"proof_bytes":96,"msm_terms":acc.pts.len()}));
        }
        eprintln!("lin-sweep k={k}: PASS");
        rows.push(json!({"k":k,"samples":samples}));
    }
    json!({"scope":"Enc(0) statements (one rerandomizer ciphertext each), statements given in memory (no decoding); prove/verify include hashing; zkp0-cr per-item proof; zkp0-msm per-item commitment form + one RLC MSM; lin one batched proof.","reps":reps,"seed":20261124092u64,"rows":rows})
}
