//! Micro-benchmarks of the individual operations (release build).
//! Reports the median and min/max over `iters` runs, in microseconds.

use crate::ballot;
use crate::circuit::Circuit;
use crate::group::*;
use crate::shamir;
use crate::sigma::{Csz, CszStmt, Dleq, Zkp0};
use crate::tally::{Engine, Item, Public, Trustee, run_local};
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
