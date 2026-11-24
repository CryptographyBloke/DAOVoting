//! Batched variable-base scalar multiplication for **public** verification work.
//!
//! Verifying a trustee message is dominated by independent variable-base
//! multiplications `[k]P`: subgroup checks `[q]P = 0` on every received point
//! and the 10 / 4 / 2 multiplications that recompute the commitments of each
//! PoK-CSZ / ZKP0 / DLEQ proof. [`crate::tally::Engine`] can collect them for a
//! whole board message (and the gate outputs completed by it), hand them to a
//! [`MulBackend`] as one batch, and then finish every check from the results.
//!
//! Every job contains only public transcript data (points and Fiat–Shamir
//! challenges/responses). Secret-dependent multiplications of the trustees
//! (shares, masking signs, simulation randomness) never enter a batch, so a
//! device backend never holds secrets.

use crate::group::*;
use anyhow::{Result, bail};
use ark_ff::{BigInt, BigInteger, PrimeField};
use rayon::prelude::*;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

/// One multiplication `[k]P` with `k` a plain 256-bit integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    pub p: G,
    pub k: BigInt<4>,
}

impl Job {
    pub fn mul(p: G, s: &F) -> Self {
        Job {
            p,
            k: s.into_bigint(),
        }
    }
    /// Subgroup check `[q]P`; the point is in `G` iff the result is the identity.
    pub fn subgroup(p: G) -> Self {
        Job { p, k: F::MODULUS }
    }
}

/// CPU reference evaluation: the same width-5 wNAF as [`vmul`]/[`in_subgroup`]
/// (protocol jobs have `k < 2^252`); plain double-and-add for `k >= 2^255`,
/// which the wNAF does not cover.
pub fn eval(j: &Job) -> G {
    use ark_ec::PrimeGroup;
    static Q: OnceLock<Vec<i64>> = OnceLock::new();
    if j.k == F::MODULUS {
        wnaf_mul(&j.p, Q.get_or_init(|| F::MODULUS.find_wnaf(5).unwrap()))
    } else if j.k.0[3] >> 63 != 0 {
        j.p.mul_bigint(j.k)
    } else {
        wnaf_mul(&j.p, &j.k.find_wnaf(5).unwrap())
    }
}

/// Sequential evaluation, used by the unbatched (inline) verification path.
pub fn eval_all(jobs: &[Job]) -> Vec<G> {
    jobs.iter().map(eval).collect()
}

pub trait MulBackend: Send + Sync {
    fn name(&self) -> String;
    fn run(&self, jobs: &[Job]) -> Result<Vec<G>>;
    /// Per-instance counters; avoids confusing separate GPU contexts in
    /// paired benchmarks. CPU-only backends have no device counters.
    fn telemetry(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
    /// Multi-scalar multiplication `Σ [s_i]P_i` (v2 batch verification).
    /// Default: arkworks' Pippenger on the CPU; device backends may override.
    fn msm(&self, pts: &[G], sc: &[F]) -> Result<G> {
        anyhow::ensure!(pts.len() == sc.len(), "MSM input length mismatch");
        Ok(msm_cpu(pts, sc))
    }
}

/// CPU reference MSM (arkworks Pippenger over normalised bases).
pub fn msm_cpu(pts: &[G], sc: &[F]) -> G {
    assert_eq!(pts.len(), sc.len(), "MSM input length mismatch");
    use ark_ec::{CurveGroup, VariableBaseMSM};
    if pts.is_empty() {
        return G::default();
    }
    let aff = G::normalize_batch(pts);
    G::msm(&aff, sc).expect("equal lengths")
}

/// Sequential evaluation in the calling thread (the original unbatched path).
pub struct Inline;

impl MulBackend for Inline {
    fn name(&self) -> String {
        "inline".into()
    }
    fn run(&self, jobs: &[Job]) -> Result<Vec<G>> {
        Ok(eval_all(jobs))
    }
}

/// Multi-core CPU backend (Rayon over the batch).
pub struct Cpu;

impl MulBackend for Cpu {
    fn name(&self) -> String {
        format!("cpu(rayon x{})", rayon::current_num_threads())
    }
    fn run(&self, jobs: &[Job]) -> Result<Vec<G>> {
        Ok(jobs.par_iter().map(eval).collect())
    }
}

/// Size-based dispatch: batches with at least `min_batch` jobs go to `big`
/// (e.g. a GPU), smaller ones stay on the CPU, where launch and transfer
/// overheads would dominate.
pub struct Adaptive {
    pub big: Arc<dyn MulBackend>,
    pub min_batch: usize,
}

impl MulBackend for Adaptive {
    fn telemetry(&self) -> serde_json::Value {
        self.big.telemetry()
    }
    fn name(&self) -> String {
        format!(
            "adaptive(>= {} -> {}, else cpu)",
            self.min_batch,
            self.big.name()
        )
    }
    fn run(&self, jobs: &[Job]) -> Result<Vec<G>> {
        if jobs.len() >= self.min_batch {
            self.big.run(jobs)
        } else {
            Cpu.run(jobs)
        }
    }
    fn msm(&self, pts: &[G], sc: &[F]) -> Result<G> {
        if pts.len() >= self.min_batch {
            self.big.msm(pts, sc)
        } else {
            Ok(msm_cpu(pts, sc))
        }
    }
}

/// Device MSM baseline: every term `[s_i]P_i` as a device job, summed on the
/// host. Correct for any backend; it does not use Pippenger amortisation
/// (a dedicated GPU MSM kernel is future work, T007 §13).
pub fn msm_via_jobs(b: &dyn MulBackend, pts: &[G], sc: &[F]) -> Result<G> {
    anyhow::ensure!(pts.len() == sc.len(), "MSM input length mismatch");
    let jobs: Vec<Job> = pts.iter().zip(sc).map(|(p, s)| Job::mul(*p, s)).collect();
    let result = b.run(&jobs)?;
    anyhow::ensure!(result.len() == jobs.len(), "MSM output length mismatch");
    Ok(result.into_par_iter().sum())
}

/// Certified offload (T007): accepts results of an untrusted backend `inner`
/// (e.g. a GPU) only after cheap CPU checks.
///
/// Every job `[k]P` is sent to the device as the *lifted* job `[k/8]P`.
/// * Subgroup job (`k = q`): the device returns a certificate `L = [1/8]P`;
///   the CPU accepts iff `L` is on the curve and `[8]L = P`. Since
///   `[8]E(F_p) = G`, this proves `P ∈ G` with no error probability.
/// * Proof job: the CPU forms `Q_i = [8]L_i ∈ G` (on-curve `L_i`) and checks
///   `Σ α_i Q_i = Σ (α_i k_i) P_i` with fresh `α_i ∈ [0, 2^128)` drawn after
///   the outputs are fixed (one MSM of `2N` terms).
///
/// Any failed check falls back to exact CPU recomputation of the batch, so a
/// faulty device can cause a wrong result only within the aggregate check's
/// error bound; honest results are bit-for-bit the
/// mathematical values (canonical elements of `G`, or `O` for members).
/// Proof-job bases must already be in G. The protocol establishes this through
/// subgroup certificates for received points and trusted group operations.
/// This is not a general certificate for arbitrary nonmember proof-job bases.
pub struct Certified {
    pub inner: Arc<dyn MulBackend>,
    pub stats: Mutex<CertStats>,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct CertStats {
    pub batches: u64,
    pub jobs: u64,
    pub fallbacks: u64,
    pub seconds_device: f64,
    pub seconds_check: f64,
    pub seconds_msm: f64,
    pub seconds_fallback: f64,
}

impl Certified {
    pub fn new(inner: Arc<dyn MulBackend>) -> Arc<Self> {
        Arc::new(Certified {
            inner,
            stats: Mutex::new(CertStats::default()),
        })
    }

    /// Checks device outputs `l` for `jobs`; returns the certified results.
    pub fn check(jobs: &[Job], l: &[G]) -> Option<Vec<G>> {
        Self::check_timed(jobs, l, &mut 0.0)
    }

    fn check_timed(jobs: &[Job], l: &[G], msm_seconds: &mut f64) -> Option<Vec<G>> {
        use ark_ff::Zero;
        // A simulated or hostile device can construct Fp internals directly.
        // Establish their range before invoking the curve equations.
        let valid =
            |p: &G| [p.x, p.y, p.t, p.z].iter().all(|f| f.0 < Fb::MODULUS) && on_curve_ext(p);
        if l.len() != jobs.len() || !l.par_iter().all(valid) {
            return None;
        }
        let q: Vec<G> = l.par_iter().map(clear8).collect();
        // subgroup certificates: [8]L == P
        let mut proof_idx = Vec::new();
        for (i, j) in jobs.iter().enumerate() {
            if j.k == F::MODULUS {
                if q[i] != j.p {
                    return None;
                }
            } else {
                proof_idx.push(i);
            }
        }
        if !proof_idx.is_empty() {
            let mut pts = Vec::with_capacity(2 * proof_idx.len());
            let mut sc = Vec::with_capacity(2 * proof_idx.len());
            for &i in &proof_idx {
                let a = F::from(rand::random::<u128>());
                pts.push(q[i]);
                sc.push(a);
                pts.push(-jobs[i].p);
                sc.push(a * F::from_le_bytes_mod_order(&jobs[i].k.to_bytes_le()));
            }
            let t = Instant::now();
            let sum = msm_cpu(&pts, &sc);
            *msm_seconds += t.elapsed().as_secs_f64();
            if !sum.is_zero() {
                return None;
            }
        }
        Some(
            jobs.iter()
                .zip(q)
                .map(|(j, x)| if j.k == F::MODULUS { G::default() } else { x })
                .collect(),
        )
    }
}

impl MulBackend for Certified {
    fn telemetry(&self) -> serde_json::Value {
        serde_json::json!({"cert": *self.stats.lock().unwrap(), "inner": self.inner.telemetry()})
    }
    fn name(&self) -> String {
        format!("certified({})", self.inner.name())
    }
    fn run(&self, jobs: &[Job]) -> Result<Vec<G>> {
        // reduce proof scalars mod q (protocol scalars already are) so the
        // aggregate check is over Z_q; k = q marks a subgroup job
        let lifted: Vec<Job> = jobs
            .iter()
            .map(|j| {
                let k = if j.k == F::MODULUS {
                    inv8()
                } else {
                    F::from_le_bytes_mod_order(&j.k.to_bytes_le()) * inv8()
                };
                Job::mul(j.p, &k)
            })
            .collect();
        let t = Instant::now();
        let out = self.inner.run(&lifted);
        let td = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let mut msm_seconds = 0.0;
        let checked = out
            .ok()
            .and_then(|l| Self::check_timed(jobs, &l, &mut msm_seconds));
        let check_seconds = t.elapsed().as_secs_f64();
        let mut st = self.stats.lock().unwrap();
        st.batches += 1;
        st.jobs += jobs.len() as u64;
        st.seconds_device += td;
        st.seconds_check += check_seconds;
        st.seconds_msm += msm_seconds;
        let r = match checked {
            Some(r) => r,
            None => {
                st.fallbacks += 1;
                let t = Instant::now();
                let result = Cpu.run(jobs)?;
                st.seconds_fallback += t.elapsed().as_secs_f64();
                result
            }
        };
        Ok(r)
    }
    fn msm(&self, pts: &[G], sc: &[F]) -> Result<G> {
        Ok(msm_cpu(pts, sc))
    }
}

/// Per-batch record: number of jobs, seconds spent in the backend.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct BatchRecord {
    pub jobs: usize,
    pub seconds: f64,
}

/// Wraps a backend and records every batch (for batch-size histograms).
pub struct Recorder {
    pub inner: Arc<dyn MulBackend>,
    pub log: Mutex<Vec<BatchRecord>>,
}

impl Recorder {
    pub fn new(inner: Arc<dyn MulBackend>) -> Arc<Self> {
        Arc::new(Recorder {
            inner,
            log: Mutex::new(Vec::new()),
        })
    }
    pub fn take(&self) -> Vec<BatchRecord> {
        std::mem::take(&mut self.log.lock().unwrap())
    }
}

impl MulBackend for Recorder {
    fn telemetry(&self) -> serde_json::Value {
        self.inner.telemetry()
    }
    fn name(&self) -> String {
        self.inner.name()
    }
    fn run(&self, jobs: &[Job]) -> Result<Vec<G>> {
        let t = Instant::now();
        let r = self.inner.run(jobs)?;
        let rec = BatchRecord {
            jobs: jobs.len(),
            seconds: t.elapsed().as_secs_f64(),
        };
        self.log.lock().unwrap().push(rec);
        Ok(r)
    }
}

/// Process-wide default used by every [`crate::tally::Engine`] at
/// construction: `None` (original inline verification) unless the
/// `WOD_VERIFY_BACKEND` environment variable — set by the CLI flag
/// `--verify-backend SPEC` and inherited by trustee/verifier subprocesses —
/// names a backend.
pub fn default_backend() -> Option<Arc<dyn MulBackend>> {
    static D: OnceLock<Option<Arc<dyn MulBackend>>> = OnceLock::new();
    D.get_or_init(|| {
        let spec = std::env::var("WOD_VERIFY_BACKEND")
            .ok()
            .filter(|s| !s.is_empty() && s != "inline")?;
        Some(backend(&spec).unwrap_or_else(|e| panic!("WOD_VERIFY_BACKEND={spec}: {e:#}")))
    })
    .clone()
}

/// Name of the default backend (`inline` when unbatched).
pub fn default_name() -> String {
    default_backend()
        .map(|b| b.name())
        .unwrap_or_else(|| "inline".into())
}

pub fn default_telemetry() -> serde_json::Value {
    default_backend()
        .map(|b| b.telemetry())
        .unwrap_or(serde_json::Value::Null)
}

/// Backend from a CLI spec: `cpu`, `cuda[:DEVICE]`, `emu`, or
/// `auto:MIN_BATCH[:DEVICE]` (CUDA for batches >= MIN_BATCH, CPU otherwise).
#[cfg(feature = "gpu")]
struct LazyCuda {
    device: usize,
    pippenger: bool,
    inner: OnceLock<std::result::Result<Arc<crate::gpu::Cuda>, String>>,
}

#[cfg(feature = "gpu")]
impl MulBackend for LazyCuda {
    fn telemetry(&self) -> serde_json::Value {
        match self.inner.get() {
            Some(Ok(b)) => b.telemetry(),
            _ => serde_json::Value::Null,
        }
    }
    fn name(&self) -> String {
        match self.inner.get() {
            Some(Ok(b)) if self.pippenger => format!("{} + GPU Pippenger", b.name()),
            Some(Ok(b)) => b.name(),
            _ => format!(
                "lazy-cuda(device {}, pippenger {})",
                self.device, self.pippenger
            ),
        }
    }
    fn run(&self, jobs: &[Job]) -> Result<Vec<G>> {
        let b = self.inner.get_or_init(|| {
            crate::gpu::Cuda::new(self.device)
                .map(Arc::new)
                .map_err(|e| format!("{e:#}"))
        });
        match b {
            Ok(b) => b.run(jobs),
            Err(e) => bail!("CUDA initialization: {e}"),
        }
    }
    fn msm(&self, pts: &[G], sc: &[F]) -> Result<G> {
        if self.pippenger {
            let b = self.inner.get_or_init(|| {
                crate::gpu::Cuda::new(self.device)
                    .map(Arc::new)
                    .map_err(|e| format!("{e:#}"))
            });
            match b {
                Ok(b) => b.run_msm(pts, sc),
                Err(e) => bail!("CUDA initialization: {e}"),
            }
        } else {
            msm_via_jobs(self, pts, sc)
        }
    }
}

fn adaptive_cuda(device: usize, pippenger: bool) -> Result<Arc<dyn MulBackend>> {
    #[cfg(feature = "gpu")]
    {
        Ok(Arc::new(LazyCuda {
            device,
            pippenger,
            inner: OnceLock::new(),
        }))
    }
    #[cfg(not(feature = "gpu"))]
    {
        let _ = pippenger;
        cuda(device)
    }
}

pub fn backend(spec: &str) -> Result<Arc<dyn MulBackend>> {
    let parts: Vec<&str> = spec.split(':').collect();
    let dev = |i: usize| parts.get(i).map(|d| d.parse::<usize>()).transpose();
    Ok(match parts[0] {
        "cpu" => Arc::new(Cpu),
        "cuda" => cuda(dev(1)?.unwrap_or(0))?,
        "cuda-msm" => cuda_msm(dev(1)?.unwrap_or(0))?,
        "auto" | "auto-msm" => {
            let min_batch = parts
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("auto:MIN_BATCH"))?
                .parse()?;
            Arc::new(Adaptive {
                big: adaptive_cuda(dev(2)?.unwrap_or(0), parts[0] == "auto-msm")?,
                min_batch,
            })
        }
        "emu" => emu()?,
        "cert" => {
            let rest = spec.split_once(':').map(|x| x.1).unwrap_or("cpu");
            Certified::new(backend(rest)?)
        }
        _ => bail!(
            "unknown verification backend `{spec}` (cpu | cuda[:dev] | cuda-msm[:dev] | auto:N[:dev] | auto-msm:N[:dev] | emu | cert:<backend>)"
        ),
    })
}

#[cfg(feature = "gpu")]
fn cuda_msm(dev: usize) -> Result<Arc<dyn MulBackend>> {
    Ok(Arc::new(crate::gpu::CudaMsm::new(dev)?))
}
#[cfg(not(feature = "gpu"))]
fn cuda_msm(dev: usize) -> Result<Arc<dyn MulBackend>> {
    cuda(dev)
}

#[cfg(feature = "gpu")]
fn cuda(dev: usize) -> Result<Arc<dyn MulBackend>> {
    Ok(Arc::new(crate::gpu::Cuda::new(dev)?))
}
#[cfg(not(feature = "gpu"))]
fn cuda(_dev: usize) -> Result<Arc<dyn MulBackend>> {
    bail!(
        "this binary was built without CUDA support (cargo build --release --features cuda, or cuda13 for a CUDA 13 toolkit)"
    )
}

#[cfg(feature = "cuda-emu")]
fn emu() -> Result<Arc<dyn MulBackend>> {
    Ok(Arc::new(crate::gpu::Emu))
}
#[cfg(not(feature = "cuda-emu"))]
fn emu() -> Result<Arc<dyn MulBackend>> {
    bail!("this binary was built without the `cuda-emu` feature")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use rand::thread_rng;

    #[cfg(feature = "gpu")]
    #[test]
    fn adaptive_small_batch_does_not_initialize_cuda() {
        let b = backend(&format!("auto:{}:{}", usize::MAX, usize::MAX)).unwrap();
        let jobs = [Job::mul(g(), &F::from(2u64))];
        assert_eq!(b.run(&jobs).unwrap(), Cpu.run(&jobs).unwrap());
        assert!(b.name().contains("lazy-cuda"));
    }

    #[test]
    fn cpu_backend_matches_reference_ops() {
        let mut rng = thread_rng();
        let pts: Vec<G> = (0..64).map(|_| g() * rand_scalar(&mut rng)).collect();
        let ks: Vec<F> = (0..64).map(|_| rand_scalar(&mut rng)).collect();
        let mut jobs: Vec<Job> = pts.iter().zip(&ks).map(|(p, k)| Job::mul(*p, k)).collect();
        jobs.extend(pts.iter().map(|p| Job::subgroup(*p)));
        let r = Cpu.run(&jobs).unwrap();
        for i in 0..64 {
            assert_eq!(r[i], pts[i] * ks[i]);
            assert!(r[64 + i].is_zero());
        }
        assert_eq!(r, eval_all(&jobs));
    }

    /// Every intended job uses a valid subgroup base; each fault is isolated.
    struct Faulty(u8);
    impl MulBackend for Faulty {
        fn name(&self) -> String {
            "faulty".into()
        }
        fn run(&self, jobs: &[Job]) -> Result<Vec<G>> {
            let mut r = Cpu.run(jobs)?;
            let t2: G =
                ark_ed_on_bn254::EdwardsAffine::new_unchecked(Fb::from(0u64), -Fb::from(1u64))
                    .into();
            match self.0 {
                0 => r[0] += g(),
                1 => r.iter_mut().for_each(|p| *p += t2), // equivalent lifts
                2 => r[1] = G::default(),                 // wrong certificate of valid nonzero base
                3 => {
                    r[0] = G::new_unchecked(
                        Fb::from(1u64),
                        Fb::from(2u64),
                        Fb::from(3u64),
                        Fb::from(4u64),
                    )
                }
                4 => {
                    r.pop();
                }
                5 => r.push(G::default()),
                6 => r[0].z = Fb::from(0u64),
                7 => r[0].x = ark_ff::Fp(Fb::MODULUS, core::marker::PhantomData),
                _ => bail!("device failure"),
            }
            Ok(r)
        }
    }

    #[test]
    fn certified_offload_detects_faulty_devices() {
        let p = g() * F::from(17u64);
        let jobs = vec![
            Job::mul(p, &F::from(9u64)),
            Job::subgroup(p),
            Job::mul(g(), &F::from(3u64)),
        ];
        let want = Cpu.run(&jobs).unwrap();
        let honest = Certified::new(Arc::new(Cpu));
        assert_eq!(honest.run(&jobs).unwrap(), want);
        assert_eq!(honest.stats.lock().unwrap().fallbacks, 0);
        for mode in [0, 2, 3, 4, 5, 6, 7, 8] {
            let c = Certified::new(Arc::new(Faulty(mode)));
            assert_eq!(c.run(&jobs).unwrap(), want, "mode {mode}");
            assert_eq!(c.stats.lock().unwrap().fallbacks, 1, "mode {mode}");
        }
        // Adding torsion changes the representation, not the decoded product.
        let c = Certified::new(Arc::new(Faulty(1)));
        assert_eq!(c.run(&jobs).unwrap(), want);
        assert_eq!(c.stats.lock().unwrap().fallbacks, 0);
    }

    #[test]
    fn certified_nonmember_subgroup_job_falls_back_exactly() {
        let t2: G =
            ark_ed_on_bn254::EdwardsAffine::new_unchecked(Fb::from(0u64), -Fb::from(1u64)).into();
        let jobs = vec![Job::subgroup(g() + t2)];
        let c = Certified::new(Arc::new(Cpu));
        assert_eq!(c.run(&jobs).unwrap(), Cpu.run(&jobs).unwrap());
        assert!(!c.run(&jobs).unwrap()[0].is_zero());
        assert_eq!(c.stats.lock().unwrap().fallbacks, 2);
    }

    #[test]
    fn certified_raw_scalar_boundaries_are_reduced_not_zeroed() {
        let mut qp1 = F::MODULUS;
        qp1.add_with_carry(&BigInt::from(1u64));
        let jobs: Vec<Job> = [BigInt::from(0u64), qp1, BigInt([u64::MAX; 4])]
            .into_iter()
            .map(|k| Job {
                p: g() * F::from(7u64),
                k,
            })
            .collect();
        let c = Certified::new(Arc::new(Cpu));
        assert_eq!(c.run(&jobs).unwrap(), Cpu.run(&jobs).unwrap());
        assert_eq!(c.stats.lock().unwrap().fallbacks, 0);
    }

    #[test]
    fn msm_job_lengths_are_checked() {
        assert!(msm_via_jobs(&Cpu, &[g()], &[]).is_err());
        assert!(msm_via_jobs(&Faulty(4), &[g()], &[F::from(1u64)]).is_err());
        assert!(msm_via_jobs(&Faulty(5), &[g()], &[F::from(1u64)]).is_err());
    }
}
