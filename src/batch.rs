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

/// Backend from a CLI spec: `cpu`, `cuda[:DEVICE]`, `emu`, or
/// `auto:MIN_BATCH[:DEVICE]` (CUDA for batches >= MIN_BATCH, CPU otherwise).
#[cfg(feature = "gpu")]
struct LazyCuda {
    device: usize,
    inner: OnceLock<std::result::Result<Arc<crate::gpu::Cuda>, String>>,
}

#[cfg(feature = "gpu")]
impl MulBackend for LazyCuda {
    fn name(&self) -> String {
        match self.inner.get() {
            Some(Ok(b)) => b.name(),
            _ => format!("lazy-cuda(device {})", self.device),
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
}

fn adaptive_cuda(device: usize) -> Result<Arc<dyn MulBackend>> {
    #[cfg(feature = "gpu")]
    {
        Ok(Arc::new(LazyCuda {
            device,
            inner: OnceLock::new(),
        }))
    }
    #[cfg(not(feature = "gpu"))]
    {
        cuda(device)
    }
}

pub fn backend(spec: &str) -> Result<Arc<dyn MulBackend>> {
    let parts: Vec<&str> = spec.split(':').collect();
    let dev = |i: usize| parts.get(i).map(|d| d.parse::<usize>()).transpose();
    Ok(match parts[0] {
        "cpu" => Arc::new(Cpu),
        "cuda" => cuda(dev(1)?.unwrap_or(0))?,
        "auto" => {
            let min_batch = parts
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("auto:MIN_BATCH"))?
                .parse()?;
            Arc::new(Adaptive {
                big: adaptive_cuda(dev(2)?.unwrap_or(0))?,
                min_batch,
            })
        }
        "emu" => emu()?,
        _ => bail!("unknown verification backend `{spec}` (cpu | cuda[:dev] | auto:N[:dev] | emu)"),
    })
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
}
