//! GPU backend for [`crate::batch`]: BabyJubjub scalar multiplication on CUDA.
//!
//! The kernel (`src/gpu/bjj.cu`) is embedded as source and compiled at run
//! time by NVRTC for the detected device (`compute_XY`), then launched through
//! the CUDA driver API via `cudarc` with dynamic loading, so building needs no
//! CUDA toolkit. Points are transferred in arkworks' own Montgomery limb
//! layout (no conversion); one thread evaluates one job.
//!
//! * feature `cuda` / `cuda13`: [`Cuda`] backend (needs an NVIDIA driver and
//!   the NVRTC library of a CUDA 12.x / 13.x toolkit at run time),
//! * feature `cuda-emu`: [`Emu`] backend, the *same kernel source* compiled as
//!   host C++, used to test the arithmetic without a GPU.

use crate::batch::Job;
#[cfg(any(feature = "gpu", feature = "cuda-emu"))]
use crate::batch::MulBackend;
use crate::group::*;
use ark_ff::{BigInt, Fp, PrimeField};
use rayon::prelude::*;

/// Per-process cumulative device timings. Kernel intervals include launch and
/// host synchronization; they are not CUDA-event-only device durations.
pub fn device_snapshot() -> Option<serde_json::Value> {
    #[cfg(feature = "gpu")]
    if let Some(c) = last_cuda() {
        return Some(serde_json::json!({"device": c.device,
            "compile_seconds": c.compile_seconds, "times": *c.times.lock().unwrap()}));
    }
    None
}

pub const KERNEL_SRC: &str = include_str!("gpu/bjj.cu");
/// u32 words per point (X, Y, T, Z) and per scalar.
pub const PT_WORDS: usize = 32;
pub const K_WORDS: usize = 8;

/// Signed-magnitude recoding is valid only for prime-order bases: qP = O
/// implies [q-k]P = -[k]P. It is NOT an equivalent integer operation on the
/// whole cofactor curve. V3/V4 relation bases satisfy this via image decoding.
#[cfg(any(feature = "gpu", test))]
fn msm_jobs(points: &[G], scalars: &[F], signed: bool) -> Vec<Job> {
    debug_assert_eq!(points.len(), scalars.len());
    points
        .par_iter()
        .zip(scalars)
        .map(|(p, s)| {
            let k = s.into_bigint();
            if signed {
                let negative = (-*s).into_bigint();
                if negative < k {
                    return Job {
                        p: -*p,
                        k: negative,
                    };
                }
            }
            Job { p: *p, k }
        })
        .collect()
}

fn fe_words(f: &Fb, out: &mut [u32]) {
    for (j, l) in f.0.0.iter().enumerate() {
        out[2 * j] = *l as u32;
        out[2 * j + 1] = (*l >> 32) as u32;
    }
}

fn fe_from(w: &[u32]) -> anyhow::Result<Fb> {
    anyhow::ensure!(w.len() == 8, "invalid field word count");
    let mut l = [0u64; 4];
    for j in 0..4 {
        l[j] = w[2 * j] as u64 | ((w[2 * j + 1] as u64) << 32);
    }
    let raw = BigInt(l);
    // These are Montgomery residues, not canonical integers to convert with
    // from_bigint. Validate the internal representative before any arithmetic.
    anyhow::ensure!(raw < Fb::MODULUS, "noncanonical device field residue");
    Ok(Fp(raw, core::marker::PhantomData))
}

/// Packs jobs into the kernel's input layout (points, scalars).
pub fn pack(jobs: &[Job]) -> (Vec<u32>, Vec<u32>) {
    let mut pts = vec![0u32; jobs.len() * PT_WORDS];
    let mut ks = vec![0u32; jobs.len() * K_WORDS];
    pts.par_chunks_mut(PT_WORDS)
        .zip(ks.par_chunks_mut(K_WORDS))
        .zip(jobs.par_iter())
        .for_each(|((p, k), j)| {
            for (i, f) in [j.p.x, j.p.y, j.p.t, j.p.z].iter().enumerate() {
                fe_words(f, &mut p[8 * i..8 * i + 8]);
            }
            for (i, l) in j.k.0.iter().enumerate() {
                k[2 * i] = *l as u32;
                k[2 * i + 1] = (*l >> 32) as u32;
            }
        });
    (pts, ks)
}

/// Unpacks kernel outputs into arkworks projective points.
pub fn unpack(out: &[u32]) -> anyhow::Result<Vec<G>> {
    anyhow::ensure!(out.len() % PT_WORDS == 0, "truncated device point");
    out.par_chunks(PT_WORDS)
        .map(|w| {
            let p = G::new_unchecked(
                fe_from(&w[0..8])?,
                fe_from(&w[8..16])?,
                fe_from(&w[16..24])?,
                fe_from(&w[24..32])?,
            );
            anyhow::ensure!(on_curve_ext(&p), "invalid extended device point");
            Ok(p)
        })
        .collect()
}

/// Cumulative timing breakdown of a device backend (seconds).
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct DeviceTimes {
    pub pack: f64,
    pub h2d: f64,
    pub kernel: f64,
    pub d2h: f64,
    pub unpack: f64,
    pub batches: u64,
    pub jobs: u64,
    pub msm_calls: u64,
    pub msm_terms: u64,
    pub msm_scatter: f64,
    pub msm_buckets: f64,
    pub msm_reduce: f64,
    pub msm_combine: f64,
    pub msm_peak_buffers_bytes: u64,
    pub msm_window: u32,
    pub msm_signed_calls: u64,
    pub msm_negated_terms: u64,
    pub msm_short_terms: u64,
}

#[cfg(feature = "cuda-emu")]
unsafe extern "C" {
    fn bjj_mul_host(pts: *const u32, ks: *const u32, out: *mut u32, n: u32);
}

/// The CUDA kernel source compiled as host C++ (feature `cuda-emu`).
#[cfg(feature = "cuda-emu")]
pub struct Emu;

#[cfg(feature = "cuda-emu")]
impl MulBackend for Emu {
    fn name(&self) -> String {
        "emu(bjj.cu as host C++)".into()
    }
    fn msm(&self, pts: &[G], sc: &[crate::group::F]) -> anyhow::Result<G> {
        crate::batch::msm_via_jobs(self, pts, sc)
    }
    fn run(&self, jobs: &[Job]) -> anyhow::Result<Vec<G>> {
        let (pts, ks) = pack(jobs);
        let mut out = vec![0u32; jobs.len() * PT_WORDS];
        const CH: usize = 16;
        out.par_chunks_mut(CH * PT_WORDS)
            .zip(
                pts.par_chunks(CH * PT_WORDS)
                    .zip(ks.par_chunks(CH * K_WORDS)),
            )
            .for_each(|(o, (p, k))| unsafe {
                bjj_mul_host(
                    p.as_ptr(),
                    k.as_ptr(),
                    o.as_mut_ptr(),
                    (o.len() / PT_WORDS) as u32,
                )
            });
        unpack(&out)
    }
}

#[cfg(feature = "gpu")]
pub use cuda::{Cuda, CudaMsm, last_cuda};

#[cfg(feature = "gpu")]
mod cuda {
    use super::*;
    use anyhow::{Context, Result};
    use cudarc::driver::{CudaContext, CudaFunction, CudaStream, LaunchConfig, PushKernelArg};
    use cudarc::nvrtc::{CompileOptions, compile_ptx_with_opts};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// Largest batch sent in one launch (bounds device memory: 288 B/job).
    const MAX_CHUNK: usize = 1 << 20;

    static LAST: std::sync::Mutex<Option<Arc<CudaInfo>>> = std::sync::Mutex::new(None);

    /// Device description and cumulative timings of the most recently created
    /// [`Cuda`] backend (for reports).
    pub struct CudaInfo {
        pub device: String,
        pub compute_capability: (i32, i32),
        pub total_mem: usize,
        pub compile_seconds: f64,
        pub times: Mutex<DeviceTimes>,
    }

    pub fn last_cuda() -> Option<Arc<CudaInfo>> {
        LAST.lock().unwrap().clone()
    }

    pub struct Cuda {
        stream: Arc<CudaStream>,
        func: CudaFunction,
        scatter: CudaFunction,
        buckets: CudaFunction,
        reduce: CudaFunction,
        block: u32,
        pub info: Arc<CudaInfo>,
        lock: Mutex<()>,
    }

    impl Cuda {
        pub fn new(dev: usize) -> Result<Self> {
            // cudarc panics on a missing library; probe first for a clean error
            anyhow::ensure!(
                unsafe { cudarc::driver::sys::is_culib_present() },
                "NVIDIA driver library (nvcuda.dll / libcuda.so) not found: no usable GPU on this machine"
            );
            anyhow::ensure!(
                unsafe { cudarc::nvrtc::sys::is_culib_present() },
                "NVRTC library not found (install the CUDA toolkit matching the build feature: cuda = 12.x, cuda13 = 13.x, and put its bin/lib directory on PATH / LD_LIBRARY_PATH)"
            );
            let ctx = CudaContext::new(dev).context("CUDA driver / device not available")?;
            let cc = ctx.compute_capability()?;
            let arch: &'static str =
                Box::leak(format!("compute_{}{}", cc.0, cc.1).into_boxed_str());
            let t = Instant::now();
            let opts = CompileOptions {
                arch: Some(arch),
                name: Some("bjj.cu".into()),
                ..Default::default()
            };
            let ptx = compile_ptx_with_opts(KERNEL_SRC, opts)
                .context("NVRTC compilation of bjj.cu failed")?;
            let module = ctx.load_module(ptx)?;
            let func = module.load_function("bjj_mul")?;
            let scatter = module.load_function("bjj_msm_scatter")?;
            let buckets = module.load_function("bjj_msm_buckets")?;
            let reduce = module.load_function("bjj_msm_reduce")?;
            let compile_seconds = t.elapsed().as_secs_f64();
            let block = std::env::var("WOD_CUDA_BLOCK")
                .ok()
                .and_then(|b| b.parse().ok())
                .unwrap_or(128);
            let info = Arc::new(CudaInfo {
                device: ctx.name()?,
                compute_capability: cc,
                total_mem: ctx.total_mem()?,
                compile_seconds,
                times: Mutex::new(DeviceTimes::default()),
            });
            *LAST.lock().unwrap() = Some(info.clone());
            Ok(Cuda {
                stream: ctx.default_stream(),
                func,
                scatter,
                buckets,
                reduce,
                block,
                info,
                lock: Mutex::new(()),
            })
        }

        fn run_chunk(&self, jobs: &[Job], tm: &mut DeviceTimes) -> Result<Vec<G>> {
            let n = jobs.len();
            let t = Instant::now();
            let (pts, ks) = pack(jobs);
            tm.pack += t.elapsed().as_secs_f64();
            let t = Instant::now();
            let d_pts = self.stream.clone_htod(&pts)?;
            let d_ks = self.stream.clone_htod(&ks)?;
            let mut d_out = self.stream.alloc_zeros::<u32>(n * PT_WORDS)?;
            self.stream.synchronize()?;
            tm.h2d += t.elapsed().as_secs_f64();
            let t = Instant::now();
            let cfg = LaunchConfig {
                grid_dim: ((n as u32).div_ceil(self.block), 1, 1),
                block_dim: (self.block, 1, 1),
                shared_mem_bytes: 0,
            };
            let n32 = n as u32;
            let mut b = self.stream.launch_builder(&self.func);
            b.arg(&d_pts).arg(&d_ks).arg(&mut d_out).arg(&n32);
            unsafe { b.launch(cfg) }?;
            self.stream.synchronize()?;
            tm.kernel += t.elapsed().as_secs_f64();
            let t = Instant::now();
            let out: Vec<u32> = self.stream.clone_dtoh(&d_out)?;
            tm.d2h += t.elapsed().as_secs_f64();
            let t = Instant::now();
            let r = unpack(&out)?;
            tm.unpack += t.elapsed().as_secs_f64();
            Ok(r)
        }

        /// Unsigned-window GPU Pippenger with linked-list buckets. Scalars are
        /// their canonical integers; no subgroup-dependent sign rewriting.
        pub fn run_msm(&self, points: &[G], scalars: &[F]) -> Result<G> {
            self.run_msm_impl(points, scalars, false)
        }

        /// Signed-magnitude variant. Every base MUST be in the q-order group;
        /// this precondition is established by V3/V4 image decoding, not by
        /// this backend. Scalar Job::run and unsigned run_msm keep full-curve
        /// integer semantics and remain the reference for arbitrary torsion.
        pub fn run_msm_signed(&self, points: &[G], scalars: &[F]) -> Result<G> {
            self.run_msm_impl(points, scalars, true)
        }

        fn run_msm_impl(&self, points: &[G], scalars: &[F], signed: bool) -> Result<G> {
            use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
            anyhow::ensure!(points.len() == scalars.len(), "MSM input length mismatch");
            if points.is_empty() {
                return Ok(G::default());
            }
            anyhow::ensure!(
                points.len() <= MAX_CHUNK,
                "GPU MSM prototype limited to 2^20 terms"
            );
            let width: u32 = std::env::var("WOD_MSM_WINDOW")
                .unwrap_or_else(|_| "8".into())
                .parse()?;
            anyhow::ensure!((4..=8).contains(&width), "MSM window must be in 4..=8");
            let _guard = self.lock.lock().unwrap();
            let mut tm = DeviceTimes::default();
            let t = Instant::now();
            let jobs = msm_jobs(points, scalars, signed);
            let bits = jobs.iter().map(|j| j.k.num_bits()).max().unwrap();
            if bits == 0 {
                return Ok(G::default());
            }
            let windows = bits.div_ceil(width);
            let count = 1usize << width;
            let n = points.len();
            let negated = if signed {
                jobs.iter()
                    .zip(scalars)
                    .filter(|(j, s)| j.k != s.into_bigint())
                    .count()
            } else {
                0
            };
            let short = jobs.iter().filter(|j| j.k.num_bits() <= 128).count();
            let (pts, ks) = pack(&jobs);
            tm.pack = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let d_pts = self.stream.clone_htod(&pts)?;
            let d_ks = self.stream.clone_htod(&ks)?;
            let mut heads = self
                .stream
                .clone_htod(&vec![-1i32; windows as usize * count])?;
            let mut next = self.stream.alloc_zeros::<i32>(windows as usize * n)?;
            let mut sums = self
                .stream
                .alloc_zeros::<u32>(windows as usize * count * PT_WORDS)?;
            let mut out = self
                .stream
                .alloc_zeros::<u32>(windows as usize * PT_WORDS)?;
            self.stream.synchronize()?;
            tm.h2d = t.elapsed().as_secs_f64();
            let n32 = n as u32;
            let cfg = |items: u32| LaunchConfig {
                grid_dim: (items.div_ceil(128), 1, 1),
                block_dim: (128, 1, 1),
                shared_mem_bytes: 0,
            };
            let t = Instant::now();
            let mut b = self.stream.launch_builder(&self.scatter);
            b.arg(&d_ks)
                .arg(&mut heads)
                .arg(&mut next)
                .arg(&n32)
                .arg(&width)
                .arg(&windows);
            unsafe { b.launch(cfg(n32 * windows)) }?;
            self.stream.synchronize()?;
            tm.msm_scatter = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let mut b = self.stream.launch_builder(&self.buckets);
            b.arg(&d_pts)
                .arg(&heads)
                .arg(&next)
                .arg(&mut sums)
                .arg(&n32)
                .arg(&width)
                .arg(&windows);
            unsafe { b.launch(cfg(windows * count as u32)) }?;
            self.stream.synchronize()?;
            tm.msm_buckets = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let mut b = self.stream.launch_builder(&self.reduce);
            b.arg(&sums).arg(&mut out).arg(&width);
            unsafe {
                b.launch(LaunchConfig {
                    grid_dim: (windows, 1, 1),
                    block_dim: (256, 1, 1),
                    shared_mem_bytes: 0,
                })
            }?;
            self.stream.synchronize()?;
            tm.msm_reduce = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let words: Vec<u32> = self.stream.clone_dtoh(&out)?;
            tm.d2h = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let window_sums = unpack(&words)?;
            anyhow::ensure!(
                window_sums.len() == windows as usize,
                "MSM window output length mismatch"
            );
            tm.unpack = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let mut result = G::default();
            for p in window_sums.iter().rev() {
                for _ in 0..width {
                    result.double_in_place();
                }
                result += p;
            }
            tm.msm_combine = t.elapsed().as_secs_f64();
            let mut all = self.info.times.lock().unwrap();
            all.pack += tm.pack;
            all.h2d += tm.h2d;
            all.d2h += tm.d2h;
            all.unpack += tm.unpack;
            all.kernel += tm.msm_scatter + tm.msm_buckets + tm.msm_reduce;
            all.msm_calls += 1;
            all.msm_terms += n as u64;
            all.msm_scatter += tm.msm_scatter;
            all.msm_buckets += tm.msm_buckets;
            all.msm_reduce += tm.msm_reduce;
            all.msm_combine += tm.msm_combine;
            all.msm_window = width;
            all.msm_signed_calls += u64::from(signed);
            all.msm_negated_terms += negated as u64;
            all.msm_short_terms += short as u64;
            let bytes =
                160 * n + 4 * windows as usize * (n + count) + 128 * windows as usize * (count + 1);
            all.msm_peak_buffers_bytes = all.msm_peak_buffers_bytes.max(bytes as u64);
            Ok(result)
        }
    }

    /// Selectable genuine GPU MSM; scalar-product API remains bjj_mul.
    pub struct CudaMsm(pub Cuda, bool);
    impl CudaMsm {
        pub fn new(dev: usize) -> Result<Self> {
            Ok(Self(Cuda::new(dev)?, false))
        }
        pub fn new_signed(dev: usize) -> Result<Self> {
            Ok(Self(Cuda::new(dev)?, true))
        }
    }
    impl MulBackend for CudaMsm {
        fn telemetry(&self) -> serde_json::Value {
            self.0.telemetry()
        }
        fn name(&self) -> String {
            format!(
                "{} + GPU Pippenger{}",
                self.0.name(),
                if self.1 {
                    " signed-magnitude (prime-order bases)"
                } else {
                    ""
                }
            )
        }
        fn run(&self, jobs: &[Job]) -> Result<Vec<G>> {
            self.0.run(jobs)
        }
        fn msm(&self, pts: &[G], sc: &[F]) -> Result<G> {
            if self.1 {
                self.0.run_msm_signed(pts, sc)
            } else {
                self.0.run_msm(pts, sc)
            }
        }
    }

    impl MulBackend for Cuda {
        fn telemetry(&self) -> serde_json::Value {
            let i = &self.info;
            serde_json::json!({"device": {"name": i.device, "compute_capability": i.compute_capability,
                "total_mem": i.total_mem, "compile_seconds": i.compile_seconds, "times": *i.times.lock().unwrap()}})
        }
        fn name(&self) -> String {
            let i = &self.info;
            format!(
                "cuda({}, sm_{}{}, block {})",
                i.device, i.compute_capability.0, i.compute_capability.1, self.block
            )
        }
        fn msm(&self, pts: &[G], sc: &[crate::group::F]) -> Result<G> {
            crate::batch::msm_via_jobs(self, pts, sc)
        }
        fn run(&self, jobs: &[Job]) -> Result<Vec<G>> {
            let _g = self.lock.lock().unwrap();
            let mut tm = DeviceTimes::default();
            let mut r = Vec::with_capacity(jobs.len());
            for c in jobs.chunks(MAX_CHUNK) {
                r.extend(self.run_chunk(c, &mut tm)?);
            }
            let mut all = self.info.times.lock().unwrap();
            all.pack += tm.pack;
            all.h2d += tm.h2d;
            all.kernel += tm.kernel;
            all.d2h += tm.d2h;
            all.unpack += tm.unpack;
            all.batches += 1;
            all.jobs += jobs.len() as u64;
            Ok(r)
        }
    }
}

/// Compiles the kernel with NVRTC only (no device needed): returns the PTX
/// size and the target architecture. Used to validate the CUDA source on
/// machines that have the NVRTC library but no GPU.
#[cfg(feature = "gpu")]
pub fn nvrtc_compile_check(arch: &'static str) -> anyhow::Result<usize> {
    use cudarc::nvrtc::{CompileOptions, compile_ptx_with_opts};
    anyhow::ensure!(
        unsafe { cudarc::nvrtc::sys::is_culib_present() },
        "NVRTC library not found"
    );
    let opts = CompileOptions {
        arch: Some(arch),
        name: Some("bjj.cu".into()),
        ..Default::default()
    };
    let ptx = compile_ptx_with_opts(KERNEL_SRC, opts)?;
    Ok(ptx.to_src().len())
}

/// Deterministic CPU-reference test vectors for `[k]P` (canonical compressed
/// encodings, hex). The reference is arkworks' exact double-and-add, so any
/// backend can be checked bit-for-bit independently of this crate's wNAF.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Vector {
    pub point: String,
    /// little-endian 64-bit limbs of k, hex
    pub k: [String; 4],
    pub expected: String,
    pub note: String,
}

fn enc_point(p: &G) -> String {
    use ark_serialize::CanonicalSerialize;
    let mut v = Vec::new();
    p.serialize_compressed(&mut v).unwrap();
    hex::encode(v)
}

fn dec_point(s: &str) -> anyhow::Result<G> {
    use ark_serialize::CanonicalDeserialize;
    // unchecked: vectors deliberately include small-order points
    Ok(G::deserialize_compressed_unchecked(&hex::decode(s)?[..])?)
}

pub fn make_vectors(seed: u64, random: usize) -> Vec<Vector> {
    use ark_ec::{AffineRepr, PrimeGroup};
    use ark_ff::{BigInteger, PrimeField};
    use rand::{Rng, SeedableRng};
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let t2 =
        ark_ed_on_bn254::EdwardsAffine::new_unchecked(Fb::from(0u64), -Fb::from(1u64)).into_group();
    let base = [
        (G::default(), "identity"),
        (g(), "g (Base8)"),
        (h_tilde(), "h~"),
        (t2, "order-2 point"),
        (g() + t2, "g + order-2"),
    ];
    let mut qm1 = F::MODULUS;
    qm1.sub_with_borrow(&BigInt::from(1u64));
    let mut qp1 = F::MODULUS;
    qp1.add_with_carry(&BigInt::from(1u64));
    let ks = [
        (BigInt::from(0u64), "k=0"),
        (BigInt::from(1u64), "k=1"),
        (BigInt::from(2u64), "k=2"),
        (BigInt::from(15u64), "k=15"),
        (BigInt::from(16u64), "k=16"),
        (qm1, "k=q-1"),
        (F::MODULUS, "k=q (subgroup check)"),
        (qp1, "k=q+1"),
        (BigInt([0, 0, 0, 1 << 63]), "k=2^255"),
        (BigInt([u64::MAX; 4]), "k=2^256-1"),
    ];
    let mut v = Vec::new();
    let mut push = |p: G, k: BigInt<4>, note: String| {
        v.push(Vector {
            point: enc_point(&p),
            k: k.0.map(|l| format!("{l:016x}")),
            expected: enc_point(&p.mul_bigint(k)),
            note,
        });
    };
    for (p, pn) in base {
        for (k, kn) in ks {
            push(p, k, format!("{pn}, {kn}"));
        }
    }
    for i in 0..random {
        let p = g() * F::from(rng.r#gen::<u128>()) + if i % 7 == 0 { t2 } else { G::default() };
        let k = if i % 4 == 3 {
            F::MODULUS
        } else {
            BigInt(rng.r#gen::<[u64; 4]>())
        };
        push(p, k, format!("random #{i}"));
    }
    v
}

/// Checks `vectors` on `backend`; returns the indices of mismatches.
pub fn check_vectors(
    backend: &dyn crate::batch::MulBackend,
    vectors: &[Vector],
) -> anyhow::Result<Vec<usize>> {
    let jobs: Vec<Job> = vectors
        .iter()
        .map(|v| {
            let mut k = [0u64; 4];
            for i in 0..4 {
                k[i] = u64::from_str_radix(&v.k[i], 16)?;
            }
            Ok(Job {
                p: dec_point(&v.point)?,
                k: BigInt(k),
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let r = backend.run(&jobs)?;
    anyhow::ensure!(r.len() == jobs.len(), "backend result count mismatch");
    Ok(vectors
        .iter()
        .zip(&r)
        .enumerate()
        .filter(|(_, (v, p))| enc_point(p) != v.expected)
        .map(|(i, _)| i)
        .collect())
}

/// Compiles the kernel to device code (SASS/CUBIN) for a real architecture
/// such as `sm_89` with NVRTC's built-in assembler and returns the assembler
/// log (`-v`: registers, spills, local memory) and the CUBIN size. Needs only
/// the NVRTC library, no GPU.
#[cfg(feature = "gpu")]
pub fn nvrtc_sass_report(sm: &str) -> anyhow::Result<(String, usize)> {
    use cudarc::nvrtc::{result, sys};
    anyhow::ensure!(
        unsafe { sys::is_culib_present() },
        "NVRTC library not found"
    );
    let src = std::ffi::CString::new(KERNEL_SRC)?;
    let prog = result::create_program(&src, Some(c"bjj.cu"))?;
    let opts = [
        format!("--gpu-architecture={sm}"),
        "--ptxas-options=-v".to_string(),
    ];
    let compiled = unsafe { result::compile_program(prog, &opts) };
    let log = unsafe { result::get_program_log(prog)? };
    let log: String = log
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8 as char)
        .collect();
    let mut size = 0usize;
    if compiled.is_ok() {
        unsafe { sys::nvrtcGetCUBINSize(prog, &mut size).result()? };
    }
    unsafe { result::destroy_program(prog)? };
    compiled.map_err(|e| anyhow::anyhow!("NVRTC {sm} failed: {e:?}\n{log}"))?;
    Ok((log, size))
}

/// T007 deterministic MSM vectors (`Σ [s_i]P_i`, canonical encodings) and
/// lift vectors (`[1/8]P`), for CPU/GPU comparison of `MulBackend::msm`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MsmVector {
    pub points: Vec<String>,
    /// little-endian 64-bit limbs of each scalar (canonical, < q), hex
    pub scalars: Vec<[String; 4]>,
    pub expected: String,
    pub note: String,
}

/// All eight representatives of four public canonical points. Unlike
/// negative scalars modulo q, the integer eight is valid on the full curve.
pub fn make_secure_lift_vectors() -> Vec<MsmVector> {
    let mut out = Vec::new();
    for (pi, p) in [G::default(), g(), g() * F::from(17u64), h_tilde()]
        .iter()
        .enumerate()
    {
        for (ti, t) in torsion8().iter().enumerate() {
            out.push(MsmVector {
                points: vec![enc_point(&(lift_of(p) + t))],
                scalars: vec![[
                    "0000000000000008".into(),
                    "0000000000000000".into(),
                    "0000000000000000".into(),
                    "0000000000000000".into(),
                ]],
                expected: enc_point(p),
                note: format!("T008 secure fibre public point {pi}, torsion representative {ti}"),
            });
        }
    }
    out
}

pub fn make_msm_vectors(seed: u64) -> Vec<MsmVector> {
    use ark_ec::PrimeGroup;
    use ark_ff::PrimeField;
    use rand::{Rng, SeedableRng};
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let hexk = |s: &F| s.into_bigint().0.map(|l| format!("{l:016x}"));
    let mut v = Vec::new();
    for (n, short) in [
        (1usize, false),
        (2, false),
        (7, true),
        (64, false),
        (333, true),
        (1024, true),
    ] {
        let pts: Vec<G> = (0..n).map(|_| g() * F::from(rng.r#gen::<u128>())).collect();
        let sc: Vec<F> = (0..n)
            .map(|i| {
                if short && i % 2 == 0 {
                    F::from(rng.r#gen::<u128>())
                } else {
                    F::from_le_bytes_mod_order(&rng.r#gen::<[u8; 32]>())
                }
            })
            .collect();
        let want: G = pts
            .iter()
            .zip(&sc)
            .map(|(p, s)| p.mul_bigint(s.into_bigint()))
            .sum();
        v.push(MsmVector {
            points: pts.iter().map(enc_point).collect(),
            scalars: sc.iter().map(hexk).collect(),
            expected: enc_point(&want),
            note: format!(
                "msm n={n}{}",
                if short {
                    " (mixed 128/253-bit scalars)"
                } else {
                    ""
                }
            ),
        });
    }
    for i in 0..8 {
        let p = g() * F::from(rng.r#gen::<u64>() + i);
        v.push(MsmVector {
            points: vec![enc_point(&p)],
            scalars: vec![hexk(&inv8())],
            expected: enc_point(&p.mul_bigint(inv8().into_bigint())),
            note: format!("lift [1/8]P #{i}"),
        });
    }
    v
}

pub fn check_msm_vectors(
    b: &dyn crate::batch::MulBackend,
    vs: &[MsmVector],
) -> anyhow::Result<Vec<usize>> {
    use ark_ff::PrimeField;
    let mut bad = Vec::new();
    for (i, v) in vs.iter().enumerate() {
        let pts: Vec<G> = v
            .points
            .iter()
            .map(|p| dec_point(p))
            .collect::<anyhow::Result<_>>()?;
        let sc: Vec<F> = v
            .scalars
            .iter()
            .map(|k| {
                let mut l = [0u64; 4];
                for j in 0..4 {
                    l[j] = u64::from_str_radix(&k[j], 16)?;
                }
                F::from_bigint(BigInt(l)).ok_or_else(|| anyhow::anyhow!("scalar >= q"))
            })
            .collect::<anyhow::Result<_>>()?;
        anyhow::ensure!(pts.len() == sc.len(), "vector {i}: length mismatch");
        if enc_point(&b.msm(&pts, &sc)?) != v.expected {
            bad.push(i);
        }
    }
    Ok(bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ed_on_bn254::EdwardsConfig;
    use ark_ff::{Field, PrimeField, Zero};

    /// Extracts `NAME[8] = {...}` from the kernel source.
    fn kernel_const(name: &str) -> [u32; 8] {
        let i = KERNEL_SRC.find(&format!("{name}[8] = {{")).expect(name);
        let body = &KERNEL_SRC[i..KERNEL_SRC[i..].find('}').unwrap() + i];
        let v: Vec<u32> = body
            .split(['{', ','])
            .skip(1)
            .map(|t| {
                u32::from_str_radix(t.trim().trim_start_matches("0x").trim_end_matches('u'), 16)
                    .unwrap()
            })
            .collect();
        v.try_into().unwrap()
    }

    fn words(f: &Fb) -> [u32; 8] {
        let mut w = [0u32; 8];
        fe_words(f, &mut w);
        w
    }

    #[test]
    fn kernel_constants_match_arkworks() {
        let m: [u32; 8] = {
            let mut w = [0u32; 8];
            for (j, l) in Fb::MODULUS.0.iter().enumerate() {
                w[2 * j] = *l as u32;
                w[2 * j + 1] = (*l >> 32) as u32;
            }
            w
        };
        assert_eq!(kernel_const("P_MOD"), m);
        assert_eq!(kernel_const("FE_ONE"), words(&Fb::ONE));
        assert_eq!(kernel_const("COEFF_D"), words(&EdwardsConfig::COEFF_D));
        // N0 = -p^{-1} mod 2^32
        let n0 = u32::from_str_radix(
            KERNEL_SRC.split("#define N0 0x").nth(1).unwrap()[..8].trim_end_matches('u'),
            16,
        )
        .unwrap();
        assert_eq!(n0.wrapping_mul(m[0]), u32::MAX);
    }

    #[test]
    fn committed_vectors_match_cpu_reference() {
        let file: Vec<Vector> =
            serde_json::from_str(include_str!("../tests/vectors/bjj_mul_v1.json")).unwrap();
        let fresh = make_vectors(20261123, 64);
        assert_eq!(file.len(), fresh.len());
        for (a, b) in file.iter().zip(&fresh) {
            assert_eq!(
                (&a.point, &a.k, &a.expected),
                (&b.point, &b.k, &b.expected),
                "{}",
                a.note
            );
        }
        assert!(check_vectors(&crate::batch::Cpu, &file).unwrap().is_empty());
        #[cfg(feature = "cuda-emu")]
        assert!(check_vectors(&Emu, &file).unwrap().is_empty());
    }

    #[test]
    fn truncated_vector_backend_is_rejected() {
        struct Empty;
        impl crate::batch::MulBackend for Empty {
            fn name(&self) -> String {
                "test-empty".into()
            }
            fn run(&self, _: &[Job]) -> anyhow::Result<Vec<G>> {
                Ok(vec![])
            }
        }
        assert!(check_vectors(&Empty, &make_vectors(7, 0)).is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    #[ignore = "requires a real CUDA device and NVRTC"]
    fn actual_cuda_vectors_and_randomized_equivalence() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let b = Cuda::new(0).unwrap();
                let committed: Vec<Vector> =
                    serde_json::from_str(include_str!("../tests/vectors/bjj_mul_v1.json")).unwrap();
                assert!(check_vectors(&b, &committed).unwrap().is_empty());
                for seed in [41, 42, 43] {
                    assert!(
                        check_vectors(&b, &make_vectors(seed, 1024))
                            .unwrap()
                            .is_empty()
                    );
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(feature = "gpu")]
    #[test]
    #[ignore = "requires a real CUDA device and NVRTC"]
    fn actual_gpu_pippenger_matches_arkworks() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                use rand::SeedableRng;
                let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(8008);
                let b = CudaMsm::new(0).unwrap();
                let pool: Vec<G> = (0..64).map(|_| g() * rand_scalar(&mut rng)).collect();
                for n in [0, 1, 2, 7, 256, 1024, 81920] {
                    let pts: Vec<G> = (0..n)
                        .map(|i| {
                            if i % 13 == 0 {
                                G::default()
                            } else {
                                pool[i % 64]
                            }
                        })
                        .collect();
                    let sc: Vec<F> = (0..n)
                        .map(|i| match i % 17 {
                            0 => F::from(0u64),
                            1 => -F::from(1u64),
                            2 => F::from(1u64),
                            _ => rand_scalar(&mut rng),
                        })
                        .collect();
                    assert_eq!(
                        b.msm(&pts, &sc).unwrap(),
                        crate::batch::msm_cpu(&pts, &sc),
                        "n={n}"
                    );
                }
                let p = pool[0];
                let pts = [p, p, -p, G::default()];
                let sc = [F::from(1u64), -F::from(1u64), F::from(0u64), F::from(19u64)];
                assert!(b.msm(&pts, &sc).unwrap().is_zero());
                assert!(b.msm(&[p], &[]).is_err());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let mut rng = rand::thread_rng();
        let jobs: Vec<Job> = (0..10)
            .map(|_| Job::mul(g() * rand_scalar(&mut rng), &rand_scalar(&mut rng)))
            .collect();
        let (pts, _) = pack(&jobs);
        let back = unpack(&pts).unwrap();
        for (j, p) in jobs.iter().zip(back) {
            assert_eq!(j.p, p);
            assert_eq!((j.p.x, j.p.y, j.p.t, j.p.z), (p.x, p.y, p.t, p.z));
        }
    }

    #[test]
    fn signed_msm_recode_requires_prime_order_bases() {
        use ark_ff::{BigInteger, One, Zero};
        let pts = [g(), g() * F::from(17u64), G::zero(), h_tilde()];
        let sc = [
            -F::one(),
            -F::from(u128::MAX),
            F::zero(),
            F::from(u128::MAX),
        ];
        let jobs = msm_jobs(&pts, &sc, true);
        let result: G = crate::batch::Cpu.run(&jobs).unwrap().into_iter().sum();
        assert_eq!(result, crate::batch::msm_cpu(&pts, &sc));
        assert_eq!(jobs[0].k, BigInt::from(1u64));
        assert_eq!(jobs[1].k.num_bits(), 128);
        assert!(msm_jobs(&[], &[], true).is_empty());
        // The signed variant's qP=0 precondition is essential, not merely
        // a performance hint. Unsigned jobs retain exact full-curve semantics.
        let torsion = torsion8()[1];
        let raw = msm_jobs(&[torsion], &[-F::one()], false);
        let recoded = msm_jobs(&[torsion], &[-F::one()], true);
        assert_ne!(crate::batch::eval(&raw[0]), crate::batch::eval(&recoded[0]));
    }

    #[cfg(feature = "gpu")]
    #[test]
    #[ignore = "requires a real CUDA device and NVRTC"]
    fn actual_gpu_signed_pippenger_matches_arkworks() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                use rand::SeedableRng;
                let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(8009);
                let b = CudaMsm::new_signed(0).unwrap();
                let pool: Vec<G> = (0..64).map(|_| g() * rand_scalar(&mut rng)).collect();
                for n in [0, 1, 4, 256, 1024, 81920] {
                    let pts: Vec<G> = (0..n)
                        .map(|i| {
                            if i % 11 == 0 {
                                G::default()
                            } else {
                                pool[i % 64]
                            }
                        })
                        .collect();
                    let sc: Vec<F> = (0..n)
                        .map(|i| match i % 5 {
                            0 => F::from(0u64),
                            1 => -F::from(1u64),
                            2 => -F::from(u128::MAX),
                            3 => F::from(u128::MAX),
                            _ => rand_scalar(&mut rng),
                        })
                        .collect();
                    assert_eq!(
                        b.msm(&pts, &sc).unwrap(),
                        crate::batch::msm_cpu(&pts, &sc),
                        "n={n}"
                    );
                }
                assert!(
                    b.msm(&[pool[0], pool[0]], &[F::from(1u64), -F::from(1u64)])
                        .unwrap()
                        .is_zero()
                );
                assert!(b.msm(&[pool[0]], &[]).is_err());
                let torsion = torsion8()[1];
                let sc = [-F::from(1u64)];
                assert_eq!(
                    b.0.run_msm(&[torsion], &sc).unwrap(),
                    crate::batch::msm_cpu(&[torsion], &sc)
                );
                assert_ne!(
                    b.msm(&[torsion], &sc).unwrap(),
                    crate::batch::msm_cpu(&[torsion], &sc)
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(feature = "gpu")]
    #[test]
    #[ignore = "requires a real CUDA device and NVRTC"]
    fn actual_cuda_certified_products_match_cpu() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                use ark_ff::BigInteger;
                use rand::SeedableRng;
                let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(8010);
                let mut jobs: Vec<Job> = (0..128)
                    .map(|_| Job::mul(g() * rand_scalar(&mut rng), &rand_scalar(&mut rng)))
                    .collect();
                let mut qp1 = F::MODULUS;
                qp1.add_with_carry(&BigInt::from(1u64));
                for k in [
                    BigInt::from(0u64),
                    (-F::from(1u64)).into_bigint(),
                    qp1,
                    BigInt([u64::MAX; 4]),
                ] {
                    jobs.push(Job {
                        p: g() * F::from(17u64),
                        k,
                    });
                }
                jobs.push(Job::subgroup(g()));
                jobs.push(Job::subgroup(G::default()));
                let certified =
                    crate::batch::Certified::new(std::sync::Arc::new(Cuda::new(0).unwrap()));
                assert_eq!(
                    certified.run(&jobs).unwrap(),
                    crate::batch::Cpu.run(&jobs).unwrap()
                );
                let stats = certified.stats.lock().unwrap();
                assert_eq!(stats.fallbacks, 0);
                assert_eq!(stats.batches, 1);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn hostile_raw_device_words_rejected_before_arithmetic() {
        let (words, _) = pack(&[Job::mul(g(), &F::from(1u64))]);
        assert!(unpack(&words[..PT_WORDS - 1]).is_err());
        for raw in [Fb::MODULUS, BigInt([u64::MAX; 4])] {
            for coordinate in 0..4 {
                let mut bad = words.clone();
                for (i, limb) in raw.0.iter().enumerate() {
                    bad[coordinate * 8 + i * 2] = *limb as u32;
                    bad[coordinate * 8 + i * 2 + 1] = (*limb >> 32) as u32;
                }
                assert!(unpack(&bad).is_err());
            }
        }
        let mut zero_z = words.clone();
        zero_z[24..32].fill(0);
        assert!(unpack(&zero_z).is_err());
        let mut off_curve = words.clone();
        off_curve[0..8].fill(0);
        assert!(unpack(&off_curve).is_err());
        let t2: G = GA::new_unchecked(Fb::zero(), -Fb::from(1u64)).into();
        let alternative = lift_of(&g()) + t2;
        let (w, _) = pack(&[Job::mul(alternative, &F::from(1u64))]);
        let decoded = unpack(&w).unwrap();
        assert_eq!(clear8(&decoded[0]), g());
    }

    /// Same kernel source on the host vs the arkworks reference, including
    /// identity, small-order points and boundary scalars.
    #[cfg(feature = "cuda-emu")]
    #[test]
    fn emulated_kernel_matches_arkworks() {
        use crate::batch::{Cpu, MulBackend};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::{BigInteger, Zero};
        let mut rng = rand::thread_rng();
        let t2 =
            ark_ed_on_bn254::EdwardsAffine::new_unchecked(Fb::from(0u64), -Fb::ONE).into_group();
        let mut pts: Vec<G> = (0..200).map(|_| g() * rand_scalar(&mut rng)).collect();
        pts.extend([G::zero(), g(), -g(), t2, g() + t2, h_tilde()]);
        let mut jobs: Vec<Job> = Vec::new();
        for p in &pts {
            jobs.push(Job::mul(*p, &rand_scalar(&mut rng)));
            jobs.push(Job::subgroup(*p));
        }
        let mut max = F::MODULUS;
        max.0 = [u64::MAX; 4];
        let mut qm1 = F::MODULUS;
        qm1.sub_with_borrow(&ark_ff::BigInt::from(1u64));
        for k in [
            ark_ff::BigInt::from(0u64),
            ark_ff::BigInt::from(1u64),
            ark_ff::BigInt::from(16u64),
            qm1,
            max,
        ] {
            jobs.push(Job { p: pts[0], k });
            jobs.push(Job { p: t2, k });
        }
        // reference: arkworks double-and-add (exact for every 256-bit k)
        use ark_ec::PrimeGroup;
        let want: Vec<G> = jobs.iter().map(|j| j.p.mul_bigint(j.k)).collect();
        assert_eq!(Cpu.run(&jobs).unwrap(), want);
        let got = Emu.run(&jobs).unwrap();
        for (i, (a, b)) in want.iter().zip(&got).enumerate() {
            assert_eq!(a.into_affine(), b.into_affine(), "job {i}");
        }
        // subgroup checks: zero for prime-order points, non-zero with torsion
        let t2_index = 203; // pts = 200 random, identity, g, -g, t2, g + t2, h~
        assert!(
            got[1].is_zero()
                && !got[2 * t2_index + 1].is_zero()
                && !got[2 * (t2_index + 1) + 1].is_zero()
        );
    }

    #[test]
    fn t007_msm_vectors_match() {
        let file: Vec<MsmVector> =
            serde_json::from_str(include_str!("../tests/vectors/t007_msm_v1.json")).unwrap();
        let fresh = make_msm_vectors(20261124);
        assert_eq!(file.len(), fresh.len());
        for (a, b) in file.iter().zip(&fresh) {
            assert_eq!(
                (&a.points, &a.scalars, &a.expected),
                (&b.points, &b.scalars, &b.expected),
                "{}",
                a.note
            );
        }
        assert!(
            check_msm_vectors(&crate::batch::Cpu, &file)
                .unwrap()
                .is_empty()
        );
        assert!(
            check_msm_vectors(
                &*crate::batch::Certified::new(std::sync::Arc::new(crate::batch::Cpu)),
                &file
            )
            .unwrap()
            .is_empty()
        );
        #[cfg(feature = "cuda-emu")]
        assert!(check_msm_vectors(&Emu, &file).unwrap().is_empty());
    }

    #[test]
    fn secure_fibre_vectors_cover_all_rational_representatives() {
        let file: Vec<MsmVector> =
            serde_json::from_str(include_str!("../tests/vectors/t008_lifts_v1.json")).unwrap();
        assert_eq!(file.len(), 32);
        assert_eq!(
            serde_json::to_value(&file).unwrap(),
            serde_json::to_value(make_secure_lift_vectors()).unwrap()
        );
        assert!(
            check_msm_vectors(&crate::batch::Cpu, &file)
                .unwrap()
                .is_empty()
        );
    }
}
