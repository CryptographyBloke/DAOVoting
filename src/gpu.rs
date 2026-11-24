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
use ark_ff::{BigInt, Fp};
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

fn fe_words(f: &Fb, out: &mut [u32]) {
    for (j, l) in f.0.0.iter().enumerate() {
        out[2 * j] = *l as u32;
        out[2 * j + 1] = (*l >> 32) as u32;
    }
}

fn fe_from(w: &[u32]) -> Fb {
    let mut l = [0u64; 4];
    for j in 0..4 {
        l[j] = w[2 * j] as u64 | ((w[2 * j + 1] as u64) << 32);
    }
    Fp(BigInt(l), core::marker::PhantomData)
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
pub fn unpack(out: &[u32]) -> Vec<G> {
    out.par_chunks(PT_WORDS)
        .map(|w| {
            G::new_unchecked(
                fe_from(&w[0..8]),
                fe_from(&w[8..16]),
                fe_from(&w[16..24]),
                fe_from(&w[24..32]),
            )
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
        Ok(unpack(&out))
    }
}

#[cfg(feature = "gpu")]
pub use cuda::{Cuda, last_cuda};

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
            let r = unpack(&out);
            tm.unpack += t.elapsed().as_secs_f64();
            Ok(r)
        }
    }

    impl MulBackend for Cuda {
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
    use ark_ff::{Field, PrimeField};

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

    #[test]
    fn pack_unpack_roundtrip() {
        let mut rng = rand::thread_rng();
        let jobs: Vec<Job> = (0..10)
            .map(|_| Job::mul(g() * rand_scalar(&mut rng), &rand_scalar(&mut rng)))
            .collect();
        let (pts, _) = pack(&jobs);
        let back = unpack(&pts);
        for (j, p) in jobs.iter().zip(back) {
            assert_eq!(j.p, p);
            assert_eq!((j.p.x, j.p.y, j.p.t, j.p.z), (p.x, p.y, p.t, p.z));
        }
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
}
