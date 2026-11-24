// BabyJubjub batched scalar multiplication: one independent job per thread.
//
// Field: F_p with p = BN254 scalar-field modulus (BabyJubjub base field),
// 8 x 32-bit little-endian limbs in Montgomery form with R = 2^256. This is
// bit-identical to arkworks' `ark_ed_on_bn254::Fq` internal representation,
// so points cross the host/device boundary without conversion.
// Curve: arkworks' twisted-Edwards form a = 1, d = COEFF_D, extended
// coordinates (X, Y, T, Z); the formulas are exactly arkworks'
// add-2008-hwcd (unified, complete for this curve) and dbl-2008-hwcd.
//
// Job i: in[32i..32i+32] = X,Y,T,Z (8 limbs each), k[8i..8i+8] = 256-bit
// scalar (plain integer, little-endian limbs), out[32i..] = [k]P.
// Only public verification data is ever sent to this kernel.
//
// The same file is compiled by NVRTC for the GPU and as host C++ (see
// build.rs, feature `cuda-emu`) so the arithmetic is tested against arkworks
// on machines without a GPU.

#if defined(__CUDACC__) || defined(__CUDACC_RTC__)
#define DEV __device__ __forceinline__
#define CONST __constant__
#else
#define DEV static inline
#define CONST static const
#endif

typedef unsigned int u32;
typedef unsigned long long u64;

CONST u32 P_MOD[8] = {0xf0000001u, 0x43e1f593u, 0x79b97091u, 0x2833e848u,
                      0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u};
#define N0 0xefffffffu
CONST u32 FE_ONE[8] = {0x4ffffffbu, 0xac96341cu, 0x9f60cd29u, 0x36fc7695u,
                       0x7879462eu, 0x666ea36fu, 0x9a07df2fu, 0x0e0a77c1u};
CONST u32 COEFF_D[8] = {0x9fb08e74u, 0xe7a66d1du, 0xe17629dcu, 0xd775bbd5u,
                        0x286ef1e7u, 0x70ccd097u, 0x398fdf98u, 0x00045809u};

struct fe {
    u32 v[8];
};

struct pt {
    fe x, y, t, z;
};

DEV bool fe_geq_p(const u32 *a) {
    for (int i = 7; i >= 0; --i) {
        if (a[i] > P_MOD[i]) return true;
        if (a[i] < P_MOD[i]) return false;
    }
    return true;
}

DEV void fe_sub_p(u32 *a) {
    u64 borrow = 0;
    for (int i = 0; i < 8; ++i) {
        u64 t = (u64)a[i] - P_MOD[i] - borrow;
        a[i] = (u32)t;
        borrow = (t >> 32) & 1;
    }
}

DEV fe fe_add(const fe &a, const fe &b) {
    fe r;
    u64 c = 0;
    for (int i = 0; i < 8; ++i) {
        c += (u64)a.v[i] + b.v[i];
        r.v[i] = (u32)c;
        c >>= 32;
    }
    // p < 2^254, so a + b < 2^255 never carries out of 8 limbs
    if (fe_geq_p(r.v)) fe_sub_p(r.v);
    return r;
}

DEV fe fe_sub(const fe &a, const fe &b) {
    fe r;
    u64 borrow = 0;
    for (int i = 0; i < 8; ++i) {
        u64 t = (u64)a.v[i] - b.v[i] - borrow;
        r.v[i] = (u32)t;
        borrow = (t >> 32) & 1;
    }
    if (borrow) {
        u64 c = 0;
        for (int i = 0; i < 8; ++i) {
            c += (u64)r.v[i] + P_MOD[i];
            r.v[i] = (u32)c;
            c >>= 32;
        }
    }
    return r;
}

// Montgomery multiplication (CIOS), returns a*b*2^-256 mod p.
DEV fe fe_mul(const fe &a, const fe &b) {
    u32 t[10];
    for (int i = 0; i < 10; ++i) t[i] = 0;
    for (int i = 0; i < 8; ++i) {
        u64 c = 0;
        for (int j = 0; j < 8; ++j) {
            c += (u64)t[j] + (u64)a.v[j] * b.v[i];
            t[j] = (u32)c;
            c >>= 32;
        }
        c += t[8];
        t[8] = (u32)c;
        t[9] = (u32)(c >> 32);
        u32 m = t[0] * N0;
        c = ((u64)t[0] + (u64)m * P_MOD[0]) >> 32;
        for (int j = 1; j < 8; ++j) {
            c += (u64)t[j] + (u64)m * P_MOD[j];
            t[j - 1] = (u32)c;
            c >>= 32;
        }
        c += t[8];
        t[7] = (u32)c;
        t[8] = t[9] + (u32)(c >> 32);
    }
    fe r;
    for (int i = 0; i < 8; ++i) r.v[i] = t[i];
    if (t[8] || fe_geq_p(r.v)) fe_sub_p(r.v);
    return r;
}

DEV fe fe_const(const u32 *c) {
    fe r;
    for (int i = 0; i < 8; ++i) r.v[i] = c[i];
    return r;
}

DEV pt pt_identity() {
    pt r;
    for (int i = 0; i < 8; ++i) {
        r.x.v[i] = 0;
        r.t.v[i] = 0;
    }
    r.y = fe_const(FE_ONE);
    r.z = fe_const(FE_ONE);
    return r;
}

// arkworks add-2008-hwcd with a = 1
DEV pt pt_add(const pt &p, const pt &q) {
    fe a = fe_mul(p.x, q.x);
    fe b = fe_mul(p.y, q.y);
    fe c = fe_mul(fe_mul(fe_const(COEFF_D), p.t), q.t);
    fe d = fe_mul(p.z, q.z);
    fe h = fe_sub(b, a);
    fe e = fe_sub(fe_sub(fe_mul(fe_add(p.x, p.y), fe_add(q.x, q.y)), a), b);
    fe f = fe_sub(d, c);
    fe g = fe_add(d, c);
    pt r;
    r.x = fe_mul(e, f);
    r.y = fe_mul(g, h);
    r.t = fe_mul(e, h);
    r.z = fe_mul(f, g);
    return r;
}

// arkworks dbl-2008-hwcd with a = 1
DEV pt pt_dbl(const pt &p) {
    fe a = fe_mul(p.x, p.x);
    fe b = fe_mul(p.y, p.y);
    fe zz = fe_mul(p.z, p.z);
    fe c = fe_add(zz, zz);
    fe s = fe_add(p.x, p.y);
    fe e = fe_sub(fe_sub(fe_mul(s, s), a), b);
    fe g = fe_add(a, b);
    fe f = fe_sub(g, c);
    fe h = fe_sub(a, b);
    pt r;
    r.x = fe_mul(e, f);
    r.y = fe_mul(g, h);
    r.t = fe_mul(e, h);
    r.z = fe_mul(f, g);
    return r;
}

DEV void pt_load(pt &p, const u32 *in) {
    for (int i = 0; i < 8; ++i) {
        p.x.v[i] = in[i];
        p.y.v[i] = in[8 + i];
        p.t.v[i] = in[16 + i];
        p.z.v[i] = in[24 + i];
    }
}

DEV void pt_store(const pt &p, u32 *out) {
    for (int i = 0; i < 8; ++i) {
        out[i] = p.x.v[i];
        out[8 + i] = p.y.v[i];
        out[16 + i] = p.t.v[i];
        out[24 + i] = p.z.v[i];
    }
}

// [k]P with a 4-bit fixed window: 256 doublings + <= 64 additions.
DEV void bjj_mul_one(const u32 *in, const u32 *k, u32 *out) {
    pt tab[16];
    tab[0] = pt_identity();
    pt_load(tab[1], in);
    for (int i = 2; i < 16; ++i) tab[i] = pt_add(tab[i - 1], tab[1]);
    pt acc = pt_identity();
    for (int w = 63; w >= 0; --w) {
        acc = pt_dbl(acc);
        acc = pt_dbl(acc);
        acc = pt_dbl(acc);
        acc = pt_dbl(acc);
        u32 nib = (k[w >> 3] >> ((w & 7) * 4)) & 15u;
        if (nib) acc = pt_add(acc, tab[nib]);
    }
    pt_store(acc, out);
}

#if defined(__CUDACC__) || defined(__CUDACC_RTC__)
extern "C" __global__ void bjj_mul(const u32 *in, const u32 *k, u32 *out, u32 n) {
    u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) bjj_mul_one(in + 32 * (u64)i, k + 8 * (u64)i, out + 32 * (u64)i);
}

// T008 unsigned-window Pippenger prototype. Scatter is integer-only; each
// nonzero bucket has one owner, so no curve-coordinate atomic operation is
// needed. Kernels execute in one stream: all links are complete before use.
extern "C" __global__ void bjj_msm_scatter(const u32 *ks, int *heads,
    int *next, u32 n, u32 width, u32 windows) {
    u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= (u64)n * windows) return;
    u32 w = (u32)(index / n), i = (u32)(index % n);
    u32 bit = w * width, word = bit >> 5, shift = bit & 31;
    u32 digit = ks[8 * (u64)i + word] >> shift;
    if (shift + width > 32 && word < 7)
        digit |= ks[8 * (u64)i + word + 1] << (32 - shift);
    digit &= (1u << width) - 1;
    if (digit) next[index] = atomicExch(heads + w * (1u << width) + digit, (int)i);
}

extern "C" __global__ void bjj_msm_buckets(const u32 *pts, const int *heads,
    const int *next, u32 *out, u32 n, u32 width, u32 windows) {
    u32 index = blockIdx.x * blockDim.x + threadIdx.x;
    u32 count = 1u << width;
    if (index >= count * windows) return;
    u32 w = index / count, digit = index % count;
    pt acc = pt_identity();
    if (digit) {
        int i = heads[index];
        while (i >= 0) {
            pt p; pt_load(p, pts + 32 * (u64)i);
            acc = pt_add(acc, p);
            i = next[(u64)w * n + i];
        }
    }
    pt_store(acc, out + 32 * (u64)index);
}

// Weighted bucket sums and an on-device tree reduction per window. Uses
// exactly 32 KiB shared memory; host performs only the final window Horner sum.
extern "C" __global__ void bjj_msm_reduce(const u32 *buckets, u32 *out, u32 width) {
    __shared__ pt partial[256];
    u32 w = blockIdx.x, t = threadIdx.x, count = 1u << width;
    pt acc = pt_identity();
    if (t < count && t) {
        pt p; pt_load(p, buckets + 32 * ((u64)w * count + t));
        u32 k = t;
        while (k) {
            if (k & 1) acc = pt_add(acc, p);
            k >>= 1;
            if (k) p = pt_dbl(p);
        }
    }
    partial[t] = acc;
    __syncthreads();
    for (u32 stride = 128; stride; stride >>= 1) {
        if (t < stride) partial[t] = pt_add(partial[t], partial[t + stride]);
        __syncthreads();
    }
    if (!t) pt_store(partial[0], out + 32 * (u64)w);
}
#else
extern "C" void bjj_mul_host(const u32 *in, const u32 *k, u32 *out, u32 n) {
    for (u32 i = 0; i < n; ++i) bjj_mul_one(in + 32 * (u64)i, k + 8 * (u64)i, out + 32 * (u64)i);
}
#endif
