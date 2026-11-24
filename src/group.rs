//! BabyJubjub group, exponential ElGamal and Fiat–Shamir hashing.
//!
//! The group is the prime-order subgroup `G = <g>` of BabyJubjub (EIP-2494) as
//! implemented by `ark-ed-on-bn254`. arkworks uses the isomorphic twisted
//! Edwards form with `a = 1`; circomlib's `Base8` is mapped into that form by
//! `x' = sqrt(168700) * x` (paper: `g = Base8`).
//! Network points are curve-validated. V1 checks subgroup membership explicitly;
//! lifted formats decode with [8] to a prime-order point. Setup uses Validate::Yes.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{AdditiveGroup, BigInteger, Field, MontFp, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub type G = EdwardsProjective;
pub type GA = EdwardsAffine;
/// Scalar field Z_q of the BabyJubjub subgroup.
pub type F = Fr;
/// Base field of BabyJubjub = scalar field of BN254.
pub type Fb = Fq;

thread_local! { static WIDE_MESSAGE_POINTS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

/// A per-item serializer scope. It is never active while loading ballots,
/// setup or ledger data, and restores the previous state even on unwinding.
pub fn message_wire<T>(wide: bool, f: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            WIDE_MESSAGE_POINTS.with(|v| v.set(self.0));
        }
    }
    let _restore = Restore(WIDE_MESSAGE_POINTS.with(|v| v.replace(wide)));
    f()
}

pub trait CurveWire: CanonicalSerialize + CanonicalDeserialize {
    fn valid_curve(&self) -> bool;
}
impl CurveWire for G {
    fn valid_curve(&self) -> bool {
        on_curve_ext(self)
    }
}
impl CurveWire for Vec<G> {
    fn valid_curve(&self) -> bool {
        self.iter().all(on_curve_ext)
    }
}
impl<const N: usize> CurveWire for [G; N] {
    fn valid_curve(&self) -> bool {
        self.iter().all(on_curve_ext)
    }
}

/// serde adapter for any arkworks `CanonicalSerialize` value (compressed,
/// validated on deserialization: on-curve and prime-order subgroup checks).
pub mod arkser {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};
    pub fn serialize<T: CanonicalSerialize, S: Serializer>(t: &T, s: S) -> Result<S::Ok, S::Error> {
        let mut v = Vec::with_capacity(t.compressed_size());
        t.serialize_compressed(&mut v).map_err(S::Error::custom)?;
        s.serialize_bytes(&v)
    }
    pub fn deserialize<'de, T: CanonicalDeserialize, D: Deserializer<'de>>(
        d: D,
    ) -> Result<T, D::Error> {
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        T::deserialize_compressed(&v[..]).map_err(D::Error::custom)
    }
}

/// serde adapter that decompresses points **without** the prime-order
/// subgroup check (decompression still guarantees an on-curve point). Used for
/// tally messages, whose points are subgroup-checked in parallel by the
/// verifying engine ([`in_subgroup`]), and for ballot ciphertexts, which the
/// Groth16 relation forces into `G`.
pub mod arkser_fast {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error as _};
    pub fn serialize<T: CurveWire, S: Serializer>(t: &T, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        if WIDE_MESSAGE_POINTS.with(|v| v.get()) {
            let mut bytes = Vec::new();
            t.serialize_uncompressed(&mut bytes)
                .map_err(S::Error::custom)?;
            s.serialize_bytes(&bytes)
        } else {
            super::arkser::serialize(t, s)
        }
    }
    pub fn deserialize<'de, T: CurveWire, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        if WIDE_MESSAGE_POINTS.with(|v| v.get()) {
            let mut input = &v[..];
            let point =
                T::deserialize_uncompressed_unchecked(&mut input).map_err(D::Error::custom)?;
            if !input.is_empty() || !point.valid_curve() {
                return Err(D::Error::custom("invalid affine curve encoding"));
            }
            Ok(point)
        } else {
            T::deserialize_compressed_unchecked(&v[..]).map_err(D::Error::custom)
        }
    }
}

/// Prime-order subgroup membership: `[q]P = 0`, using a fixed wNAF of `q`.
pub fn in_subgroup(p: &G) -> bool {
    static Q: OnceLock<Vec<i64>> = OnceLock::new();
    let naf = Q.get_or_init(|| F::MODULUS.find_wnaf(5).unwrap());
    wnaf_mul(p, naf).is_zero()
}

/// `g = Base8` of circomlib, mapped into arkworks' `a = 1` coordinates.
pub fn g() -> G {
    static P: OnceLock<G> = OnceLock::new();
    *P.get_or_init(|| {
        let x: Fb =
            MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553");
        let y: Fb = MontFp!(
            "16950150798460657717958625567821834550301663161624707787222815936182638968203"
        );
        let s = Fb::from(168700u64).sqrt().expect("168700 is a square");
        let p = GA::new_unchecked(x * s, y);
        assert!(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() && !p.is_zero());
        p.into_group()
    })
}

/// Hash onto G (assumption A2: auxiliary group map). Try-and-increment on
/// SHA-256 for the y-coordinate, then cofactor clearing.
pub fn hash_to_group(tag: &[u8]) -> G {
    for ctr in 0u32.. {
        let mut h = Sha256::new();
        h.update(b"wod/hash-to-group/v1");
        h.update(tag);
        h.update(ctr.to_be_bytes());
        let y = Fb::from_be_bytes_mod_order(&h.finalize());
        if let Some(p) = GA::get_point_from_y_unchecked(y, false) {
            let p = p.mul_by_cofactor_to_group();
            if !p.is_zero() {
                return p;
            }
        }
    }
    unreachable!()
}

/// `h~`: the public element independent of pk used in CGY masking messages.
pub fn h_tilde() -> G {
    static P: OnceLock<G> = OnceLock::new();
    *P.get_or_init(|| hash_to_group(b"Conditional gate"))
}

pub fn rand_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> F {
    F::rand(rng)
}

/// Fixed-base comb table with 8-bit windows: `t[w][j] = j * 256^w * P`.
/// A scalar multiplication costs 32 mixed additions.
pub struct FixedBase {
    t: Vec<Vec<GA>>,
}

impl FixedBase {
    pub fn new(p: G) -> Self {
        let mut t = Vec::with_capacity(32);
        let mut base = p;
        for _ in 0..32 {
            let mut row = Vec::with_capacity(256);
            let mut acc = G::zero();
            for _ in 0..256 {
                row.push(acc);
                acc += base;
            }
            t.push(G::normalize_batch(&row));
            base = acc; // 256 * base
        }
        FixedBase { t }
    }
    pub fn mul(&self, s: &F) -> G {
        let bytes = s.into_bigint().to_bytes_le();
        let mut acc = G::zero();
        for (w, &b) in bytes.iter().enumerate().take(32) {
            if b != 0 {
                acc += &self.t[w][b as usize];
            }
        }
        acc
    }
}

/// Scalar multiplication by a width-5 NAF (odd multiples P, 3P, …, 15P).
pub fn wnaf_mul(p: &G, naf: &[i64]) -> G {
    let p2 = p.double();
    let mut tab = [*p; 8];
    for i in 1..8 {
        tab[i] = tab[i - 1] + p2;
    }
    let mut acc = G::zero();
    let mut started = false;
    for &d in naf.iter().rev() {
        if started {
            acc.double_in_place();
        }
        if d > 0 {
            acc += &tab[(d / 2) as usize];
            started = true;
        } else if d < 0 {
            acc -= &tab[(-d / 2) as usize];
            started = true;
        }
    }
    acc
}

/// Variable-base scalar multiplication (width-5 wNAF).
pub fn vmul(p: &G, s: &F) -> G {
    wnaf_mul(p, &s.into_bigint().find_wnaf(5).unwrap())
}

/// Exponential ElGamal ciphertext `(a, b) = ([r]g, [m]g + [r]h)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ct {
    #[serde(with = "arkser_fast")]
    pub a: G,
    #[serde(with = "arkser_fast")]
    pub b: G,
}

impl Ct {
    pub fn zero() -> Self {
        Ct {
            a: G::zero(),
            b: G::zero(),
        }
    }
    /// Trivial (zero-randomness) encryption of a small integer, e.g. `E_1`, `E_{-1}`.
    pub fn trivial(m: i64) -> Self {
        Ct {
            a: G::zero(),
            b: small_mul(&g(), m),
        }
    }
    pub fn add(&self, o: &Ct) -> Ct {
        Ct {
            a: self.a + o.a,
            b: self.b + o.b,
        }
    }
    pub fn sub(&self, o: &Ct) -> Ct {
        Ct {
            a: self.a - o.a,
            b: self.b - o.b,
        }
    }
    pub fn neg(&self) -> Ct {
        Ct {
            a: -self.a,
            b: -self.b,
        }
    }
    /// Multiplication of the plaintext by a public scalar.
    pub fn scale(&self, s: &F) -> Ct {
        Ct {
            a: vmul(&self.a, s),
            b: vmul(&self.b, s),
        }
    }
    /// Multiplication of the plaintext by a small public integer (add chain).
    pub fn small(&self, k: i64) -> Ct {
        Ct {
            a: small_mul(&self.a, k),
            b: small_mul(&self.b, k),
        }
    }
    pub fn points(&self) -> [G; 2] {
        [self.a, self.b]
    }
}

pub fn small_mul(p: &G, k: i64) -> G {
    let mut acc = G::zero();
    let mut base = *p;
    let mut m = k.unsigned_abs();
    while m > 0 {
        if m & 1 == 1 {
            acc += base;
        }
        base.double_in_place();
        m >>= 1;
    }
    if k < 0 { -acc } else { acc }
}

/// Public encryption key with fixed-base tables for `g` and `h`.
pub struct Key {
    pub h: G,
    pub tg: FixedBase,
    pub th: FixedBase,
}

impl Key {
    pub fn new(h: G) -> Self {
        Key {
            h,
            tg: FixedBase::new(g()),
            th: FixedBase::new(h),
        }
    }
    /// `Enc(0; r) = ([r]g, [r]h)`.
    pub fn enc0(&self, r: &F) -> Ct {
        Ct {
            a: self.tg.mul(r),
            b: self.th.mul(r),
        }
    }
    /// `Enc(m; r) = ([r]g, [m]g + [r]h)`.
    pub fn enc(&self, m: &F, r: &F) -> Ct {
        Ct {
            a: self.tg.mul(r),
            b: self.th.mul(r) + self.tg.mul(m),
        }
    }
    /// Re-encryption (rerandomization) `X + Enc(0; r)`.
    pub fn reenc(&self, x: &Ct, r: &F) -> Ct {
        x.add(&self.enc0(r))
    }
}

/// Decrypts with the full secret key (dealer/test use only) and solves a small
/// discrete logarithm in `[-bound, bound]`.
pub fn decrypt_small(sk: &F, c: &Ct, bound: i64) -> Option<i64> {
    let m = c.b - vmul(&c.a, sk);
    dlog_small(&m, bound)
}

pub fn dlog_small(m: &G, bound: i64) -> Option<i64> {
    let gg = g();
    let mut p = G::zero();
    for k in 0..=bound {
        if p == *m {
            return Some(k);
        }
        if -p == *m {
            return Some(-k);
        }
        p += gg;
    }
    None
}

/// Domain-separated SHA-256 transcript; `scalar()` reads the digest as a
/// big-endian integer modulo q (paper, assumption A2).
pub struct Hasher {
    h: Sha256,
    pts: Vec<G>,
}

impl Hasher {
    pub fn new(domain: &str, ctx: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update((domain.len() as u32).to_be_bytes());
        h.update(domain.as_bytes());
        h.update(ctx);
        Hasher {
            h,
            pts: Vec::with_capacity(24),
        }
    }
    pub fn u64(mut self, x: u64) -> Self {
        self.h.update(x.to_be_bytes());
        self
    }
    pub fn bytes(mut self, b: &[u8]) -> Self {
        self.h.update(b);
        self
    }
    /// Points are buffered and batch-normalised (one inversion) at the end.
    pub fn pts(mut self, p: &[G]) -> Self {
        self.pts.extend_from_slice(p);
        self
    }
    pub fn cts(mut self, c: &[Ct]) -> Self {
        for x in c {
            self.pts.push(x.a);
            self.pts.push(x.b);
        }
        self
    }
    pub fn digest(mut self) -> [u8; 32] {
        for p in G::normalize_batch(&self.pts) {
            // affine (x, y) encoding; the identity is (0, 1)
            let mut buf = [0u8; 64];
            p.x.serialize_uncompressed(&mut buf[..32]).unwrap();
            p.y.serialize_uncompressed(&mut buf[32..]).unwrap();
            self.h.update(buf);
        }
        self.h.finalize().into()
    }
    pub fn scalar(self) -> F {
        F::from_be_bytes_mod_order(&self.digest())
    }
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

// ------------------------------------------------ cofactor-image encoding
//
// T007. BabyJubjub has #E(F_p) = 8q, hence [8]E(F_p) = G (the q-torsion):
// any rational curve point Q yields [8]Q ∈ G, and every P ∈ G has exactly
// eight preimages Q (P/8 + E[8]). A *lift* of P is any such Q. Transcript
// format v2 sends lifts and every receiver uses [8]Q, so decoded points are
// in G without a subgroup test; senders obtain lifts at no extra cost by
// using the bases g/8, h/8, h~/8 and scalars k/8.

/// `8^{-1} mod q`.
pub fn inv8() -> F {
    static I: OnceLock<F> = OnceLock::new();
    *I.get_or_init(|| F::from(8u64).inverse().unwrap())
}

/// `[8]P` (three doublings): the canonical element of `G` encoded by a lift.
pub fn clear8(p: &G) -> G {
    let mut x = p.double();
    x.double_in_place();
    x.double_in_place();
    x
}

/// Whether extended coordinates `(X, Y, T, Z)` describe a point of the curve
/// (`X² + Y² = Z² + dT²`, `XY = TZ`, `Z ≠ 0`; arkworks' `a = 1` form). Needed
/// for coordinates returned by an untrusted device: the doubling formulas are
/// defined off the curve too.
pub fn on_curve_ext(p: &G) -> bool {
    use ark_ec::twisted_edwards::TECurveConfig;
    let (x2, y2, z2, t2) = (p.x.square(), p.y.square(), p.z.square(), p.t.square());
    !p.z.is_zero()
        && x2 + y2 == z2 + ark_ed_on_bn254::EdwardsConfig::COEFF_D * t2
        && p.x * p.y == p.t * p.z
}

/// The lift `[1/8]P` of `P ∈ G` (one variable-base multiplication).
pub fn lift_of(p: &G) -> G {
    vmul(p, &inv8())
}

/// The complete *rational* kernel of [8]. A deterministic public search finds
/// a point of exact order eight by projecting a rational point with [q].
/// The eight multiples are checked explicitly; no secret material is used.
pub fn torsion8() -> &'static [G; 8] {
    static K: OnceLock<[G; 8]> = OnceLock::new();
    K.get_or_init(|| {
        for y in 0..1024u64 {
            if let Some(p) = GA::get_point_from_y_unchecked(Fb::from(y), false) {
                let t = p.mul_bigint(F::MODULUS);
                if clear8(&t).is_zero() && !small_mul(&t, 4).is_zero() {
                    let table = std::array::from_fn(|i| small_mul(&t, i as i64));
                    for i in 0..8 {
                        assert!(on_curve_ext(&table[i]) && clear8(&table[i]).is_zero());
                        for j in 0..i {
                            assert_ne!(table[i], table[j]);
                        }
                    }
                    return table;
                }
            }
        }
        panic!("no rational point of order eight found");
    })
}

/// Uniform representative in the same cofactor-image fibre. Each invocation
/// consumes independent three-bit coins from a separate representation CSPRNG.
/// This is public-point arithmetic, never a replacement for secret nonces.
pub fn randomize_lift<R: RngCore + CryptoRng>(p: &mut G, rng: &mut R) {
    *p += torsion8()[(rng.next_u32() & 7) as usize];
}

impl Ct {
    pub fn clear8(&self) -> Ct {
        Ct {
            a: clear8(&self.a),
            b: clear8(&self.b),
        }
    }
    pub fn lift_of(&self) -> Ct {
        Ct {
            a: lift_of(&self.a),
            b: lift_of(&self.b),
        }
    }
}

/// Fixed-base tables for `g/8` and `h/8`: `[r](g/8)` is a lift of `[r]g`.
pub struct LiftKey {
    pub tg: FixedBase,
    pub th: FixedBase,
}

impl LiftKey {
    pub fn new(h: G) -> Self {
        LiftKey {
            tg: FixedBase::new(lift_of(&g())),
            th: FixedBase::new(lift_of(&h)),
        }
    }
    /// A lift of `Enc(0; r)`.
    pub fn enc0(&self, r: &F) -> Ct {
        Ct {
            a: self.tg.mul(r),
            b: self.th.mul(r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn generators_valid() {
        let gg = g().into_affine();
        assert!(gg.is_on_curve() && gg.is_in_correct_subgroup_assuming_on_curve());
        let ht = h_tilde().into_affine();
        assert!(ht.is_on_curve() && ht.is_in_correct_subgroup_assuming_on_curve());
        assert_ne!(g(), h_tilde());
        // g has order q
        assert!(vmul(&g(), &(F::from(0u64) - F::from(1u64))) + g() == G::zero());
    }

    #[test]
    fn fixed_and_window_mul_agree() {
        let mut rng = thread_rng();
        let tb = FixedBase::new(g());
        for _ in 0..20 {
            let s = rand_scalar(&mut rng);
            let want = g() * s;
            assert_eq!(tb.mul(&s), want);
            assert_eq!(vmul(&g(), &s), want);
        }
        assert_eq!(small_mul(&g(), -5), -(g() * F::from(5u64)));
    }

    #[test]
    fn elgamal_homomorphic() {
        let mut rng = thread_rng();
        let sk = rand_scalar(&mut rng);
        let k = Key::new(g() * sk);
        let c1 = k.enc(&F::from(3u64), &rand_scalar(&mut rng));
        let c2 = k.enc(&F::from(5u64), &rand_scalar(&mut rng));
        assert_eq!(decrypt_small(&sk, &c1.add(&c2), 100), Some(8));
        assert_eq!(decrypt_small(&sk, &c1.sub(&c2), 100), Some(-2));
        assert_eq!(decrypt_small(&sk, &c1.small(-3), 100), Some(-9));
        assert_eq!(decrypt_small(&sk, &c2.scale(&F::from(7u64)), 100), Some(35));
        let r = k.reenc(&c1, &rand_scalar(&mut rng));
        assert_ne!(r, c1);
        assert_eq!(decrypt_small(&sk, &r, 100), Some(3));
        assert_eq!(decrypt_small(&sk, &Ct::trivial(-1), 10), Some(-1));
    }

    #[test]
    fn point_validation_rejects_small_order() {
        // (0, -1) has order 2: on curve but not in the prime-order subgroup.
        let p = GA::new_unchecked(Fb::zero(), -Fb::ONE);
        assert!(p.is_on_curve());
        let mut v = Vec::new();
        p.serialize_compressed(&mut v).unwrap();
        assert!(G::deserialize_compressed(&v[..]).is_err());
        assert!(!in_subgroup(&p.into_group()));
        assert!(in_subgroup(&g()) && in_subgroup(&G::zero()));
        let mixed = g() + p.into_group();
        assert!(!in_subgroup(&mixed));
        let c = Ct { a: g(), b: mixed };
        let bytes = bincode::serialize(&c).unwrap();
        let back: Ct = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn cofactor_image_encoding() {
        let mut rng = thread_rng();
        let t2 = GA::new_unchecked(Fb::zero(), -Fb::ONE).into_group();
        for _ in 0..20 {
            let p = g() * rand_scalar(&mut rng);
            let q = lift_of(&p);
            assert_eq!(clear8(&q), p);
            // every lift (any torsion offset) encodes the same element
            assert_eq!(clear8(&(q + t2)), p);
            // and [8]Q lies in G for an arbitrary curve point Q
            assert!(in_subgroup(&clear8(&(q + t2))));
        }
        assert!(!in_subgroup(&t2) && clear8(&t2).is_zero());
        let r = rand_scalar(&mut rng);
        let k = Key::new(g() * rand_scalar(&mut rng));
        let lk = LiftKey::new(k.h);
        assert_eq!(lk.enc0(&r).clear8(), k.enc0(&r));
    }

    #[test]
    fn uniform_torsion_masks_the_entire_fibre_for_both_signs() {
        let k = torsion8();
        let p = lift_of(&g());
        for incoming in k {
            for sign in [-1, 1] {
                let base = small_mul(&(p + incoming), sign) + g();
                let image = clear8(&base);
                let outputs: Vec<G> = k.iter().map(|u| base + u).collect();
                assert!(outputs.iter().all(|l| clear8(l) == image));
                // Each fibre contains exactly eight outputs, each with one
                // preimage of the uniform representation coin.
                for target in k.iter().map(|u| lift_of(&image) + u) {
                    assert_eq!(outputs.iter().filter(|x| **x == target).count(), 1);
                }
            }
        }
        let images = |s: i64| -> Vec<(G, G)> {
            k.iter()
                .flat_map(|u| {
                    k.iter()
                        .map(move |v| (small_mul(&k[1], s) + u, small_mul(&k[3], s) + v))
                })
                .collect()
        };
        let plus = images(1);
        let minus = images(-1);
        assert_eq!(plus.len(), 64);
        for point in plus {
            assert_eq!(minus.iter().filter(|x| **x == point).count(), 1);
        }
    }

    #[test]
    fn wide_message_encoding_validates_curve_fields_and_scope() {
        let c = Ct {
            a: g() + torsion8()[1],
            b: G::zero(),
        };
        let normal = bincode::serialize(&c).unwrap();
        let wide = message_wire(true, || bincode::serialize(&c).unwrap());
        assert_eq!(wide.len(), normal.len() + 64);
        assert_eq!(
            message_wire(true, || bincode::deserialize::<Ct>(&wide)).unwrap(),
            c
        );
        assert_eq!(bincode::serialize(&c).unwrap(), normal); // no ambient codec change
        let bad = Ct {
            a: G::new_unchecked(Fb::ONE, Fb::ONE, Fb::ONE, Fb::ONE),
            b: c.b,
        };
        let bytes = message_wire(true, || bincode::serialize(&bad).unwrap());
        assert!(message_wire(true, || bincode::deserialize::<Ct>(&bytes)).is_err());
        let mut bad = wide;
        bad[8..40].copy_from_slice(&Fb::MODULUS.to_bytes_le());
        assert!(message_wire(true, || bincode::deserialize::<Ct>(&bad)).is_err());
        let mut extra = message_wire(true, || bincode::serialize(&c).unwrap());
        extra[..8].copy_from_slice(&65u64.to_le_bytes());
        extra.insert(72, 0);
        assert!(message_wire(true, || bincode::deserialize::<Ct>(&extra)).is_err());
        assert!(
            message_wire(true, || bincode::deserialize::<Ct>(
                &extra[..extra.len() - 1]
            ))
            .is_err()
        );
    }
}
