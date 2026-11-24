//! Exact prime-order subgroup membership for BabyJubjub by an order-8 Tate
//! pairing (T009 strong baseline).
//!
//! `E(F_p) ≅ Z/8 × Z/q` with a rational point `T` of exact order eight, and
//! `8 | p − 1`. The reduced Tate pairing `t_8(T, ·) : E(F_p)/8E(F_p) → μ_8` is
//! non-degenerate, so for a point `P` of `E(F_p)`
//!
//! `P ∈ G = 8E(F_p)  ⇔  f_{8,T}(P)^{(p−1)/8} = 1`,
//!
//! where `f_{8,T}` is the normalised Miller function with divisor
//! `8(T) − 8(O)`. This is the cofactor-8 instance of Koshelev's
//! pairing-based membership test (ePrint 2022/037); Divide-and-Pair
//! (ePrint 2026/749) reduces to it for twisted Edwards curves of this shape.
//!
//! In short-Weierstrass coordinates of the birationally equivalent curve,
//! `f_{8,T} = l_T⁴ · l_{2T}² / (v_{2T}⁴ · v_{4T})` with the tangent lines
//! `l_T`, `l_{2T}` and the verticals `v_{2T}`, `v_{4T}`. All of these are
//! monic in `Y` or `X`, hence normalised at `O`, so no constant survives the
//! final exponentiation. The function is evaluated projectively from the
//! Edwards coordinates (no inversion), followed by one exponentiation by
//! `(p−1)/8`. Torsion points, the only points where the evaluation can be
//! zero or undefined, are handled separately: a torsion point is in `G` iff
//! it is the identity.

use crate::group::{G, clear8, torsion8};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ed_on_bn254::{EdwardsConfig, Fq as Fb};
use ark_ff::{AdditiveGroup, Field, One, PrimeField, Zero};
use std::sync::OnceLock;

struct Tate {
    a_m: Fb,
    b_m: Fb,
    lam1: Fb,
    k1: Fb,
    x2: Fb,
    lam2: Fb,
    k2: Fb,
    x4: Fb,
    e: Vec<u64>,
}

fn tate() -> &'static Tate {
    static T: OnceLock<Tate> = OnceLock::new();
    T.get_or_init(|| {
        let (a, d) = (EdwardsConfig::COEFF_A, EdwardsConfig::COEFF_D);
        // Montgomery B v² = u³ + A u² + u and short Weierstrass X = u/B + A/(3B), Y = v/B.
        let a_m = (a + d).double() * (a - d).inverse().unwrap();
        let b_m = Fb::from(4u64) * (a - d).inverse().unwrap();
        let three = Fb::from(3u64);
        let a4 = (three - a_m.square()) * (three * b_m.square()).inverse().unwrap();
        let to_w = |p: &G| -> (Fb, Fb) {
            let z = p.z.inverse().unwrap();
            let (x, y) = (p.x * z, p.y * z);
            let u = (Fb::one() + y) * (Fb::one() - y).inverse().unwrap();
            let v = u * x.inverse().unwrap();
            let bi = b_m.inverse().unwrap();
            (u * bi + a_m * (three * b_m).inverse().unwrap(), v * bi)
        };
        let t = torsion8()[1];
        let (xt, yt) = to_w(&t);
        // the curve equation is checked implicitly by the doubling chain below
        let tangent = |x: Fb, y: Fb| (three * x.square() + a4) * y.double().inverse().unwrap();
        let lam1 = tangent(xt, yt);
        let x2 = lam1.square() - xt.double();
        let y2 = lam1 * (xt - x2) - yt;
        let lam2 = tangent(x2, y2);
        let x4 = lam2.square() - x2.double();
        let y4 = lam2 * (x2 - x4) - y2;
        assert!(y4.is_zero(), "4T must be the rational 2-torsion point");
        // cross-check 2T against the Edwards doubling
        assert_eq!(to_w(&torsion8()[2]), (x2, y2));
        let mut e = Fb::MODULUS;
        e.sub_with_borrow(&ark_ff::BigInt::from(1u64));
        for _ in 0..3 {
            e.div2();
        }
        Tate {
            a_m,
            b_m,
            lam1,
            k1: yt - lam1 * xt,
            x2,
            lam2,
            k2: y2 - lam2 * x2,
            x4,
            e: e.0.to_vec(),
        }
    })
}

use ark_ff::BigInteger;

/// `f_{8,T}(P)^{(p−1)/8}` for a non-torsion point `P` (an 8th root of unity).
fn pairing_value(p: &G) -> Fb {
    let t = tate();
    // Edwards (X:Y:Z) with x = X/Z, y = Y/Z; Weierstrass X_w = Xn/D, Y_w = Yn/D
    // up to the common factor Z² that cancels between numerator and denominator.
    let (n, m) = (p.z + p.y, p.z - p.y);
    let xn = (n.double() + n + t.a_m * m) * p.x;
    let yn = (n.double() + n) * p.z;
    let dd = Fb::from(3u64) * t.b_m * m * p.x;
    let l1 = yn - t.lam1 * xn - t.k1 * dd;
    let l2 = yn - t.lam2 * xn - t.k2 * dd;
    let v2 = xn - t.x2 * dd;
    let v4 = xn - t.x4 * dd;
    let num = l1.square().square() * l2.square();
    let den = v2.square().square() * v4 * dd;
    // (num/den)^e = (num · den^7)^e because den^{8e} = den^{p−1} = 1
    let den7 = den.square() * den;
    let den7 = den7.square() * den;
    (num * den7).pow(&t.e)
}

/// Exact membership `P ∈ G` for an on-curve point (one exponentiation).
pub fn in_subgroup_tate(p: &G) -> bool {
    if clear8(p).is_zero() {
        return p.is_zero();
    }
    pairing_value(p).is_one()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{in_subgroup, rand_scalar, vmul};
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn tate_membership_matches_q_multiplication() {
        let mut rng = thread_rng();
        let tor = torsion8();
        for i in 0..8 {
            assert_eq!(in_subgroup_tate(&tor[i]), i == 0);
        }
        // the pairing is a character of E(F_p)/8E(F_p): values multiply
        let base = vmul(&crate::group::g(), &rand_scalar(&mut rng));
        let w1 = pairing_value(&(base + tor[1]));
        for k in 0..8 {
            let p = vmul(&crate::group::g(), &rand_scalar(&mut rng)) + tor[k];
            assert_eq!(in_subgroup_tate(&p), k == 0);
            assert_eq!(in_subgroup_tate(&p), in_subgroup(&p));
            assert_eq!(pairing_value(&p), w1.pow([k as u64]), "character at T^{k}");
        }
        // random rational curve points (any torsion component)
        let mut seen = [false; 2];
        for _ in 0..64 {
            let y = Fb::rand(&mut rng);
            if let Some(a) = crate::group::GA::get_point_from_y_unchecked(y, false) {
                let p: G = a.into();
                let want = in_subgroup(&p);
                seen[want as usize] = true;
                assert_eq!(in_subgroup_tate(&p), want);
            }
        }
        assert!(seen[0]);
        assert!(
            w1.pow([8u64]).is_one() && !w1.pow([4u64]).is_one(),
            "order-8 character"
        );
    }
}
