//! Shamir secret sharing of the ElGamal key and threshold decryption
//! (CGY Appendix A.2). Trustee `i` (1-based) holds `s_i = P(i)` and the
//! public commitment `h_i = [s_i]g`; `pk = [P(0)]g`.

use crate::group::*;
use ark_ff::{Field, One, Zero};
use rand::{CryptoRng, RngCore};

/// Test-only dealer: degree-`t` polynomial, `a` shares. Returns
/// `(sk, shares s_1..s_a)`. A deployment replaces this by a DKG.
pub fn deal<R: RngCore + CryptoRng>(t: usize, a: usize, rng: &mut R) -> (F, Vec<F>) {
    let coeffs: Vec<F> = (0..=t).map(|_| rand_scalar(rng)).collect();
    let shares = (1..=a as u64)
        .map(|i| {
            let x = F::from(i);
            coeffs.iter().rev().fold(F::zero(), |acc, c| acc * x + c)
        })
        .collect();
    (coeffs[0], shares)
}

/// Lagrange coefficients at 0 for the 1-based indices in `set`.
pub fn lagrange(set: &[usize]) -> Vec<F> {
    set.iter()
        .map(|&i| {
            let xi = F::from(i as u64);
            let (mut num, mut den) = (F::one(), F::one());
            for &j in set {
                if j != i {
                    let xj = F::from(j as u64);
                    num *= xj;
                    den *= xj - xi;
                }
            }
            num * den.inverse().unwrap()
        })
        .collect()
}

/// Combines partial decryptions `w_i = [s_i]u` (indices `set`) of `c` and
/// returns the plaintext group element `[m]g = b − Σ λ_i w_i`.
pub fn combine(c: &Ct, set: &[usize], w: &[G], lam: &[F]) -> G {
    debug_assert_eq!(set.len(), w.len());
    let mut acc = c.b;
    for (wi, li) in w.iter().zip(lam) {
        acc -= vmul(wi, li);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn threshold_decrypt_5_of_5_and_t_plus_1() {
        let mut rng = thread_rng();
        let (sk, sh) = deal(4, 5, &mut rng);
        let k = Key::new(g() * sk);
        let c = k.enc(&F::from(1u64), &rand_scalar(&mut rng));
        let set: Vec<usize> = (1..=5).collect();
        let w: Vec<G> = sh.iter().map(|s| vmul(&c.a, s)).collect();
        assert_eq!(combine(&c, &set, &w, &lagrange(&set)), g());
        // any 4 shares of a degree-4 polynomial do not suffice
        let set4 = [1, 2, 3, 4];
        assert_ne!(combine(&c, &set4, &w[..4], &lagrange(&set4)), g());
        // degree-2 sharing: any 3 suffice
        let (sk2, sh2) = deal(2, 5, &mut rng);
        let k2 = Key::new(g() * sk2);
        let c2 = k2.enc(&F::from(0u64), &rand_scalar(&mut rng));
        let set3 = [2, 4, 5];
        let w3: Vec<G> = set3.iter().map(|&i| vmul(&c2.a, &sh2[i - 1])).collect();
        assert!(combine(&c2, &set3, &w3, &lagrange(&set3)).is_zero());
    }
}
