//! Verifiable winner-only weighted voting (Li & Li, "Enforced Winner-Only
//! Disclosure") on the conditional-gate toolbox of Cortier, Gaudry and Yang.
//!
//! Module map (bottom-up):
//! * [`group`]      BabyJubjub group, exponential ElGamal, fixed-base tables, Fiat–Shamir hashing
//! * [`subgroup`]   exact prime-order membership by an order-8 Tate pairing (T009 baseline)
//! * [`shamir`]     Shamir sharing, Lagrange interpolation, threshold decryption
//! * [`sigma`]      Σ-proofs: PoK-CSZ (masking), ZKP0 (rerandomization), DLEQ (decryption)
//! * [`circuit`]    adder tree + subtractor + terminal adapter over encrypted bits
//! * [`tdec`]       T009 second protocol: verifiable threshold ElGamal decryption (5 methods)
//! * [`tally`]      CGY conditional gates, release, trustee logic, message engine
//! * [`ballot`]     Groth16 ballot relation (Poseidon registry, nullifier, in-circuit ElGamal)
//! * [`ledger`]     admission contract (simulated chain), sealed-board commitment, claim
//! * [`setup`]      test-only dealer and file layout
//! * [`transcript`] public transcript and `H(T)`
//! * [`net`]        authenticated board (coordinator) and trustee processes over TCP
//! * [`verify`]     independent public verifier
//! * [`oracle`]     isolated plaintext oracle (testing only)
//! * [`experiment`], [`bench`] experiment runner and micro-benchmarks

pub mod ballot;
pub mod batch;
pub mod bench;
pub mod circuit;
pub mod evm;
pub mod experiment;
pub mod gpu;
pub mod group;
pub mod ledger;
pub mod net;
pub mod oracle;
pub mod setup;
pub mod shamir;
pub mod sigma;
pub mod subgroup;
pub mod tally;
pub mod tdec;
pub mod transcript;
pub mod verify;
