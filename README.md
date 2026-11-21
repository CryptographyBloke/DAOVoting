# Weighted voting research artifact

This repository contains the Rust implementation and scripts used to reproduce experiments for *Enforced Winner-Only Disclosure: Verifiable Tally Hiding for Weighted On-Chain Governance*. It computes the encrypted weighted threshold decision

```text
W = Σᵢ vᵢwᵢ,     b = [W ≥ τ]
```

and releases `b` without reconstructing `W`. Ballots use BabyJubjub exponential ElGamal and Groth16 proofs. Five trustees evaluate the CGY conditional-gate circuit.

## Requirements

- Windows PowerShell 5.1 or 7 and Git.
- Rust stable with the MSVC toolchain. The first build needs access to crates.io.
- Node.js and npm only for the optional local EVM and Arbitrum Sepolia steps.

## Reproduce the local experiments

From the repository root:

```powershell
cargo fmt --check
cargo build --release --locked
cargo test --release --locked
powershell -ExecutionPolicy Bypass -File .\reproduce.ps1
```

The default run performs the single-gate checks, operation benchmarks, and the n=8 local and five-process experiments with three repetitions and configured RTTs of 0, 10, and 50 ms. To reproduce the larger scales:

```powershell
powershell -ExecutionPolicy Bypass -File .\reproduce.ps1 -Large
```

Or select parameters directly:

```powershell
powershell -ExecutionPolicy Bypass -File .\reproduce.ps1 -N 8,64 -Reps 3 -RttMs 0,10,50
```

Each invocation creates a unique run directory under `results/local/`, with a manifest recording the source revision, machine, parameters, measurements, verification outcomes, and public-file hashes. `public/` contains verifier inputs; `private/` and `work/` contain secrets or proving materials and must not be published. Large-scale runs can take substantially longer than n=8.

## Optional EVM reproduction

`contracts/WodAdmission.sol` and `tests/evm_local.cjs` support local EVM validation. `tests/evm_arbitrum.cjs` runs the separate Arbitrum Sepolia admission and receipt experiment. Setup, local validation, cost estimation, and the explicitly opt-in broadcast procedure are documented in [docs/ARBITRUM_SEPOLIA.md](docs/ARBITRUM_SEPOLIA.md).

Never commit `.env`, wallet credentials, trustee shares, voter secrets, oracle inputs, or generated local runs. The testnet runner supports a read-only `--preflight-only` estimate; it sends transactions only when explicitly invoked with `--broadcast` and checks the configured spending cap before the first transaction.

## Scope and limitations

The distributed workflow launches five trustee processes on one host. They load separate shares from a shared local directory; this does not provide OS or hardware isolation. Setup uses a test-only dealer and the TCP board is trusted. The Solidity adapter verifies ballots and admission, then records a decision claim; independent Rust replay verifies the tally transcript. The adapter does not run the encrypted tally on chain. This artifact is a research prototype, not a production governance deployment.

The code is organized in `src/`, integration tests in `tests/`, and the admission adapter in `contracts/`. Dependencies are pinned in `Cargo.lock`.
