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

## Controlled scheduler comparison

The [measured comparison and paper-ready table](reports/summary.md) and
[public measurement index](evidence/schedulers.json) record the paired results,
timing boundaries, source revision and checksums.

Run the same circuit and admitted ballots through both local scheduling policies:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\reproduce.ps1 -SchedulerComparison -SchedulerThreads 24
```

This explicit profile runs n=8,64,256 with three fresh paired elections each and
n=1024 with one pair. Within each pair, setup, weights, votes, threshold, admitted
ciphertexts and trustee keys are identical. Each tally uses fresh protocol randomness,
all cryptographic checks and the same 24-thread Rayon setting. Reference/dataflow
order alternates across pairs; manifests record the order. Setup/proving/admission
are separate from tally. This profile skips operation microbenchmarks and uses no
cloud hosts, latency injection or blockchain calls. Use `-N 8 -Reps 1` for a small
reproduction. Output directories are unique, and previous results remain intact.

The reference policy serializes each ripple adder's gates in construction order,
allows different adders in a tree level to progress independently, and places
barriers between tree levels before the sequential subtractor. Dataflow dispatches
all currently enabled gates. Both use the original gate IDs, DAG, proofs and release;
public verification needs no scheduler flag. Reference depths are 72/147/207/275;
dataflow depths are 25/37/45/53. These depths are distinct from runtime and message count.

Direct CLI selection is `wod tally --dir DIR --scheduler reference|dataflow` or
`wod experiment --n 8 --modes local --scheduler both --reps 3 --out FRESH_DIR`.
Dataflow remains the default; TCP commands retain dataflow. `both` alternates the
two policies, and `--order-offset` sets the starting parity across batches.
Local tally timing includes role/RNG and public-engine initialization, scheduling,
proof production/checks, encrypted affine propagation, serialization, signatures,
transcript hashing and final flush. Gate, release, finalization and initialization
fields state the boundaries. Claim publication, public replay, oracle, setup and
ballot proving are outside tally timing. This is a same-circuit execution benchmark,
not a comparison with CGY's independently implemented voting systems.

## GPU research branch (T005)

Branch `research/gpu-exploration` adds an optional, off-by-default GPU path for
the public verification arithmetic of the encrypted tally; the CPU path above
remains the reference. Default builds and commands are unchanged.

- `--verify-backend cpu|cuda[:DEV]|auto:MIN[:DEV]|emu` (any command; inherited
  by trustee/verifier subprocesses) verifies each board message in one batch of
  BabyJubjub scalar multiplications. Only public transcript data is batched.
- `cargo build --release --features cuda` (CUDA 12.x NVRTC) or `cuda13`;
  no CUDA toolkit is needed to *build*, the NVRTC/driver libraries are loaded at
  run time. `cuda-emu` compiles the same kernel source as host C++ for tests.
- `wod profile`, `wod gpu-check`, `wod gpu-bench`, `wod gpu-vectors`,
  `wod gpu-summary`; the complete local RTX workflow is
  `powershell -NoProfile -ExecutionPolicy Bypass -File .\reproduce_gpu.ps1`.

Design, CPU profiling evidence, correctness status and the local GPU handoff
are in [reports/T005.md](reports/T005.md).

Stage B (`research/gpu-stage-b`) records actual RTX 4050 validation in
[reports/T006.md](reports/T006.md). Windows CUDA builds reserve a larger compiler
stack; adaptive dispatch initializes CUDA only when a batch reaches its threshold.
`gpu-bench` includes the original inline verifier and retains raw samples.
For paired full-protocol trials, `reproduce_gpu.ps1 -ProtocolOnly -SkipBuild
-SkipTests -PreparedInputs DIR -MinBatch 4096 -TallyN 8,64,256,1024` reads genuine
pre-claim elections at `DIR/**/nN/rep0/base/`, copies them to fresh outputs, rotates
backend order, and requires public-only CPU replay and oracle agreement.
It uses three repetitions at n=8/64 and one at n=256/1024 by default.
`wod tally --mode dist` reuses the existing five-process TCP runner.

GPU jobs contain public values. Correct arithmetic is still an integrity
assumption: sampling or public inputs alone do not make a malicious GPU safe.
Independent CPU replay protects the final experimental acceptance decision;
it cannot retroactively undo online trustee actions after faulty verification.

## Optional EVM reproduction

`contracts/WodAdmission.sol` and `tests/evm_local.cjs` support local EVM validation. `tests/evm_arbitrum.cjs` runs the separate Arbitrum Sepolia admission and receipt experiment. Setup, local validation, cost estimation, and the explicitly opt-in broadcast procedure are documented in [docs/ARBITRUM_SEPOLIA.md](docs/ARBITRUM_SEPOLIA.md).

Verified Arbitrum Sepolia measurements and transaction links are summarized in [evidence/README.md](evidence/README.md). Re-running the experiment deploys a fresh poll; it does not reuse these transactions.

Never commit `.env`, wallet credentials, trustee shares, voter secrets, oracle inputs, or generated local runs. The testnet runner supports a read-only `--preflight-only` estimate; it sends transactions only when explicitly invoked with `--broadcast` and checks the configured spending cap before the first transaction.

## Scope and limitations

The default distributed workflow launches five trustee processes on one host and loads indexed shares from a shared directory. A separate [multi-host procedure](docs/MULTIHOST.md) provisions one Board VM and five Trustee VMs, with only each Trustee's own key file on its host. [Measured results](evidence/multihost.json) cover n=8 and 64 with three repetitions, and n=256 and 1024 with one repetition. Distinct physical servers and independent operators are not established. Setup uses a test-only dealer and the common-view TCP board remains trusted.

The admission adapter records a decision claim; independent Rust replay verifies the tally transcript. The optional `ReplayGatedExecutor` demonstrates a fixed governance action after receipt-derived public verification and an EIP-712 authorization. It additionally trusts the named attesting verifier and authenticated RPC view; it does not verify CGY on chain. [The separate execution evidence](evidence/governance.json) records the n=8 Sepolia demonstration and local rejection tests. This is a research prototype, not a production governance deployment.

The [public evidence package](https://github.com/CryptographyBloke/DAOVoting/releases/tag/v0.2.0) contains independently replayable public inputs, original manifests, per-host measurements and SHA-256 checksums. Private inputs and large transcripts stay outside Git history.

The code is organized in `src/`, integration tests in `tests/`, and the admission adapter in `contracts/`. Dependencies are pinned in `Cargo.lock`.
