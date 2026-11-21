# Arbitrum Sepolia reproduction

This is an optional on-chain experiment. The Solidity adapter verifies Groth16 ballot proofs, admission, nullifiers, sealing, and a decision claim. It does not verify the tally transcript or perform the encrypted tally; the Rust public verifier replays that transcript.

The testnet runner submits real transactions and spends testnet ETH. Use only a dedicated test wallet, estimate the full profile cost first, and pass `--broadcast` only when you intend to send the transactions.

## Configure PowerShell

Use an Alchemy Arbitrum Sepolia endpoint and chain ID `421614`. From the repository root, create a local ignored `.env` file and enter credentials without echoing them:

```powershell
Copy-Item .env.example .env
$rpcSecure = Read-Host 'Alchemy Arbitrum Sepolia HTTPS URL' -AsSecureString
$keySecure = Read-Host 'Dedicated test wallet private key' -AsSecureString
$maxEth = Read-Host 'Maximum total testnet ETH spend, e.g. 0.1'
$rpcPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($rpcSecure)
$keyPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($keySecure)
try {
    $rpc = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($rpcPtr)
    $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPtr)
    $body = @(
        "ARB_SEPOLIA_RPC_URL=$rpc"
        "ARB_SEPOLIA_PRIVATE_KEY=$key"
        'ARB_SEPOLIA_CHAIN_ID=421614'
        "ARB_SEPOLIA_MAX_TOTAL_ETH=$maxEth"
    ) -join "`n"
    [IO.File]::WriteAllText((Join-Path $PWD '.env'), $body, [Text.UTF8Encoding]::new($false))
    Write-Host 'Local .env written; credentials were not printed.'
}
finally {
    if ($rpcPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($rpcPtr) }
    if ($keyPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPtr) }
    $rpc = $null; $key = $null; $rpcSecure = $null; $keySecure = $null
}
git check-ignore .env
```

Keep the spend ledger for the whole batch. Never print the private key or full RPC URL, or commit `.env`.

## Validate locally first

The local Ganache test does not broadcast to a network. Install its pinned tools outside the repository:

```powershell
$evmTools = Join-Path $env:TEMP 'wod-evm-tools'
npm install --prefix $evmTools --no-save solc@0.8.30 ganache@7.9.2 ethers@6.17.0
cargo build --release --locked
cargo test --release --locked
```

Create a fresh n=8 local run and exercise the Solidity verifier and event replay:

```powershell
$commit = (git rev-parse --short HEAD).Trim()
$protocolCommit = (git rev-parse HEAD).Trim()
$runId = "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$commit-evm"
$experimentOut = Join-Path "results/local/$runId" 'experiment'
$evmOut = Join-Path "results/local/$runId" 'evm-local'
.\target\release\wod.exe experiment --n 8 --modes local --reps 1 --out $experimentOut
$runDir = Join-Path $experimentOut 'n8\rep0\local'
node tests/evm_local.cjs --dir $runDir --out-dir $evmOut --wod .\target\release\wod.exe --tools $evmTools
```

The local test checks valid Rust-generated proofs, modified proofs and inputs, duplicate nullifiers, premature sealing, decision claims, and Rust reconstruction of the emitted board. Local EVM gas is not Arbitrum gas.

## Estimate and broadcast

Before broadcasting, check RPC connectivity, chain ID, locally derived wallet address, balance, gas price, current base fee, and the configured cap. Estimate deployments, registration, each ballot, sealing, and the final claim using the actual bytecode and calldata.

Arbitrum incorporates L1 data-posting cost into its gas estimate. `NodeInterface.gasEstimateComponents()` reports `gasEstimate`, `gasEstimateForL1`, `baseFee`, and `l1BaseFeeEstimate`; do not add the L1 component twice. See [Arbitrum gas estimation](https://docs.arbitrum.io/arbitrum-essentials/how-to-estimate-gas) and the [NodeInterface reference](https://docs.arbitrum.io/arbitrum-essentials/nodeinterface/reference).

The runner requires a clean committed tree, a fresh output path, passing local verification and oracle agreement, and a spend ledger. For each voter count, generate a fresh protocol run and local EVM summary. First run the read-only estimate with its own output path:

```powershell
$preflightOut = Join-Path "results/local/$runId" 'preflight/n8'
$ledger = Join-Path "results/local/$runId" 'spend-ledger.json'
node tests/evm_arbitrum.cjs --dir $runDir `
  --local-summary (Join-Path $evmOut 'public/evm-local-summary.json') `
  --out-dir $preflightOut --budget-ledger $ledger --env-file (Join-Path $PWD '.env') `
  --wod .\target\release\wod.exe --tools $evmTools --preflight-only `
  --protocol-run-commit $protocolCommit
```

Review the estimate manifest and confirm it fits both the configured cap and wallet balance. The read-only mode does not reserve funds or send transactions. Only then use a fresh output path and pass `--broadcast`:

For large profiles, `--batch-size` accepts 1–16 ballots. The runner assigns sequential wallet nonces, submits each bounded group in order, and waits for every receipt before starting the next group. It stops after any failed receipt. Pass `--protocol-run-commit` when the Rust run was produced by a different source revision than the current runner.

```powershell
$chainOut = Join-Path "results/local/$runId" 'arbitrum-sepolia/n8'
node tests/evm_arbitrum.cjs --dir $runDir `
  --local-summary (Join-Path $evmOut 'public/evm-local-summary.json') `
  --out-dir $chainOut --budget-ledger $ledger --env-file (Join-Path $PWD '.env') `
  --wod .\target\release\wod.exe --tools $evmTools --broadcast `
  --batch-size 16 --protocol-run-commit $protocolCommit
```

Choose new output directories for every run and keep the same ledger across the batch. Successful receipts, public inputs, events, contract details, and Rust replay results are written below `results/local/`. Private shares, voter material, oracle plaintext, and proving work remain local and are not exported. Reproductions create new transactions and gas measurements; they do not reuse historical receipts.

If a process stops after broadcasting transactions, keep the original protocol run, output directory, and spend ledger. Commit the runner fix first, then rerun the same command with `--resume`. Resume checks the original manifest and public inputs, polls unresolved receipts with bounded concurrency, matches the accepted on-chain ballot count to the manifest, and continues from that count using the existing poll. It refuses a completed run or mismatched inputs. Do not create a second poll to recover an interrupted batch.

## Optional replay-authorized governance action

`contracts/ReplayExecutor.sol` adds a small executor and test governed parameter.
This path is separate from the original four-scale admission measurements.
It uses an immutable authorized verification EOA, not an on-chain CGY verifier.
The honest-verifier and authenticated-RPC assumptions are additional to the
cryptographic protocol. The original admission contract exposes sealed state and
a claimed flag; the verifier authenticates the exact decision/hash from its events.

The [EIP-712](https://eips.ethereum.org/EIPS/eip-712) statement binds chain ID,
executor address, admission address, poll, complete setup hash, threshold, sealed
board commitment, transcript hash, decision, action hash and nonce. The owner fixes
the proposal action and setup before ballot admission. Execution requires decision
1, current sealed/claimed poll state and the named authority's canonical signature.
An executed flag and consumed nonce prevent reuse. No test target funds are transferred.
This construction relies on the authority to sign only correct public verification;
a malicious authority can sign a false assertion. It does not inherit all-malicious
trustee correctness as an automatic on-chain guarantee.

First create independent approving/rejecting test elections and run the local tests:

```powershell
$yes = Join-Path "results/local/$runId" 'approve'
$no = Join-Path "results/local/$runId" 'reject'
$executorTests = Join-Path "results/local/$runId" 'executor-local'
.\target\release\wod.exe experiment --n 8 --modes local --reps 1 --tau 1 --out $yes
if ($LASTEXITCODE -ne 0) { throw 'approving fixture failed' }
.\target\release\wod.exe experiment --n 8 --modes local --reps 1 --tau 300 --out $no
if ($LASTEXITCODE -ne 0) { throw 'rejecting fixture failed' }
node tests/evm_executor.cjs --dir (Join-Path $yes 'n8/rep0/local') `
  --reject-dir (Join-Path $no 'n8/rep0/local') --out-dir $executorTests `
  --wod .\target\release\wod.exe --tools $evmTools
if ($LASTEXITCODE -ne 0) { throw 'executor tests failed' }
```

The approval fixture must actually release 1; create another fresh fixture if it
releases 0. The rejection fixture's threshold exceeds
the sum of its public example weights. The tests exercise genuine Rust proofs,
public-only chain replay, wrong bindings/signatures/domains, tampering, decision 0,
duplicate execution and nonce reuse. All rejected actions leave the target unchanged.

Use the approving run with `evm_local.cjs`, then add `--execute` and
`--execution-summary "$executorTests/public/executor-summary.json"` to the ordinary
testnet runner command, with fresh preflight and broadcast paths. Keep the existing
spend ledger. Review the read-only estimate before explicitly using `--broadcast`.
The n=8 execution profile requires 18 successful transactions and deploys fresh
executor/target contracts. Its attestation authority is generated locally and
stored only in the ignored run's `private/` directory; restrict local file access.

Before signing, the production helper retrieves poll transaction receipts again
from the live RPC, checks canonical block hashes and pinned runtime identity,
then invokes `wod evm-verify-chain` using only `setup.bin`, `transcript.bin` and the
receipt bundle. No simulated `ledger.bin` enters that verifier directory.
All seven acceptance components must pass. A subsequent block confirms the RPC
view; this is not a light-client or L1-finality proof. Public attestation files
contain the signature and authority address, never the private key.

For a stopped execution profile, automatic recovery is deliberately restricted:
`--execute --resume` accepts exactly 17 confirmed deployment/poll transactions,
the original authority, and no prior execution receipts/report/attestation files.
Inspect the transaction journal and keep `--protocol-run-commit` pinned to the
original run. Recovery fetches live receipts without depending on a large
`eth_getLogs` range and sends only the remaining action transaction. Other partial
execution states require explicit journal inspection; never deploy a duplicate
poll to hide a failed run or reset the spending ledger.
