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

The runner requires a clean committed tree, a fresh output path, passing local verification and oracle agreement, a spend ledger, and `--broadcast`. It checks the budget before sending the first transaction and records each receipt. For each voter count, generate a fresh protocol run and local EVM summary, then invoke:

```powershell
$chainOut = Join-Path "results/local/$runId" 'arbitrum-sepolia/n8'
$ledger = Join-Path "results/local/$runId" 'spend-ledger.json'
node tests/evm_arbitrum.cjs --dir $runDir `
  --local-summary (Join-Path $evmOut 'public/evm-local-summary.json') `
  --out-dir $chainOut --budget-ledger $ledger --env-file (Join-Path $PWD '.env') `
  --wod .\target\release\wod.exe --tools $evmTools --broadcast
```

Choose new output directories for every run and keep the same ledger across the batch. Successful receipts, public inputs, events, contract details, and Rust replay results are written below `results/local/`. Private shares, voter material, oracle plaintext, and proving work remain local and are not exported. Reproductions create new transactions and gas measurements; they do not reuse historical receipts.
