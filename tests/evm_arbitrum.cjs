// Budget-capped Arbitrum Sepolia runner. It broadcasts only with --broadcast.
// Private configuration is read from .env and is never copied to output/logs.
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

function args(argv) {
  const out = { broadcast: false, preflightOnly: false, resume: false, execute: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--broadcast') { out.broadcast = true; continue; }
    if (argv[i] === '--preflight-only') { out.preflightOnly = true; continue; }
    if (argv[i] === '--resume') { out.resume = true; continue; }
    if (argv[i] === '--execute') { out.execute = true; continue; }
    if (!argv[i].startsWith('--') || !argv[i + 1]) throw new Error('expected --name value');
    out[argv[i].slice(2)] = argv[++i];
  }
  return out;
}
function sha256(data) { return crypto.createHash('sha256').update(data).digest('hex'); }
function loadEnv(file) {
  const out = {};
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && m[2] && !m[2].startsWith('#')) out[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
  }
  return out;
}
function writeJson(file, value) { fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n'); }
function runRust(binary, argv) {
  const r = spawnSync(binary, argv, { encoding: 'utf8', windowsHide: true });
  if (r.error || r.status !== 0) throw new Error('Rust public verification command failed');
  return JSON.parse(r.stdout);
}
function max(a, b) { return a > b ? a : b; }
function ceilMul(a, b, d) { return (a * b + d - 1n) / d; }

(async () => {
  let stage = 'arguments';
  const opt = args(process.argv.slice(2));
  for (const k of ['dir', 'out-dir', 'local-summary', 'wod', 'tools', 'budget-ledger']) {
    if (!opt[k]) throw new Error(`missing --${k}`);
  }
  if (opt.broadcast === opt.preflightOnly) throw new Error('select exactly one of --preflight-only or --broadcast');
  if (opt.resume && !opt.broadcast) throw new Error('--resume requires --broadcast');
  if (opt.execute && !opt['execution-summary']) throw new Error('--execute requires --execution-summary from passing local executor tests');
  const ballotBatchSize = Number(opt['batch-size'] || 1);
  if (!Number.isInteger(ballotBatchSize) || ballotBatchSize < 1 || ballotBatchSize > 16) {
    throw new Error('--batch-size must be an integer from 1 to 16');
  }
  const repo = path.resolve(__dirname, '..');
  const runDir = path.resolve(opt.dir), outDir = path.resolve(opt['out-dir']);
  const ledgerPath = path.resolve(opt['budget-ledger']);
  const localRoot = path.resolve(repo, 'results', 'local') + path.sep;
  for (const p of [outDir, ledgerPath]) {
    if (!p.startsWith(localRoot)) throw new Error('experiment output and budget ledger must stay under results/local');
  }
  if (opt.resume ? !fs.existsSync(outDir) : fs.existsSync(outDir)) {
    throw new Error(opt.resume ? 'resume output directory does not exist' : 'refusing to reuse an existing output directory');
  }
  if (!fs.existsSync(path.join(runDir, 'public', 'setup.bin')) || !fs.existsSync(path.join(runDir, 'public', 'ledger.bin'))) {
    throw new Error('run is missing public setup or admission ledger');
  }
  const env = loadEnv(path.resolve(opt['env-file'] || path.join(repo, '.env')));
  for (const k of ['ARB_SEPOLIA_RPC_URL', 'ARB_SEPOLIA_PRIVATE_KEY', 'ARB_SEPOLIA_CHAIN_ID', 'ARB_SEPOLIA_MAX_TOTAL_ETH']) {
    if (!env[k]) throw new Error('required local environment configuration is missing');
  }
  if (env.ARB_SEPOLIA_CHAIN_ID !== '421614') throw new Error('configured chain ID must be 421614');
  const cap = require(path.join(path.resolve(opt.tools), 'node_modules', 'ethers')).parseEther(env.ARB_SEPOLIA_MAX_TOTAL_ETH);
  const ethers = require(path.join(path.resolve(opt.tools), 'node_modules', 'ethers'));
  const solc = require(path.join(path.resolve(opt.tools), 'node_modules', 'solc'));
  const wallet = new ethers.Wallet(env.ARB_SEPOLIA_PRIVATE_KEY);
  const provider = new ethers.JsonRpcProvider(env.ARB_SEPOLIA_RPC_URL, 421614, { staticNetwork: true });
  const publicDir = path.join(outDir, 'public');
  fs.mkdirSync(publicDir, { recursive: true });
  const publicInputPath = path.join(publicDir, 'evm-public-input.json');
  const logsPath = path.join(publicDir, 'evm-chain-logs.json');
  const manifestPath = path.join(publicDir, 'manifest.json');
  const existingManifest = opt.resume ? JSON.parse(fs.readFileSync(manifestPath, 'utf8')) : null;
  if (opt.resume && (!fs.existsSync(publicInputPath) || existingManifest.status !== 'BROADCAST_STARTED')) {
    throw new Error('resume requires the original public input and an unfinished manifest');
  }
  const ledgerLock = `${ledgerPath}.lock`;
  let lockFd;
  try {
    stage = 'source and public input validation';
    const head = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', cwd: repo });
    const status = spawnSync('git', ['status', '--porcelain', '--untracked-files=all'], { encoding: 'utf8', cwd: repo });
    if (head.status !== 0 || status.status !== 0 || status.stdout.trim()) throw new Error('source must be committed and clean before publication measurements');
    const runManifest = JSON.parse(fs.readFileSync(path.join(runDir, 'public', 'manifest.json'), 'utf8'));
    const protocolRunCommit = opt['protocol-run-commit'] || runManifest.source_commit || head.stdout.trim();
    if (!/^[0-9a-f]{40}$/i.test(protocolRunCommit)) throw new Error('protocol run commit must be a full Git SHA');
    const priorVerification = JSON.parse(fs.readFileSync(path.join(runDir, 'public', 'verify.json'), 'utf8'));
    if (priorVerification.accept !== true || runManifest.oracle_agrees !== true) throw new Error('Rust verifier and oracle checks must both pass');
    // Verification must not overwrite verify.json inside a frozen source run.
    const verificationDir = path.join(outDir, 'work', 'local-verifier');
    fs.mkdirSync(path.join(verificationDir, 'public'), { recursive: true });
    for (const name of ['setup.bin', 'ledger.bin', 'transcript.bin']) {
      fs.copyFileSync(path.join(runDir, 'public', name), path.join(verificationDir, 'public', name));
    }
    const verify = runRust(path.resolve(opt.wod), ['verify', '--dir', verificationDir]);
    if (verify.accept !== true) throw new Error('independent Rust verifier rejected the run');
    if (!opt.resume) runRust(path.resolve(opt.wod), ['evm-export', '--dir', runDir, '--out', publicInputPath]);
    const input = JSON.parse(fs.readFileSync(publicInputPath, 'utf8'));
    const publicInputSha256 = sha256(fs.readFileSync(publicInputPath));
    const local = JSON.parse(fs.readFileSync(path.resolve(opt['local-summary']), 'utf8'));
    if (input.ballots.length !== Number(input.expectedBallots)) throw new Error('public ballot count mismatch');
    const executionModule = opt.execute ? require('./evm_executor.cjs') : null;
    const executionLocal = opt.execute ? JSON.parse(fs.readFileSync(path.resolve(opt['execution-summary']), 'utf8')) : null;
    if (opt.execute && (Number(input.expectedBallots) !== 8 || Number(input.expectedClaim.decision) !== 1 ||
        executionLocal.status !== 'PASS' || !executionLocal.local_evm_only ||
        !executionLocal.tests.sharedProductionPath || !executionLocal.tests.tamperedTranscript || !executionLocal.tests.incorrectDecisionClaim)) {
      throw new Error('execution requires n=8, an approving verified result and passing local executor tests');
    }
    const authority = opt.execute ? (opt.resume ? new ethers.Wallet(JSON.parse(fs.readFileSync(
      path.join(outDir, 'private', 'verification-authority.json'), 'utf8')).private_key) : ethers.Wallet.createRandom()) : null;
    if (opt.execute && opt.resume && (existingManifest.transactions.length !== 17 ||
        existingManifest.transactions.some(t => t.status !== 'CONFIRMED') ||
        existingManifest.execution_configuration?.verificationAuthority.toLowerCase() !== authority.address.toLowerCase() ||
        ['execution-receipts.json', 'execution-verification.json', 'execution-attestation.json', 'execution-governance.json']
          .some(name => fs.existsSync(path.join(publicDir, name))))) {
      throw new Error('execution recovery requires exactly 17 confirmed setup/poll transactions, the original authority, and no prior execution artifacts');
    }

    stage = 'Solidity compilation';
    const sourcePath = path.join(repo, 'contracts', 'WodAdmission.sol');
    const source = fs.readFileSync(sourcePath);
    const compiled = JSON.parse(solc.compile(JSON.stringify({
      language: 'Solidity', sources: { 'WodAdmission.sol': { content: source.toString('utf8') } },
      settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: 'shanghai',
        outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } } }
    })));
    const errors = (compiled.errors || []).filter(e => e.severity === 'error');
    if (errors.length) throw new Error('Solidity compilation failed');
    const artifacts = compiled.contracts['WodAdmission.sol'];
    const artifact = name => ({ abi: artifacts[name].abi, bytecode: `0x${artifacts[name].evm.bytecode.object}`,
      runtime: `0x${artifacts[name].evm.deployedBytecode.object}` });
    const verifier = artifact('RustGroth16Verifier'), board = artifact('WodAdmission');
    const executionArtifacts = opt.execute ? executionModule.compile(solc, repo) : null;
    const verifierFactory = new ethers.ContractFactory(verifier.abi, verifier.bytecode);
    const verifierData = (await verifierFactory.getDeployTransaction(input.verifyingKey.alpha, input.verifyingKey.beta,
      input.verifyingKey.gamma, input.verifyingKey.delta, input.verifyingKey.ic)).data;
    const boardFactory = new ethers.ContractFactory(board.abi, board.bytecode);
    const boardInit = (await boardFactory.getDeployTransaction('0x0000000000000000000000000000000000000001')).data;
    const boardIface = new ethers.Interface(board.abi);
    const poll = BigInt(input.pollId);
    const [cx, cy] = input.committeeKey;
    const registrationData = boardIface.encodeFunctionData('registerPoll', [poll, input.registryRoot, cx, cy, input.expectedBallots]);
    const ballotData = input.ballots.map(b => boardIface.encodeFunctionData('submitBallot', [poll, b.signals, b.proof.a, b.proof.b, b.proof.c]));
    const sealData = boardIface.encodeFunctionData('sealPoll', [poll]);
    const claim = input.expectedClaim;
    const claimData = boardIface.encodeFunctionData('publishDecision', [poll, claim.commitment, claim.transcriptHash, Number(claim.decision)]);

    stage = 'read-only RPC preflight and cost check';
    const chain = BigInt(await provider.send('eth_chainId', []));
    if (chain !== 421614n) throw new Error('RPC chain ID mismatch');
    const balance = await provider.getBalance(wallet.address);
    const node = '0x00000000000000000000000000000000000000c8';
    const nodeIface = new ethers.Interface([
      'function gasEstimateComponents(address to,bool contractCreation,bytes data) payable returns (uint64 gasEstimate,uint64 gasEstimateForL1,uint256 baseFee,uint256 l1BaseFeeEstimate)',
      'function gasEstimateL1Component(address to,bool contractCreation,bytes data) payable returns (uint64 gasEstimateForL1,uint256 baseFee,uint256 l1BaseFeeEstimate)'
    ]);
    async function components(to, creation, data) {
      const encoded = nodeIface.encodeFunctionData('gasEstimateComponents', [to, creation, data]);
      const raw = await provider.call({ to: node, from: wallet.address, data: encoded });
      const [gas, l1, baseFee, l1BaseFee] = nodeIface.decodeFunctionResult('gasEstimateComponents', raw);
      return { gas: BigInt(gas), l1: BigInt(l1), baseFee: BigInt(baseFee), l1BaseFee: BigInt(l1BaseFee) };
    }
    async function l1Component(to, data) {
      const encoded = nodeIface.encodeFunctionData('gasEstimateL1Component', [to, false, data]);
      const raw = await provider.call({ to: node, from: wallet.address, data: encoded });
      const [l1, baseFee, l1BaseFee] = nodeIface.decodeFunctionResult('gasEstimateL1Component', raw);
      return { l1: BigInt(l1), baseFee: BigInt(baseFee), l1BaseFee: BigInt(l1BaseFee) };
    }
    const deployVerifier = await components(ethers.ZeroAddress, true, verifierData);
    const deployBoard = await components(ethers.ZeroAddress, true, boardInit);
    const l1Registration = await l1Component(ethers.ZeroAddress, registrationData);
    const l1Seal = await l1Component(ethers.ZeroAddress, sealData);
    const l1Claim = await l1Component(ethers.ZeroAddress, claimData);
    const l1Samples = await Promise.all(ballotData.slice(0, Math.min(8, ballotData.length)).map(d => l1Component(ethers.ZeroAddress, d)));
    const maxBaseFee = [deployVerifier.baseFee, deployBoard.baseFee, l1Registration.baseFee, l1Seal.baseFee, l1Claim.baseFee,
      ...l1Samples.map(x => x.baseFee)].reduce(max, 0n);
    const maxBallotL1 = l1Samples.map(x => x.l1).reduce(max, 0n);
    const localBallotGas = local.ballots.map(b => BigInt(b.gasUsed)).reduce(max, 0n);
    const localOtherGas = BigInt(local.deployment.registrationGas) + BigInt(local.sealGas) + BigInt(local.claimGas);
    const callL1 = BigInt(l1Registration.l1) + BigInt(l1Seal.l1) + BigInt(l1Claim.l1) + BigInt(input.expectedBallots) * maxBallotL1;
    const executionGasReserve = opt.execute ? Object.entries(executionLocal.gas)
      .filter(([name]) => ['ReplayGatedExecutor', 'TestGovernedParameter', 'setExecutor', 'registerProposal', 'execute'].includes(name))
      .reduce((sum, [, value]) => sum + BigInt(value), 0n) + 1000000n : 0n;
    const executionEstimate = executionGasReserve * maxBaseFee;
    const rawEstimate = executionEstimate + deployVerifier.gas * deployVerifier.baseFee + deployBoard.gas * deployBoard.baseFee +
      (localOtherGas + BigInt(input.expectedBallots) * localBallotGas + callL1) * maxBaseFee;
    const reserve = rawEstimate * 2n;
    if (opt.broadcast) lockFd = fs.openSync(ledgerLock, 'wx');
    let ledger = fs.existsSync(ledgerPath) ? JSON.parse(fs.readFileSync(ledgerPath, 'utf8')) :
      { chainId: 421614, wallet: wallet.address, capWei: cap.toString(), spentWei: '0', reservations: [] };
    if (ledger.wallet.toLowerCase() !== wallet.address.toLowerCase() || ledger.chainId !== 421614 || BigInt(ledger.capWei) !== cap) {
      throw new Error('budget ledger identity or cap mismatch');
    }
    const reservedOthers = ledger.reservations.reduce((sum, r) => sum + BigInt(r.wei), 0n);
    const spent = BigInt(ledger.spentWei);
    const latestBlock = await provider.getBlock('latest');
    const gasPrice = BigInt(await provider.send('eth_gasPrice', []));
    const runId = path.basename(outDir);
    const ownReservations = ledger.reservations.filter(r => r.runId === runId);
    if (opt.resume) {
      const m = existingManifest;
      if (ownReservations.length !== 1 || m.chain_id !== 421614 ||
          m.wallet_address.toLowerCase() !== wallet.address.toLowerCase() ||
          m.input_ballots !== Number(input.expectedBallots) || m.ballot_batch_size !== ballotBatchSize ||
          m.protocol_run_source_commit !== protocolRunCommit || !m.verifier_address || !m.board_address ||
          m.contract_source_sha256 !== sha256(source) ||
          m.arkworks_verifying_key_sha256 !== sha256(Buffer.from(JSON.stringify(input.verifyingKey))) ||
          (m.resume_input_sha256 && m.resume_input_sha256 !== publicInputSha256)) {
        throw new Error('existing run identity does not match resume inputs or source');
      }
      const originalReserve = BigInt(m.preflight.two_x_reserve_wei);
      if (BigInt(ownReservations[0].wei) !== originalReserve || originalReserve < reserve) {
        throw new Error('existing run reservation is missing or below the current estimate');
      }
    }
    const budgetOk = opt.resume ? spent + reservedOthers <= cap : spent + reservedOthers + reserve <= cap;
    const balanceOk = opt.resume ? balance >= reservedOthers : balance >= reservedOthers + reserve;
    if (opt.broadcast && !budgetOk) throw new Error('estimated profile cost plus reserve exceeds remaining spending cap');
    if (opt.broadcast && !balanceOk) throw new Error('wallet balance is below estimated spending reserve');
    if (opt.broadcast && !opt.resume) {
      ledger.reservations.push({ runId, wei: reserve.toString() });
      writeJson(ledgerPath, ledger);
    }
    const manifest = existingManifest || {
      schema: 'wod/arbitrum-sepolia-evidence/v1', network: 'Arbitrum Sepolia', chain_id: 421614,
      source_commit: head.stdout.trim(), source_dirty: false, created_utc: new Date().toISOString(),
      protocol_run_source_commit: protocolRunCommit, ballot_batch_size: ballotBatchSize,
      execution_demonstration: opt.execute,
      machine: { os: `${os.type()} ${os.release()}`, cpu: os.cpus()[0]?.model || 'unknown', logical_processors: os.cpus().length },
      wallet_address: wallet.address, configured_spend_cap_eth: env.ARB_SEPOLIA_MAX_TOTAL_ETH,
      preflight_wallet_balance_eth: ethers.formatEther(balance),
      input_ballots: Number(input.expectedBallots), rust_verifier: 'PASS', oracle_agrees: true,
      arkworks_verifying_key_sha256: sha256(Buffer.from(JSON.stringify(input.verifyingKey))),
      compiler: solc.version(), evm_target: 'shanghai', optimizer_runs: 200,
      contract_source_sha256: sha256(source), bytecode: {
        verifier_init_bytes: (verifier.bytecode.length - 2) / 2,
        verifier_runtime_bytes: (verifier.runtime.length - 2) / 2,
        verifier_init_keccak256: ethers.keccak256(verifier.bytecode),
        board_init_bytes: (board.bytecode.length - 2) / 2,
        board_runtime_bytes: (board.runtime.length - 2) / 2,
        board_init_keccak256: ethers.keccak256(board.bytecode)
      },
      preflight: {
        read_only: true, latest_block: latestBlock.number, eth_gas_price_wei: gasPrice.toString(),
        node_interface_base_fee_wei: maxBaseFee.toString(), raw_estimated_fee_wei: rawEstimate.toString(),
        two_x_reserve_wei: reserve.toString(), two_x_reserve_eth: ethers.formatEther(reserve),
        l1_estimation_method: 'NodeInterface gasEstimateComponents for deployments; gasEstimateL1Component for calls; local Ganache receipt gas for call execution before deployment',
        local_call_gas_basis: 'maximum local gas among real Rust proof samples and measured registration/seal/claim receipts',
        ballots_preflighted_l1_samples: l1Samples.length,
        expected_transactions: Number(input.expectedBallots) + (opt.execute ? 10 : 5),
        execution_extra_fee_estimate_wei: executionEstimate.toString(),
        execution_estimation_method: opt.execute ? 'passing local executor receipt gas plus 1000000 gas posting/variation allowance; full profile receives a further 2x reserve' : null,
        spending_cap_check: budgetOk ? 'PASS' : 'EXCEEDS_CAP',
        balance_check: balanceOk ? 'PASS' : 'INSUFFICIENT_BALANCE'
      },
      transactions: [], public_artifact_sha256: {}, status: opt.preflightOnly ?
        (budgetOk && balanceOk ? 'PREFLIGHT_PASS' : 'PREFLIGHT_BUDGET_EXCEEDED') : 'BROADCAST_STARTED'
    };
    if (!opt.resume) writeJson(manifestPath, manifest);
    if (opt.preflightOnly) {
      console.log(JSON.stringify({ status: manifest.status, chainId: 421614, walletAddress: wallet.address,
        ballots: Number(input.expectedBallots), estimatedFeeEth: ethers.formatEther(rawEstimate),
        reserveEth: ethers.formatEther(reserve), testEthBalance: ethers.formatEther(balance),
        configuredSpendCapEth: env.ARB_SEPOLIA_MAX_TOTAL_ETH, gasPriceGwei: ethers.formatUnits(gasPrice, 'gwei'),
        expectedTransactions: Number(input.expectedBallots) + (opt.execute ? 10 : 5), manifest: manifestPath }, null, 2));
      if (!budgetOk || !balanceOk) process.exitCode = 2;
      return;
    }

    let nonce = await provider.getTransactionCount(wallet.address, 'pending');
    const confirmedReceiptLogs = [];
    const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
    async function getReceiptWithRetry(entry, timeoutMs = 90000) {
      const deadline = Date.now() + timeoutMs;
      let delayMs = 250;
      while (Date.now() < deadline) {
        const raw = await provider.send('eth_getTransactionReceipt', [entry.transaction_hash]).catch(() => null);
        if (raw) return raw;
        await pause(delayMs);
        delayMs = Math.min(2000, Math.ceil(delayMs * 1.5));
      }
      return null;
    }
    async function settleEntries(entries) {
      const settled = new Array(entries.length);
      let cursor = 0;
      const worker = async () => {
        while (cursor < entries.length) {
          const index = cursor++;
          settled[index] = { entry: entries[index], rawReceipt: await getReceiptWithRetry(entries[index]) };
        }
      };
      await Promise.all(Array.from({ length: Math.min(4, entries.length) }, worker));
      const current = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
      let batchFeeWei = 0n;
      let failed = false;
      const receipts = [];
      for (const result of settled) {
        const { entry, rawReceipt } = result;
        if (!rawReceipt) {
          entry.status = 'RECEIPT_UNAVAILABLE';
          failed = true;
          receipts.push(null);
          continue;
        }
        const status = Number(BigInt(rawReceipt.status));
        const gasUsed = BigInt(rawReceipt.gasUsed);
        const effectiveGasPrice = rawReceipt.effectiveGasPrice ? BigInt(rawReceipt.effectiveGasPrice) :
          (rawReceipt.gasPrice ? BigInt(rawReceipt.gasPrice) : BigInt(entry.estimated_base_fee_wei));
        const feeWei = gasUsed * effectiveGasPrice;
        if (!['CONFIRMED', 'REVERTED'].includes(entry.status)) batchFeeWei += feeWei;
        entry.status = status === 1 ? 'CONFIRMED' : 'REVERTED';
        entry.block_number = Number(BigInt(rawReceipt.blockNumber));
        entry.gas_used = gasUsed.toString(); entry.effective_gas_price_wei = effectiveGasPrice.toString();
        entry.fee_wei = feeWei.toString(); entry.rpc_receipt_fee_fields = {};
        for (const field of ['l1Fee', 'l1GasUsed', 'l1GasPrice', 'l1BlockNumber', 'effectiveGasPrice']) {
          if (rawReceipt[field] != null) entry.rpc_receipt_fee_fields[field] = rawReceipt[field];
        }
        const logs = (rawReceipt.logs || []).map(log => ({ address: log.address, topics: [...log.topics], data: log.data,
          blockNumber: Number(BigInt(log.blockNumber)), transactionHash: log.transactionHash,
          logIndex: Number(BigInt(log.logIndex ?? log.index ?? 0)) }));
        confirmedReceiptLogs.push(...logs);
        if (rawReceipt.contractAddress) entry.contract_address = rawReceipt.contractAddress;
        if (entry.status !== 'CONFIRMED') failed = true;
        receipts.push({ hash: entry.transaction_hash, status, gasUsed, gasPrice: effectiveGasPrice,
          blockNumber: entry.block_number, contractAddress: entry.contract_address || null, logs });
      }
      current.spentWei = (BigInt(current.spentWei) + batchFeeWei).toString();
      writeJson(ledgerPath, current);
      writeJson(manifestPath, manifest);
      if (failed) throw new Error('one or more transactions lack successful receipts');
      return receipts;
    }
    async function settleBatch(pending) {
      return settleEntries(pending.map(item => item.entry));
    }
    async function send(kind, to, data, creation, preEstimate = null, waitForReceipt = true, gasPriceOverride = null) {
      stage = `broadcast ${kind}`;
      const est = preEstimate || await components(to || ethers.ZeroAddress, creation, data);
      const gasLimit = ceilMul(est.gas, 120n, 100n);
      const gasPrice = gasPriceOverride ?? BigInt(await provider.send('eth_gasPrice', []));
      const maxFeePerGas = ceilMul(max(gasPrice, est.baseFee), 120n, 100n);
      const estimatedCostReserve = gasLimit * maxFeePerGas;
      const currentLedger = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
      const allReserved = currentLedger.reservations.reduce((s, r) => s + BigInt(r.wei), 0n);
      const thisReserved = currentLedger.reservations.filter(r => r.runId === runId).reduce((s, r) => s + BigInt(r.wei), 0n);
      if (BigInt(currentLedger.spentWei) + currentLedger.reservations.reduce((s, r) => s + BigInt(r.wei), 0n) > cap ||
          BigInt(currentLedger.spentWei) + allReserved - thisReserved + estimatedCostReserve > cap) {
        throw new Error('transaction reserve would exceed spend cap');
      }
      const req = { chainId: 421614, nonce, gasLimit, maxFeePerGas, maxPriorityFeePerGas: 0n, data };
      if (!creation) req.to = to;
      const rawTx = await wallet.signTransaction(req);
      const hash = ethers.keccak256(rawTx);
      const entry = { kind, transaction_hash: hash, nonce, estimated_gas_total: est.gas.toString(),
        estimated_l1_gas: est.l1.toString(), estimated_base_fee_wei: est.baseFee.toString(),
        gas_limit: gasLimit.toString(), status: 'SUBMITTING' };
      manifest.transactions.push(entry); writeJson(manifestPath, manifest);
      const tx = await provider.broadcastTransaction(rawTx);
      nonce++;
      entry.status = 'PENDING'; writeJson(manifestPath, manifest);
      const pending = { tx, entry, est };
      if (!waitForReceipt) return pending;
      return (await settleBatch([pending]))[0];
    }

    let verifierAddress, boardAddress, boardDeploymentBlock, startBallot = 0;
    let executionConfiguration;
    if (opt.execute && opt.resume) executionConfiguration = existingManifest.execution_configuration;
    let contract, state;
    if (opt.resume) {
      stage = 'recover transaction receipts';
      const unresolved = manifest.transactions.filter(t => !['CONFIRMED', 'REVERTED'].includes(t.status));
      const ballotEntries = manifest.transactions.filter(t => t.kind === 'ballot_admission');
      const checkTransaction = async entry => {
        const raw = await provider.send('eth_getTransactionByHash', [entry.transaction_hash]).catch(() => null);
        const ordinal = ballotEntries.indexOf(entry);
        if (!raw || entry.kind !== 'ballot_admission' || ordinal < 0 ||
            raw.from.toLowerCase() !== wallet.address.toLowerCase() ||
            raw.to.toLowerCase() !== manifest.board_address.toLowerCase() ||
            Number(BigInt(raw.nonce)) !== Number(entry.nonce) ||
            raw.input.toLowerCase() !== ballotData[ordinal].toLowerCase()) {
          throw new Error('unresolved transaction does not match the signed ballot manifest');
        }
      };
      let checkCursor = 0;
      await Promise.all(Array.from({ length: Math.min(4, unresolved.length) }, async () => {
        while (checkCursor < unresolved.length) await checkTransaction(unresolved[checkCursor++]);
      }));
      if (unresolved.length) await settleEntries(unresolved);
      const latestNonce = await provider.getTransactionCount(wallet.address, 'latest');
      const pendingNonce = await provider.getTransactionCount(wallet.address, 'pending');
      if (latestNonce !== pendingNonce) throw new Error('wallet has unrelated or unmined transactions; resume stopped safely');
      nonce = latestNonce;
      verifierAddress = manifest.verifier_address;
      boardAddress = manifest.board_address;
      const deployment = manifest.transactions.find(t => t.kind === 'board_deployment' && t.status === 'CONFIRMED');
      if (!deployment || !Number.isInteger(deployment.block_number)) throw new Error('confirmed board deployment receipt is missing');
      boardDeploymentBlock = deployment.block_number;
      contract = new ethers.Contract(boardAddress, board.abi, wallet.connect(provider));
      state = await contract.pollState(poll);
      const confirmedBallots = manifest.transactions.filter(t => t.kind === 'ballot_admission' && t.status === 'CONFIRMED').length;
      if (!state.registered || Number(state.expected) !== Number(input.expectedBallots) ||
          Number(state.accepted) !== confirmedBallots || state.claimed && !state.isSealed ||
          (state.isSealed && (confirmedBallots !== Number(input.expectedBallots) ||
            state.commitment.toLowerCase() !== input.expectedSealedCommitment.toLowerCase()))) {
        throw new Error('on-chain poll state does not match the verified transaction manifest');
      }
      startBallot = Number(state.accepted);
      manifest.resume_input_sha256 = publicInputSha256;
      manifest.resume_history = manifest.resume_history || [];
      manifest.resume_history.push({ resumed_utc: new Date().toISOString(), runner_source_commit: head.stdout.trim(),
        recovered_receipts: unresolved.length, accepted_ballots_at_resume: startBallot, next_nonce: nonce });
      writeJson(manifestPath, manifest);
    } else {
      stage = 'deploy Groth16 verifier';
      const vr = await send('verifier_deployment', null, verifierData, true, deployVerifier);
      verifierAddress = vr.contractAddress;
      if (!verifierAddress) throw new Error('verifier deployment receipt has no address');
      manifest.verifier_address = verifierAddress; writeJson(manifestPath, manifest);
      stage = 'deploy admission board';
      const boardData = (await boardFactory.getDeployTransaction(verifierAddress)).data;
      const br = await send('board_deployment', null, boardData, true);
      boardAddress = br.contractAddress;
      if (!boardAddress) throw new Error('board deployment receipt has no address');
      boardDeploymentBlock = br.blockNumber;
      manifest.board_address = boardAddress; writeJson(manifestPath, manifest);
      if (opt.execute) {
        const privateDir = path.join(outDir, 'private');
        fs.mkdirSync(privateDir, { recursive: true });
        fs.writeFileSync(path.join(privateDir, 'verification-authority.json'),
          JSON.stringify({ address: authority.address, private_key: authority.privateKey }) + '\n', { flag: 'wx', mode: 0o600 });
        stage = 'register bound governance action before ballot admission';
        executionConfiguration = await executionModule.prepareExecution({ ethers, artifacts: executionArtifacts,
          input: { ...input, admission: boardAddress }, authority, send });
        manifest.execution_configuration = executionConfiguration;
        manifest.executor_source_sha256 = sha256(fs.readFileSync(path.join(repo, 'contracts', 'ReplayExecutor.sol')));
        writeJson(manifestPath, manifest);
      }
      contract = new ethers.Contract(boardAddress, board.abi, wallet.connect(provider));
      stage = 'register poll';
      await send('poll_registration', boardAddress, registrationData, false);
    }
    if (!state || !state.isSealed) for (let start = startBallot; start < input.ballots.length; start += ballotBatchSize) {
      const end = Math.min(start + ballotBatchSize, input.ballots.length);
      const dataBatch = ballotData.slice(start, end);
      stage = `estimate ballot batch ${start + 1}-${end}/${input.ballots.length}`;
      const estimates = await Promise.all(dataBatch.map(data => components(boardAddress, false, data)));
      const batchGasPrice = BigInt(await provider.send('eth_gasPrice', []));
      const pending = [];
      try {
        for (let offset = 0; offset < dataBatch.length; offset++) {
          stage = `submit ballot ${start + offset + 1}/${input.ballots.length}`;
          pending.push(await send('ballot_admission', boardAddress, dataBatch[offset], false,
            estimates[offset], false, batchGasPrice));
        }
      } catch (e) {
        if (pending.length) { try { await settleBatch(pending); } catch {} }
        throw e;
      }
      stage = `confirm ballot batch ${start + 1}-${end}/${input.ballots.length}`;
      await settleBatch(pending);
    }
    state = await contract.pollState(poll);
    if (!state.isSealed) {
      stage = 'seal accepted board';
      await send('board_sealing', boardAddress, sealData, false);
      state = await contract.pollState(poll);
    }
    if (!state.registered || !state.isSealed || Number(state.accepted) !== Number(input.expectedBallots) ||
        state.commitment.toLowerCase() !== input.expectedSealedCommitment.toLowerCase()) {
      throw new Error('on-chain sealed board does not match the Rust commitment');
    }
    if (!state.claimed) {
      stage = 'publish winner-only decision';
      await send('decision_claim', boardAddress, claimData, false);
    }
    stage = 'public event replay';
    let rawLogs;
    try { rawLogs = await provider.getLogs({ address: boardAddress, fromBlock: boardDeploymentBlock, toBlock: 'latest' }); }
    catch { rawLogs = []; }
    if (rawLogs.length !== Number(input.expectedBallots) + 3) {
      confirmedReceiptLogs.length = 0;
      await settleEntries(manifest.transactions.filter(t => t.status === 'CONFIRMED'));
      rawLogs = confirmedReceiptLogs.filter(log => log.address.toLowerCase() === boardAddress.toLowerCase());
      manifest.event_log_source = 'individual confirmed transaction receipts captured during submission';
    } else {
      manifest.event_log_source = 'eth_getLogs';
    }
    if (rawLogs.length !== Number(input.expectedBallots) + 3) throw new Error('board event count does not match the accepted poll');
    const logs = rawLogs.map(log => ({ address: log.address, topics: log.topics, data: log.data,
      blockNumber: Number(BigInt(log.blockNumber)), transactionHash: log.transactionHash,
      logIndex: Number(BigInt(log.index ?? log.logIndex)) }));
    writeJson(logsPath, logs);
    const replay = runRust(path.resolve(opt.wod), ['evm-check-events', '--dir', runDir, '--logs', logsPath, '--contract', boardAddress]);
    if (replay.event_replay !== 'PASS' || replay.proofs_verified !== Number(input.expectedBallots) || !replay.matches_original_run) {
      throw new Error('independent Rust event replay failed');
    }
    if (opt.execute) {
      stage = 'receipt-derived independent verification and authorized governance execution';
      const chainPublicDir = path.join(outDir, 'work', 'chain-verifier');
      fs.mkdirSync(path.join(chainPublicDir, 'public'), { recursive: true });
      for (const name of ['setup.bin', 'transcript.bin']) fs.copyFileSync(path.join(runDir, 'public', name), path.join(chainPublicDir, 'public', name));
      manifest.governance_execution = await executionModule.finishExecution({ provider, ethers,
        admission: boardAddress, pollId: input.pollId, fromBlock: boardDeploymentBlock,
        transactionHashes: manifest.transactions.filter(t => ['poll_registration', 'ballot_admission', 'board_sealing', 'decision_claim'].includes(t.kind)).map(t => t.transaction_hash),
        runtimeHash: ethers.keccak256(await provider.getCode(boardAddress)), outDir: publicDir,
        wod: path.resolve(opt.wod), publicDir: chainPublicDir, setupHash: input.setupHash,
        sourceCommit: head.stdout.trim(), label: 'execution' }, executionConfiguration, authority, executionArtifacts, send);
    }
    const currentLedger = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
    currentLedger.reservations = currentLedger.reservations.filter(r => r.runId !== runId);
    writeJson(ledgerPath, currentLedger);
    manifest.status = 'PASS'; manifest.accepted_board_commitment = input.expectedSealedCommitment;
    manifest.decision_bit = Number(claim.decision); manifest.independent_rust_event_replay = replay;
    manifest.chain_explorer_base = 'https://sepolia.arbiscan.io';
    manifest.public_artifact_sha256 = {
      'evm-public-input.json': sha256(fs.readFileSync(publicInputPath)),
      'evm-chain-logs.json': sha256(fs.readFileSync(logsPath))
    };
    if (opt.execute) for (const name of ['execution-receipts.json', 'execution-verification.json', 'execution-attestation.json', 'execution-governance.json']) {
      manifest.public_artifact_sha256[name] = sha256(fs.readFileSync(path.join(publicDir, name)));
    }
    manifest.actual_fee_total_wei = manifest.transactions.reduce((s, x) => s + BigInt(x.fee_wei), 0n).toString();
    manifest.actual_fee_total_eth = ethers.formatEther(BigInt(manifest.actual_fee_total_wei));
    writeJson(manifestPath, manifest);
    console.log(JSON.stringify({ status: manifest.status, chainId: 421614, walletAddress: wallet.address,
      verifierAddress, boardAddress, ballots: Number(input.expectedBallots), decision: manifest.decision_bit,
      verifiedProofs: replay.proofs_verified, actualFeeEth: manifest.actual_fee_total_eth,
      transactionCount: manifest.transactions.length, manifest: manifestPath }, null, 2));
  } catch (e) {
    console.error(`Stopped at ${stage}; sensitive configuration is suppressed. Error code: ${String(e.code || e.info?.error?.code || 'unavailable')}.`);
    process.exitCode = 1;
  } finally {
    if (lockFd !== undefined) { fs.closeSync(lockFd); try { fs.unlinkSync(ledgerLock); } catch {} }
    await provider.destroy();
  }
})();
