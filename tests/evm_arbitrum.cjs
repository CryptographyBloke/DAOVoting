// Budget-capped Arbitrum Sepolia runner. It broadcasts only with --broadcast.
// Private configuration is read from .env and is never copied to output/logs.
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

function args(argv) {
  const out = { broadcast: false, preflightOnly: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--broadcast') { out.broadcast = true; continue; }
    if (argv[i] === '--preflight-only') { out.preflightOnly = true; continue; }
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
  const repo = path.resolve(__dirname, '..');
  const runDir = path.resolve(opt.dir), outDir = path.resolve(opt['out-dir']);
  const ledgerPath = path.resolve(opt['budget-ledger']);
  const localRoot = path.resolve(repo, 'results', 'local') + path.sep;
  for (const p of [outDir, ledgerPath]) {
    if (!p.startsWith(localRoot)) throw new Error('experiment output and budget ledger must stay under results/local');
  }
  if (fs.existsSync(outDir)) throw new Error('refusing to reuse an existing output directory');
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
  const ledgerLock = `${ledgerPath}.lock`;
  let lockFd;
  try {
    stage = 'source and public input validation';
    const head = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', cwd: repo });
    const status = spawnSync('git', ['status', '--porcelain', '--untracked-files=all'], { encoding: 'utf8', cwd: repo });
    if (head.status !== 0 || status.status !== 0 || status.stdout.trim()) throw new Error('source must be committed and clean before publication measurements');
    const runManifest = JSON.parse(fs.readFileSync(path.join(runDir, 'public', 'manifest.json'), 'utf8'));
    const priorVerification = JSON.parse(fs.readFileSync(path.join(runDir, 'public', 'verify.json'), 'utf8'));
    if (priorVerification.accept !== true || runManifest.oracle_agrees !== true) throw new Error('Rust verifier and oracle checks must both pass');
    const verify = runRust(path.resolve(opt.wod), ['verify', '--dir', runDir]);
    if (verify.accept !== true) throw new Error('independent Rust verifier rejected the run');
    runRust(path.resolve(opt.wod), ['evm-export', '--dir', runDir, '--out', publicInputPath]);
    const input = JSON.parse(fs.readFileSync(publicInputPath, 'utf8'));
    const local = JSON.parse(fs.readFileSync(path.resolve(opt['local-summary']), 'utf8'));
    if (input.ballots.length !== Number(input.expectedBallots)) throw new Error('public ballot count mismatch');

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
    const rawEstimate = deployVerifier.gas * deployVerifier.baseFee + deployBoard.gas * deployBoard.baseFee +
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
    const budgetOk = spent + reservedOthers + reserve <= cap;
    const balanceOk = balance >= spent + reservedOthers + reserve;
    if (opt.broadcast && !budgetOk) throw new Error('estimated profile cost plus reserve exceeds remaining spending cap');
    if (opt.broadcast && !balanceOk) throw new Error('wallet balance is below estimated spending reserve');
    if (opt.broadcast) {
      ledger.reservations.push({ runId, wei: reserve.toString() });
      writeJson(ledgerPath, ledger);
    }
    const manifest = {
      schema: 'wod/arbitrum-sepolia-evidence/v1', network: 'Arbitrum Sepolia', chain_id: 421614,
      source_commit: head.stdout.trim(), source_dirty: false, created_utc: new Date().toISOString(),
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
        expected_transactions: Number(input.expectedBallots) + 5,
        spending_cap_check: budgetOk ? 'PASS' : 'EXCEEDS_CAP',
        balance_check: balanceOk ? 'PASS' : 'INSUFFICIENT_BALANCE'
      },
      transactions: [], public_artifact_sha256: {}, status: opt.preflightOnly ?
        (budgetOk && balanceOk ? 'PREFLIGHT_PASS' : 'PREFLIGHT_BUDGET_EXCEEDED') : 'BROADCAST_STARTED'
    };
    writeJson(manifestPath, manifest);
    if (opt.preflightOnly) {
      console.log(JSON.stringify({ status: manifest.status, chainId: 421614, walletAddress: wallet.address,
        ballots: Number(input.expectedBallots), estimatedFeeEth: ethers.formatEther(rawEstimate),
        reserveEth: ethers.formatEther(reserve), testEthBalance: ethers.formatEther(balance),
        configuredSpendCapEth: env.ARB_SEPOLIA_MAX_TOTAL_ETH, gasPriceGwei: ethers.formatUnits(gasPrice, 'gwei'),
        expectedTransactions: Number(input.expectedBallots) + 5, manifest: manifestPath }, null, 2));
      if (!budgetOk || !balanceOk) process.exitCode = 2;
      return;
    }

    let nonce = await provider.getTransactionCount(wallet.address, 'pending');
    const confirmedReceiptLogs = [];
    async function send(kind, to, data, creation, preEstimate = null) {
      stage = `broadcast ${kind}`;
      const est = preEstimate || await components(to || ethers.ZeroAddress, creation, data);
      const gasLimit = ceilMul(est.gas, 120n, 100n);
      const maxFeePerGas = ceilMul(max(await provider.send('eth_gasPrice', []).then(BigInt), est.baseFee), 120n, 100n);
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
      let receipt;
      try { receipt = await tx.wait(1); }
      catch (e) { receipt = e.receipt; }
      if (!receipt) throw new Error(`transaction receipt unavailable for ${kind}`);
      const effectiveGasPrice = receipt.gasPrice || receipt.effectiveGasPrice || est.baseFee;
      const feeWei = receipt.gasUsed * effectiveGasPrice;
      entry.status = Number(receipt.status) === 1 ? 'CONFIRMED' : 'REVERTED';
      entry.block_number = receipt.blockNumber; entry.gas_used = receipt.gasUsed.toString();
      entry.effective_gas_price_wei = effectiveGasPrice.toString(); entry.fee_wei = feeWei.toString();
      const rawReceipt = await provider.send('eth_getTransactionReceipt', [hash]);
      entry.rpc_receipt_fee_fields = {};
      for (const field of ['l1Fee', 'l1GasUsed', 'l1GasPrice', 'l1BlockNumber', 'effectiveGasPrice']) {
        if (rawReceipt && rawReceipt[field] != null) entry.rpc_receipt_fee_fields[field] = rawReceipt[field];
      }
      confirmedReceiptLogs.push(...(receipt.logs || []).map(log => ({
        address: log.address, topics: [...log.topics], data: log.data,
        blockNumber: Number(log.blockNumber), transactionHash: log.transactionHash,
        logIndex: Number(log.index ?? log.logIndex)
      })));
      if (receipt.contractAddress) entry.contract_address = receipt.contractAddress;
      const current = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
      current.spentWei = (BigInt(current.spentWei) + feeWei).toString();
      writeJson(ledgerPath, current);
      writeJson(manifestPath, manifest);
      if (entry.status !== 'CONFIRMED') throw new Error(`transaction reverted: ${kind}`);
      return receipt;
    }

    stage = 'deploy Groth16 verifier';
    const vr = await send('verifier_deployment', null, verifierData, true, deployVerifier);
    const verifierAddress = vr.contractAddress;
    if (!verifierAddress) throw new Error('verifier deployment receipt has no address');
    manifest.verifier_address = verifierAddress; writeJson(manifestPath, manifest);
    stage = 'deploy admission board';
    const boardData = (await boardFactory.getDeployTransaction(verifierAddress)).data;
    const br = await send('board_deployment', null, boardData, true);
    const boardAddress = br.contractAddress;
    if (!boardAddress) throw new Error('board deployment receipt has no address');
    manifest.board_address = boardAddress; writeJson(manifestPath, manifest);
    const contract = new ethers.Contract(boardAddress, board.abi, wallet.connect(provider));
    stage = 'register poll';
    await send('poll_registration', boardAddress, registrationData, false);
    for (let i = 0; i < input.ballots.length; i++) {
      stage = `submit ballot ${i + 1}/${input.ballots.length}`;
      await send('ballot_admission', boardAddress, ballotData[i], false);
    }
    stage = 'seal accepted board';
    await send('board_sealing', boardAddress, sealData, false);
    const state = await contract.pollState(poll);
    if (!state.registered || !state.isSealed || Number(state.accepted) !== Number(input.expectedBallots) ||
        state.commitment.toLowerCase() !== input.expectedSealedCommitment.toLowerCase()) {
      throw new Error('on-chain sealed board does not match the Rust commitment');
    }
    stage = 'publish winner-only decision';
    await send('decision_claim', boardAddress, claimData, false);
    stage = 'public event replay';
    let rawLogs;
    try { rawLogs = await provider.getLogs({ address: boardAddress, fromBlock: br.blockNumber, toBlock: 'latest' }); }
    catch { rawLogs = []; }
    if (rawLogs.length !== Number(input.expectedBallots) + 3) {
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
