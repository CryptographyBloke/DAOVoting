// Local-only EVM integration test for the Rust-native Arkworks Groth16 ballot.
// No network RPC endpoint or private key is read by this test.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { spawnSync } = require('child_process');

function options(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith('--') || !argv[i + 1]) throw new Error('expected --name value options');
    out[argv[i].slice(2)] = argv[i + 1];
  }
  return out;
}
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function runRust(binary, args) {
  const result = spawnSync(binary, args, { encoding: 'utf8', windowsHide: true });
  if (result.error || result.status !== 0) {
    const message = (result.stderr || result.error?.message || 'Rust command failed').split(/\r?\n/)[0];
    throw new Error(`Rust verification failed: ${message.slice(0, 240)}`);
  }
  return JSON.parse(result.stdout);
}

(async () => {
  const opt = options(process.argv.slice(2));
  for (const key of ['dir', 'out-dir', 'wod', 'tools']) {
    if (!opt[key]) throw new Error(`missing --${key}`);
  }
  const runDir = path.resolve(opt.dir);
  const repo = path.resolve(__dirname, '..');
  const outDir = path.resolve(opt['out-dir']);
  if (fs.existsSync(outDir)) throw new Error(`refusing to reuse output directory ${outDir}`);
  const sourcePublicDir = path.join(runDir, 'public');
  const publicDir = path.join(outDir, 'public');
  fs.mkdirSync(publicDir, { recursive: true });
  const wod = path.resolve(opt.wod);
  const tools = path.resolve(opt.tools);
  const inputPath = path.join(publicDir, 'evm-public-input.json');
  const logsPath = path.join(publicDir, 'evm-local-logs.json');
  const summaryPath = path.join(publicDir, 'evm-local-summary.json');
  const manifestPath = path.join(outDir, 'manifest.json');
  for (const file of ['setup.bin', 'ledger.bin']) {
    if (!fs.existsSync(path.join(sourcePublicDir, file))) throw new Error(`missing source public/${file}`);
  }
  if (!fs.existsSync(wod)) throw new Error('release Rust binary not found');

  const exported = runRust(wod, ['evm-export', '--dir', runDir, '--out', inputPath]);
  const publicExport = { ...exported, path: path.relative(repo, inputPath).split(path.sep).join('/') };
  const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  const sourcePath = path.resolve(__dirname, '..', 'contracts', 'WodAdmission.sol');
  const sourceBytes = fs.readFileSync(sourcePath);
  const solc = require(path.join(tools, 'node_modules', 'solc'));
  const ethers = require(path.join(tools, 'node_modules', 'ethers'));
  const savedWarn = console.warn, savedError = console.error;
  console.warn = () => {}; console.error = () => {};
  const ganache = require(path.join(tools, 'node_modules', 'ganache'));
  console.warn = savedWarn; console.error = savedError;

  const compiled = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity',
    sources: { 'WodAdmission.sol': { content: sourceBytes.toString('utf8') } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: 'shanghai',
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } }
    }
  })));
  const errors = (compiled.errors || []).filter(e => e.severity === 'error');
  if (errors.length) throw new Error(`Solidity compile failed: ${errors[0].formattedMessage.slice(0, 400)}`);
  const artifacts = compiled.contracts['WodAdmission.sol'];
  const artifact = name => ({
    abi: artifacts[name].abi,
    bytecode: `0x${artifacts[name].evm.bytecode.object}`,
    runtime: `0x${artifacts[name].evm.deployedBytecode.object}`
  });
  const verifierArtifact = artifact('RustGroth16Verifier');
  const boardArtifact = artifact('WodAdmission');
  const evm = ganache.provider({
    logging: { quiet: true },
    chain: { chainId: 421614, hardfork: 'shanghai' },
    miner: { blockGasLimit: 30000000 },
    wallet: { deterministic: true }
  });
  const provider = new ethers.BrowserProvider(evm);
  try {
    const signer = await provider.getSigner(0);
    const localChainId = (await provider.getNetwork()).chainId.toString();
    if (localChainId !== '421614') throw new Error('local EVM chain id mismatch');
    const vk = input.verifyingKey;
    const verifierFactory = new ethers.ContractFactory(verifierArtifact.abi, verifierArtifact.bytecode, signer);
    const verifier = await verifierFactory.deploy(vk.alpha, vk.beta, vk.gamma, vk.delta, vk.ic);
    const verifierReceipt = await verifier.deploymentTransaction().wait();
    const boardFactory = new ethers.ContractFactory(boardArtifact.abi, boardArtifact.bytecode, signer);
    const board = await boardFactory.deploy(await verifier.getAddress());
    const boardReceipt = await board.deploymentTransaction().wait();
    const poll = BigInt(input.pollId);
    const [committeeX, committeeY] = input.committeeKey;
    const registrationReceipt = await (await board.registerPoll(
      poll, input.registryRoot, committeeX, committeeY, BigInt(input.expectedBallots)
    )).wait();

    const sample = input.ballots[0];
    const verifierAcceptsRustProof = await verifier.verify.staticCall(
      sample.signals, sample.proof.a, sample.proof.b, sample.proof.c
    );
    if (!verifierAcceptsRustProof) throw new Error('Solidity verifier rejected a Rust-generated proof');
    async function mustRevert(promise, label) {
      let rejected = false;
      try { await promise; } catch { rejected = true; }
      if (!rejected) throw new Error(`${label} unexpectedly accepted`);
    }
    const badSignals = [...sample.signals];
    badSignals[33] = `0x${(BigInt(badSignals[33]) + 1n).toString(16).padStart(64, '0')}`;
    await mustRevert(board.submitBallot.staticCall(poll, badSignals, sample.proof.a, sample.proof.b, sample.proof.c), 'modified public input');
    const badProofA = [...sample.proof.a];
    badProofA[0] = `0x${(BigInt(badProofA[0]) + 1n).toString(16).padStart(64, '0')}`;
    await mustRevert(board.submitBallot.staticCall(poll, sample.signals, badProofA, sample.proof.b, sample.proof.c), 'modified proof');
    await mustRevert(board.sealPoll.staticCall(poll), 'premature seal');

    const ballotsGas = [];
    for (let i = 0; i < input.ballots.length; i++) {
      if (i === 1) {
        const first = input.ballots[0];
        await mustRevert(board.submitBallot.staticCall(poll, first.signals, first.proof.a, first.proof.b, first.proof.c), 'duplicate nullifier');
      }
      const ballot = input.ballots[i];
      const receipt = await (await board.submitBallot(
        poll, ballot.signals, ballot.proof.a, ballot.proof.b, ballot.proof.c, { gasLimit: 10000000n }
      )).wait();
      ballotsGas.push({ ballot: i, gasUsed: receipt.gasUsed.toString(), blockNumber: receipt.blockNumber });
    }
    const sealReceipt = await (await board.sealPoll(poll)).wait();
    const state = await board.pollState(poll);
    if (!state.registered || !state.isSealed || Number(state.accepted) !== input.expectedBallots) throw new Error('unexpected post-seal state');
    const commitment = state.commitment.toLowerCase();
    if (commitment !== input.expectedSealedCommitment.toLowerCase()) throw new Error('EVM board commitment differs from the Rust ledger');
    const claim = input.expectedClaim;
    await mustRevert(board.publishDecision.staticCall(poll, claim.commitment, `0x${'00'.repeat(32)}`, claim.decision), 'zero transcript hash');
    await mustRevert(board.publishDecision.staticCall(poll, claim.commitment, claim.transcriptHash, 2), 'non-bit decision');
    const claimReceipt = await (await board.publishDecision(poll, claim.commitment, claim.transcriptHash, claim.decision)).wait();

    const rawLogs = await provider.getLogs({ address: await board.getAddress(), fromBlock: 0, toBlock: 'latest' });
    const logs = rawLogs.map(log => ({
      address: log.address, topics: log.topics, data: log.data,
      blockNumber: log.blockNumber, transactionHash: log.transactionHash, logIndex: log.index
    }));
    fs.writeFileSync(logsPath, JSON.stringify(logs, null, 2));
    const replay = runRust(wod, ['evm-check-events', '--dir', runDir, '--logs', logsPath, '--contract', await board.getAddress()]);
    const totalBallotGas = ballotsGas.reduce((sum, item) => sum + BigInt(item.gasUsed), 0n);
    const summary = {
      localEvm: 'PASS',
      network: 'Ganache local EVM only; this is not Arbitrum Sepolia evidence',
      localChainId: Number(localChainId),
      solidityCompiler: solc.version(),
      compilerEvmTarget: 'shanghai',
      optimizerRuns: 200,
      sourceSha256: sha256(sourceBytes),
      contractBytecode: {
        verifierInitBytes: (verifierArtifact.bytecode.length - 2) / 2,
        verifierRuntimeBytes: (verifierArtifact.runtime.length - 2) / 2,
        verifierInitKeccak256: ethers.keccak256(verifierArtifact.bytecode),
        boardInitBytes: (boardArtifact.bytecode.length - 2) / 2,
        boardRuntimeBytes: (boardArtifact.runtime.length - 2) / 2,
        boardInitKeccak256: ethers.keccak256(boardArtifact.bytecode)
      },
      deployment: {
        verifierGas: verifierReceipt.gasUsed.toString(),
        boardGas: boardReceipt.gasUsed.toString(),
        registrationGas: registrationReceipt.gasUsed.toString()
      },
      ballots: ballotsGas,
      admissionGasTotal: totalBallotGas.toString(),
      sealGas: sealReceipt.gasUsed.toString(),
      claimGas: claimReceipt.gasUsed.toString(),
      eventCount: logs.length,
      verifierAcceptsRustProof,
      rejectedCases: {
        modifiedPublicInput: true, modifiedProof: true, duplicateNullifier: true,
        prematureSeal: true, zeroTranscriptHash: true, nonBitDecision: true
      },
      independentRustEventReplay: replay,
      sourceExport: publicExport
    };
    fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));
    const gitHead = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', cwd: repo });
    const gitStatus = spawnSync('git', ['status', '--porcelain'], { encoding: 'utf8', cwd: repo });
    const publicSha256 = {};
    for (const file of [inputPath, logsPath, summaryPath]) publicSha256[path.basename(file)] = sha256(fs.readFileSync(file));
    const manifest = {
      source_commit: (gitHead.stdout || '').trim(),
      source_dirty: Boolean((gitStatus.stdout || '').trim()),
      created_utc: new Date().toISOString(),
      machine: { os: `${os.type()} ${os.release()}`, cpu: os.cpus()[0]?.model || 'unknown', logical_processors: os.cpus().length, memory_bytes: os.totalmem(), node: process.version },
      local_evm_only: true,
      public_sha256: publicSha256
    };
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    console.log(JSON.stringify(summary, null, 2));
  } finally {
    await provider.destroy();
    await evm.disconnect();
  }
})().catch(error => {
  const message = error?.shortMessage || error?.message || 'local EVM test failed';
  console.error(String(message).split(/\r?\n/)[0].slice(0, 500));
  process.exit(1);
});
