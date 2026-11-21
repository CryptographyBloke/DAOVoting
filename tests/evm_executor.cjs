// Chain-derived Rust replay and EIP-712 execution. This module never reads
// trustee/voter files. The authorized verifier is an additional trust role.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const types = { Verification: [
  ['admission', 'address'], ['pollId', 'uint64'], ['setupHash', 'bytes32'],
  ['threshold', 'uint64'], ['boardCommitment', 'bytes32'], ['transcriptHash', 'bytes32'],
  ['decision', 'uint8'], ['actionHash', 'bytes32'], ['nonce', 'uint256']
].map(([name, type]) => ({ name, type })) };
const sha256 = x => crypto.createHash('sha256').update(x).digest('hex');
const writeNew = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function compile(solc, repo) {
  const sources = {};
  for (const name of ['WodAdmission.sol', 'ReplayExecutor.sol']) sources[name] = {
    content: fs.readFileSync(path.join(repo, 'contracts', name), 'utf8')
  };
  const result = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources,
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: 'shanghai',
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } } }
  })));
  if ((result.errors || []).some(e => e.severity === 'error')) throw new Error('executor Solidity compilation failed');
  return Object.assign({}, ...Object.values(result.contracts));
}
function rust(wod, args) {
  const result = spawnSync(wod, args, { encoding: 'utf8', windowsHide: true });
  if (result.error || result.status !== 0) throw new Error('independent Rust chain/transcript verification rejected');
  const output = JSON.parse(result.stdout);
  if (output.accept !== true) throw new Error('public acceptance predicate rejected');
  return output;
}

// The caller provides a live authenticated RPC connection and pins the exact
// deployed runtime hash. An offline receipt JSON is not a chain authenticator.
async function collect(provider, ethers, admission, pollId, fromBlock, runtimeHash, destination, transactionHashes) {
  const chainId = Number(BigInt(await provider.send('eth_chainId', [])));
  if (chainId !== 421614) throw new Error('wrong chain ID');
  const pollTopic = ethers.zeroPadValue(ethers.toBeHex(pollId), 32);
  // A confirmed submission journal avoids RPC eth_getLogs range limits. Every
  // supplied hash is fetched again from the live RPC; Rust checks the complete
  // registration/admission/seal/claim sequence and every ballot proof.
  const logs = transactionHashes ? null : await provider.getLogs({ address: admission, fromBlock, toBlock: 'latest', topics: [null, pollTopic] });
  const hashes = [...new Set(transactionHashes || logs.map(log => log.transactionHash))];
  if (!hashes.length) throw new Error('no live poll receipts');
  const receipts = [];
  const blocks = new Map();
  for (const hash of hashes) {
    const receipt = await provider.send('eth_getTransactionReceipt', [hash]);
    if (!receipt || BigInt(receipt.status) !== 1n || receipt.to.toLowerCase() !== admission.toLowerCase() ||
        !receipt.logs.some(log => log.address.toLowerCase() === admission.toLowerCase() && log.topics[1]?.toLowerCase() === pollTopic.toLowerCase())) {
      throw new Error('missing or failed poll receipt');
    }
    const block = await provider.send('eth_getBlockByNumber', [receipt.blockNumber, false]);
    if (!block || block.hash !== receipt.blockHash) throw new Error('receipt is not in the current canonical RPC view');
    blocks.set(block.number, { number: block.number, hash: block.hash });
    receipts.push(receipt);
  }
  receipts.sort((a, b) => Number(BigInt(a.blockNumber) - BigInt(b.blockNumber)) || Number(BigInt(a.transactionIndex) - BigInt(b.transactionIndex)));
  const latestReceiptBlock = receipts.reduce((n, r) => BigInt(r.blockNumber) > n ? BigInt(r.blockNumber) : n, 0n);
  let anchor;
  const deadline = Date.now() + 60000;
  do {
    anchor = await provider.send('eth_getBlockByNumber', ['latest', false]);
    if (BigInt(anchor.number) > latestReceiptBlock) break;
    await delay(250);
  } while (Date.now() < deadline);
  if (BigInt(anchor.number) <= latestReceiptBlock) throw new Error('waiting for a subsequent confirmation block');
  const code = await provider.send('eth_getCode', [admission, anchor.number]);
  if (ethers.keccak256(code) !== runtimeHash) throw new Error('admission runtime code differs from the pinned deployment');
  const bundle = { schema: 'wod/chain-receipts/v1', chain_id: chainId, contract: admission,
    runtime_code_keccak256: runtimeHash, anchor: { number: anchor.number, hash: anchor.hash },
    receipts, blocks: [...blocks.values()], receipt_source: 'live RPC; canonical block hashes checked; not a light-client proof' };
  writeNew(destination, bundle);
  return bundle;
}

async function verifyLive({ provider, ethers, admission, pollId, fromBlock, runtimeHash, outDir,
  wod, publicDir, setupHash, sourceCommit, label, transactionHashes }) {
  const receiptsFile = path.join(outDir, `${label}-receipts.json`);
  const bundle = await collect(provider, ethers, admission, pollId, fromBlock, runtimeHash, receiptsFile, transactionHashes);
  const report = rust(wod, ['evm-verify-chain', '--dir', publicDir, '--receipts', receiptsFile,
    '--contract', admission, '--chain-id', '421614', '--setup-hash', setupHash, '--source-commit', sourceCommit]);
  const anchor = await provider.send('eth_getBlockByNumber', [bundle.anchor.number, false]);
  if (anchor.hash !== bundle.anchor.hash || report.receipt_bundle_sha256 !== sha256(fs.readFileSync(receiptsFile))) {
    throw new Error('chain anchor or receipt bundle changed during verification');
  }
  writeNew(path.join(outDir, `${label}-verification.json`), report);
  return report;
}
function domain(chainId, executor) { return { name: 'VotingReplayExecutor', version: '1', chainId, verifyingContract: executor }; }
function statement(report, actionHash, nonce) {
  return { admission: report.admission, pollId: report.poll_id, setupHash: report.setup_hash,
    threshold: report.threshold, boardCommitment: report.board_commitment,
    transcriptHash: report.transcript_hash, decision: report.decision, actionHash, nonce };
}

// Production signing always performs live public verification inside this
// function. It never accepts a pre-existing 'PASS' report as authorization.
async function verifiedAuthorization(options, authority, executor, actionHash, nonce) {
  const report = await verifyLive(options);
  if (report.decision !== 1) throw new Error('verified decision does not approve execution');
  const value = statement(report, actionHash, nonce);
  const d = domain(report.chain_id, executor);
  const signature = await authority.signTypedData(d, types, value);
  const attestation = { schema: 'wod/verification-attestation/v1', domain: d, types, value,
    signature, authority: authority.address, source_commit: options.sourceCommit,
    receipt_bundle_sha256: report.receipt_bundle_sha256,
    trust: 'honest verification authority; authenticated RPC view; no on-chain CGY transcript verification' };
  writeNew(path.join(options.outDir, `${options.label}-attestation.json`), attestation);
  return attestation;
}

async function prepareExecution({ ethers, artifacts, input, authority, send }) {
  const artifact = name => artifacts[name];
  const executorFactory = new ethers.ContractFactory(artifact('ReplayGatedExecutor').abi,
    '0x' + artifact('ReplayGatedExecutor').evm.bytecode.object);
  const targetFactory = new ethers.ContractFactory(artifact('TestGovernedParameter').abi,
    '0x' + artifact('TestGovernedParameter').evm.bytecode.object);
  const executorReceipt = await send('executor_deployment', null,
    (await executorFactory.getDeployTransaction(authority.address)).data, true);
  const targetReceipt = await send('governed_target_deployment', null,
    (await targetFactory.getDeployTransaction()).data, true);
  const executor = executorReceipt.contractAddress, target = targetReceipt.contractAddress;
  if (!executor || !target) throw new Error('execution deployment is missing a contract address');
  const executorIface = new ethers.Interface(artifact('ReplayGatedExecutor').abi);
  const targetIface = new ethers.Interface(artifact('TestGovernedParameter').abi);
  const data = targetIface.encodeFunctionData('setValue', [42]);
  const actionHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['address', 'uint256', 'bytes32'], [target, 0, ethers.keccak256(data)]));
  await send('governed_executor_binding', target, targetIface.encodeFunctionData('setExecutor', [executor]), false);
  await send('governance_proposal_registration', executor, executorIface.encodeFunctionData('registerProposal',
    [input.admission, input.pollId, input.setupHash, input.threshold, target, 0, data]), false);
  return { executor, target, data, actionHash, verificationAuthority: authority.address,
    pollId: input.pollId, admission: input.admission, setupHash: input.setupHash, threshold: input.threshold };
}

async function finishExecution(options, configuration, authority, artifacts, send) {
  const { provider, ethers } = options;
  const iface = new ethers.Interface(artifacts.ReplayGatedExecutor.abi);
  const targetIface = new ethers.Interface(artifacts.TestGovernedParameter.abi);
  const getValue = async block => BigInt(await provider.send('eth_call', [{ to: configuration.target,
    data: targetIface.encodeFunctionData('value', []) }, block]));
  const before = await getValue('latest');
  if (before !== 0n) throw new Error('governed target is not in its fresh initial state');
  const attestation = await verifiedAuthorization(options, authority, configuration.executor, configuration.actionHash, 0);
  const receipt = await send('governance_execution', configuration.executor,
    iface.encodeFunctionData('execute', [attestation.value, configuration.target, 0, configuration.data, attestation.signature]), false);
  const after = await getValue(ethers.toQuantity(receipt.blockNumber));
  if (after !== 42n) throw new Error('confirmed governance action did not set the expected state');
  const logs = receipt.logs || [];
  const event = logs.filter(l => l.address.toLowerCase() === configuration.executor.toLowerCase())
    .map(l => { try { return iface.parseLog(l); } catch { return null; } }).find(l => l?.name === 'GovernanceExecuted');
  if (!event || Number(event.args.pollId) !== Number(attestation.value.pollId) ||
      event.args.transcriptHash !== attestation.value.transcriptHash || event.args.actionHash !== configuration.actionHash) {
    throw new Error('execution event does not match the verified authorization');
  }
  const result = { schema: 'wod/replay-gated-execution/v1', status: 'PASS', ...configuration,
    chain_id: attestation.domain.chainId, source_commit: options.sourceCommit,
    transcript_hash: attestation.value.transcriptHash, board_commitment: attestation.value.boardCommitment,
    decision: 1, state_before: before.toString(), state_after: after.toString(),
    execution_block: receipt.blockNumber, execution_transaction: receipt.hash || logs[0]?.transactionHash,
    execution_gas: receipt.gasUsed.toString(), receipt_bundle_sha256: attestation.receipt_bundle_sha256,
    trust: attestation.trust };
  writeNew(path.join(options.outDir, `${options.label}-governance.json`), result);
  return result;
}

module.exports = { compile, collect, verifyLive, verifiedAuthorization, prepareExecution, finishExecution,
  domain, statement, types, writeNew, sha256 };

async function localTest() {
  const opt = {};
  for (let i = 2; i < process.argv.length; i += 2) {
    if (!process.argv[i].startsWith('--') || !process.argv[i + 1]) throw new Error('expected --name value');
    opt[process.argv[i].slice(2)] = process.argv[i + 1];
  }
  for (const k of ['dir', 'reject-dir', 'out-dir', 'tools', 'wod']) if (!opt[k]) throw new Error(`missing --${k}`);
  const repo = path.resolve(__dirname, '..'), out = path.resolve(opt['out-dir']);
  if (fs.existsSync(out)) throw new Error('refusing to overwrite executor test output');
  fs.mkdirSync(path.join(out, 'public'), { recursive: true });
  const tools = path.resolve(opt.tools), wod = path.resolve(opt.wod);
  const ethers = require(path.join(tools, 'node_modules', 'ethers'));
  const solc = require(path.join(tools, 'node_modules', 'solc'));
  const savedWarn = console.warn, savedError = console.error;
  console.warn = () => {}; console.error = () => {};
  const ganache = require(path.join(tools, 'node_modules', 'ganache'));
  console.warn = savedWarn; console.error = savedError;
  const artifacts = compile(solc, repo);
  const evm = ganache.provider({ logging: { quiet: true }, chain: { chainId: 421614, hardfork: 'shanghai' },
    miner: { blockGasLimit: 30000000 }, wallet: { deterministic: true } });
  const provider = new ethers.BrowserProvider(evm);
  const source = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' });
  if (source.status !== 0) throw new Error('source commit unavailable');
  const sourceCommit = source.stdout.trim();
  const tests = {};
  try {
    const signer = await provider.getSigner(0);
    const authority = ethers.Wallet.createRandom(); // Local-only; no funded key or credentials.
    const outsider = ethers.Wallet.createRandom();
    const gas = {};
    async function deploy(name, args = []) {
      const a = artifacts[name];
      const c = await new ethers.ContractFactory(a.abi, '0x' + a.evm.bytecode.object, signer).deploy(...args);
      const r = await c.deploymentTransaction().wait();
      gas[name] = r.gasUsed.toString();
      return c;
    }
    async function prepare(run, name, wrongClaim = false) {
      const publicDir = path.join(out, name);
      fs.mkdirSync(path.join(publicDir, 'public'), { recursive: true });
      // Deliberately omit ledger.bin, every secret file and the private oracle.
      for (const f of ['setup.bin', 'transcript.bin']) fs.copyFileSync(path.join(run, 'public', f), path.join(publicDir, 'public', f));
      const exported = spawnSync(wod, ['evm-export', '--dir', run, '--out', path.join(publicDir, 'public', 'ballots.json')], { encoding: 'utf8', windowsHide: true });
      if (exported.status !== 0) throw new Error('public ballot export rejected');
      const input = JSON.parse(fs.readFileSync(path.join(publicDir, 'public', 'ballots.json'), 'utf8'));
      const k = input.verifyingKey;
      const verifier = await deploy('RustGroth16Verifier', [k.alpha, k.beta, k.gamma, k.delta, k.ic]);
      const board = await deploy('WodAdmission', [await verifier.getAddress()]);
      const deployment = await board.deploymentTransaction().wait();
      await (await board.registerPoll(input.pollId, input.registryRoot, ...input.committeeKey, input.expectedBallots)).wait();
      for (const b of input.ballots) await (await board.submitBallot(input.pollId, b.signals, b.proof.a, b.proof.b, b.proof.c, { gasLimit: 10000000n })).wait();
      await (await board.sealPoll(input.pollId)).wait();
      const cl = input.expectedClaim;
      await (await board.publishDecision(input.pollId, cl.commitment, cl.transcriptHash, wrongClaim ? 1 - Number(cl.decision) : Number(cl.decision))).wait();
      await provider.send('evm_mine', []);
      const admission = await board.getAddress();
      return { input, board, options: { provider, ethers, admission, pollId: input.pollId, fromBlock: deployment.blockNumber,
        runtimeHash: ethers.keccak256(await provider.getCode(admission)), outDir: path.join(out, 'public'), wod,
        publicDir, setupHash: input.setupHash, sourceCommit, label: name } };
    }
    const yes = await prepare(path.resolve(opt.dir), 'approval');
    if (Number(yes.input.expectedClaim.decision) !== 1) throw new Error('positive fixture must have decision 1');
    const executor = await deploy('ReplayGatedExecutor', [authority.address]);
    const target = await deploy('TestGovernedParameter');
    const executorAddress = await executor.getAddress(), targetAddress = await target.getAddress();
    gas.setExecutor = (await (await target.setExecutor(executorAddress)).wait()).gasUsed.toString();
    const data = target.interface.encodeFunctionData('setValue', [42]);
    const action = await executor.actionHash(targetAddress, 0, data);
    gas.registerProposal = (await (await executor.registerProposal(yes.options.admission, yes.input.pollId,
      yes.input.setupHash, yes.input.threshold, targetAddress, 0, data)).wait()).gasUsed.toString();
    const attestation = await verifiedAuthorization(yes.options, authority, executorAddress, action, 0);
    if (await executor.verificationDigest(attestation.value) !== ethers.TypedDataEncoder.hash(attestation.domain, types, attestation.value)) {
      throw new Error('Solidity EIP-712 digest differs from ethers');
    }
    tests.chainDerivedAllPredicates = true;
    tests.noSimulatedLedgerInVerifierDirectory = !fs.existsSync(path.join(yes.options.publicDir, 'public', 'ledger.bin'));
    async function expectRevert(label, value, sig, targetArg = targetAddress, dataArg = data) {
      const before = await target.value();
      let reverted = false;
      try {
        const tx = await executor.execute(value, targetArg, 0, dataArg, sig, { gasLimit: 1500000n });
        const receipt = await tx.wait();
        reverted = Number(receipt.status) === 0;
      } catch (e) { reverted = e.receipt && Number(e.receipt.status) === 0; }
      if (!reverted || await target.value() !== before) throw new Error(`${label} did not revert without state change`);
      tests[label] = true;
    }
    const v = attestation.value, sign = value => authority.signTypedData(attestation.domain, types, value);
    for (const [name, fields] of [
      ['wrongSetupHash', { setupHash: ethers.ZeroHash }], ['wrongThreshold', { threshold: BigInt(v.threshold) + 1n }],
      ['wrongBoardCommitment', { boardCommitment: ethers.ZeroHash }], ['wrongActionHash', { actionHash: ethers.ZeroHash }],
      ['wrongPoll', { pollId: BigInt(v.pollId) + 1n }], ['wrongAdmission', { admission: targetAddress }],
      ['wrongNonce', { nonce: 1 }], ['decisionZero', { decision: 0 }]
    ]) { const bad = { ...v, ...fields }; await expectRevert(name, bad, await sign(bad)); }
    await expectRevert('modifiedAction', v, attestation.signature, targetAddress, target.interface.encodeFunctionData('setValue', [99]));
    await expectRevert('forgedSignature', v, await outsider.signTypedData(attestation.domain, types, v));
    await expectRevert('wrongChainDomain', v, await authority.signTypedData({ ...attestation.domain, chainId: 1 }, types, v));
    await expectRevert('wrongExecutorDomain', v, await authority.signTypedData({ ...attestation.domain, verifyingContract: targetAddress }, types, v));
    const goodReceiptFile = path.join(out, 'public', 'approval-receipts.json');
    const originalBundle = JSON.parse(fs.readFileSync(goodReceiptFile, 'utf8'));
    const journalReport = await verifyLive({ ...yes.options, label: 'receipt-journal',
      transactionHashes: originalBundle.receipts.map(r => r.transactionHash) });
    if (!journalReport.accept || journalReport.transcript_hash !== v.transcriptHash) throw new Error('receipt journal replay differs');
    tests.receiptJournalReplay = true;
    async function expectRustRejection(label, bundle, dir = yes.options.publicDir, setupHash = yes.input.setupHash) {
      const before = await target.value();
      const file = path.join(out, 'public', `${label}-receipts.json`); writeNew(file, bundle);
      let rejected = false;
      try { rust(wod, ['evm-verify-chain', '--dir', dir, '--receipts', file,
        '--contract', yes.options.admission, '--chain-id', '421614', '--setup-hash', setupHash, '--source-commit', sourceCommit]); }
      catch { rejected = true; }
      if (!rejected || await target.value() !== before) throw new Error(`${label} was not rejected before signing`);
      tests[label] = true;
    }
    const tamperedDir = path.join(out, 'tampered-transcript');
    fs.mkdirSync(path.join(tamperedDir, 'public'), { recursive: true });
    for (const f of ['setup.bin', 'transcript.bin']) fs.copyFileSync(path.join(yes.options.publicDir, 'public', f), path.join(tamperedDir, 'public', f));
    const transcript = fs.readFileSync(path.join(tamperedDir, 'public', 'transcript.bin')); transcript[Math.floor(transcript.length / 2)] ^= 1;
    fs.writeFileSync(path.join(tamperedDir, 'public', 'transcript.bin'), transcript);
    await expectRustRejection('tamperedTranscript', originalBundle, tamperedDir);
    const modifiedBoard = structuredClone(originalBundle);
    const ballotReceipt = modifiedBoard.receipts.find(r => r.logs.some(l => l.topics[0] === ethers.id('BallotAccepted(uint64,uint64,uint256,uint256[32],uint256[2],uint256[2][2],uint256[2])')));
    const ballotLog = ballotReceipt.logs.find(l => l.address.toLowerCase() === yes.options.admission.toLowerCase());
    const bytes = ethers.getBytes(ballotLog.data); bytes[2 * 32 + 31] ^= 1; ballotLog.data = ethers.hexlify(bytes);
    await expectRustRejection('modifiedAcceptedBoard', modifiedBoard);
    await expectRustRejection('unapprovedSetup', originalBundle, yes.options.publicDir, ethers.ZeroHash);
    const incorrect = await prepare(path.resolve(opt.dir), 'incorrect-claim', true);
    let incorrectRejected = false;
    try { await verifiedAuthorization(incorrect.options, authority, executorAddress, action, 0); } catch { incorrectRejected = true; }
    if (!incorrectRejected || await target.value() !== 0n) throw new Error('incorrect published decision was authorized');
    tests.incorrectDecisionClaim = true;
    const no = await prepare(path.resolve(opt['reject-dir']), 'rejection');
    const zeroReport = await verifyLive(no.options);
    if (zeroReport.decision !== 0 || await target.value() !== 0n) throw new Error('negative fixture must verify decision 0');
    await (await executor.registerProposal(no.options.admission, no.input.pollId,
      no.input.setupHash, no.input.threshold, targetAddress, 0, data)).wait();
    const zeroValue = statement(zeroReport, action, 0);
    await expectRevert('validDecisionZeroOnChain', zeroValue, await sign(zeroValue));
    let zeroRefused = false;
    try { await verifiedAuthorization({ ...no.options, label: 'rejection-signing' }, authority, executorAddress, action, 0); } catch { zeroRefused = true; }
    if (!zeroRefused) throw new Error('production signer authorized decision 0');
    tests.validDecisionZeroRefused = true;
    const tx = await executor.execute(v, targetAddress, 0, data, attestation.signature);
    const receipt = await tx.wait(); gas.execute = receipt.gasUsed.toString();
    if (await target.value() !== 42n) throw new Error('governed state did not change');
    tests.validExecution = true;
    await expectRevert('replayedAuthorization', v, attestation.signature);
    const repeated = { ...v, nonce: 1 };
    await expectRevert('repeatedExecution', repeated, await sign(repeated));
    // Exercise the exact deployment and execution helpers used by the opt-in
    // testnet runner, through real local transactions and receipt collection.
    const localSend = async (kind, to, data, creation) => {
      const request = { data, gasLimit: creation ? 6000000n : 1500000n };
      if (!creation) request.to = to;
      return (await signer.sendTransaction(request)).wait();
    };
    const productionConfig = await prepareExecution({ ethers, artifacts, authority,
      input: { ...yes.input, admission: yes.options.admission }, send: localSend });
    const productionResult = await finishExecution({ ...yes.options, label: 'production-path' },
      productionConfig, authority, artifacts, localSend);
    if (productionResult.status !== 'PASS' || productionResult.state_after !== '42') throw new Error('shared execution path failed');
    tests.sharedProductionPath = true;
    const status = spawnSync('git', ['status', '--porcelain'], { cwd: repo, encoding: 'utf8' });
    const result = { schema: 'wod/executor-local-test/v1', status: 'PASS', local_evm_only: true,
      source_commit: sourceCommit, source_dirty: Boolean(status.stdout.trim()),
      chain_id: 421614, tests, gas, governed_value: '42', authority: authority.address,
      executor: executorAddress, target: targetAddress, successful_execution_transaction: receipt.hash,
      rust_verification_uses_only_chain_receipts_setup_transcript: true,
      trust: 'honest attesting verifier; authenticated RPC; ECDSA authorization, not on-chain transcript verification' };
    writeNew(path.join(out, 'public', 'executor-summary.json'), result);
    console.log(JSON.stringify(result, null, 2));
  } finally { await provider.destroy(); await evm.disconnect(); }
}
if (require.main === module) localTest().catch(error => {
  console.error(String(error.shortMessage || error.message || 'executor test failed').split(/\r?\n/)[0].slice(0,240));
  process.exitCode = 1;
});
