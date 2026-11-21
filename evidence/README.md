# Arbitrum Sepolia measurements

These measurements cover ballot-proof verification and admission, poll sealing, and publication of the winner-only decision on Arbitrum Sepolia (chain ID `421614`). The weighted encrypted tally remains off-chain; Rust independently verifies the public tally transcript and replays the accepted ballot events.

Each profile completed with all transactions confirmed, public event replay passing, and the Rust result matching the original run and oracle. Each profile contains `n + 5` transactions: two deployments, poll registration, `n` ballot admissions, sealing, and the decision claim.

| Ballots | Admission gas | Average gas per ballot | Setup gas¹ | Seal gas | Claim gas | Total gas | Receipt fees (ETH) | Result |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 8 | 6,192,720 | 774,090.0 | 3,671,697 | 53,755 | 32,502 | 9,950,674 | 0.000200458920670 | PASS |
| 64 | 49,541,388 | 774,084.2 | 3,671,721 | 53,755 | 32,502 | 53,299,366 | 0.001071110119324 | PASS |
| 256 | 198,170,616 | 774,104.0 | 3,671,745 | 53,755 | 32,502 | 201,928,618 | 0.004058359559042 | PASS |
| 1,024 | 792,668,748 | 774,090.6 | 3,671,733 | 53,755 | 32,490 | 796,426,726 | 0.016038167473630 | PASS |

¹ Setup gas includes verifier deployment, admission-board deployment, and poll registration. Total gas is the sum of all successful transaction receipts. Receipt fees are the sum of `gasUsed × effectiveGasPrice`; Arbitrum's L1 posting charge is already represented in the receipt fee and is not added again, following the [Arbitrum gas-estimation method](https://docs.arbitrum.io/arbitrum-essentials/how-to-estimate-gas). Values are measurements from the listed transactions, not extrapolations.

## On-chain records

Each board address links to its Arbiscan transaction and event history. The decision link points to that profile's final claim transaction.

| Ballots | Admission board | Decision claim | Verified proofs | Decision |
|---:|---|---|---:|---:|
| 8 | [0x75F8118c…2D63947](https://sepolia.arbiscan.io/address/0x75F8118c05E6812330610880A5fb94A8e2D63947) | [transaction](https://sepolia.arbiscan.io/tx/0xa1ac10bfc57ff1d9bca09588b77fb6b87795d54d50f61610bb698c84ffa38f37) | 8/8 | 1 |
| 64 | [0xB5809761…d32bd1b](https://sepolia.arbiscan.io/address/0xB5809761300e9375BF2271861eddCe1d2d32bd1b) | [transaction](https://sepolia.arbiscan.io/tx/0x4ea5fa34bc4eff9222428ae39e7e08742b3c7b693a28ecb4ce1c25424eb16b4c) | 64/64 | 1 |
| 256 | [0x9C7C0477…63F223](https://sepolia.arbiscan.io/address/0x9C7C047789A86b027276ab38D45C1651cC63F223) | [transaction](https://sepolia.arbiscan.io/tx/0x71ffffacb7f17ed9f1b39fd0976d091e591735c5c23b39b1bd6fe0e67871885e) | 256/256 | 1 |
| 1,024 | [0x0a6e96DD…061b86B7](https://sepolia.arbiscan.io/address/0x0a6e96DDc1095D521559E8Ffe9Db9E6A061b86B7) | [transaction](https://sepolia.arbiscan.io/tx/0xc8d4832450987a07f0c8c38a76bb1d18b645f51ffeb6f3309b73462a383e43b7) | 1,024/1,024 | 0 |

The contracts were compiled with Solidity `0.8.30`, optimizer enabled for 200 runs, targeting Shanghai. The measured adapter leaves the threshold in the Rust setup and checks leading ciphertext coordinates against `(0,0)`; Rust replay additionally rejects the Edwards identity `(0,1)`. Every recorded ballot passes the stricter Rust policy. Gas depends on the deployed bytecode, calldata, and network fee conditions; these values describe the recorded profiles.

## Source and evidence

- The Rust run used source commit [`d5da2ce`](https://github.com/CryptographyBloke/DAOVoting/commit/d5da2ce86b14a79c7498d655bf6e176c79a7c01e).
- The n=8, 64, and 256 transaction manifests identify that source revision. The n=1,024 manifest preserves its original local runner snapshot `b36bc8aaff583b8fa8d98fe1d9dafb618cadeddc`; its complete tree matches public commit [`6031a66`](https://github.com/CryptographyBloke/DAOVoting/commit/6031a66b30501d6b62bd89b8ecabd3ad3c8e2d9a). The interrupted n=1,024 poll resumed with runner commit [`24911d5`](https://github.com/CryptographyBloke/DAOVoting/commit/24911d52fef9d35f60fb86ad2211db0ac4fc70cf), recovered 16 receipts, and continued from 848 accepted ballots without redeployment.
- Solidity source SHA-256: `ad0c4df9bde6105ebf20b7c623b972f0b03852667d6bd8fe056789b3954f8d73`.
- Local run manifests, public inputs, event logs, and SHA-256 checksums are generated under the ignored `results/local/` directory. Private shares, witnesses, wallet credentials, and oracle inputs are not part of the public evidence.

Use [the reproduction guide](../docs/ARBITRUM_SEPOLIA.md) to run a fresh experiment. These transaction records are fixed evidence; a reproduction creates its own poll and pays its own testnet fees.

## Separate-VM computation

Board plus five Trustees run on six Ubuntu 24.04 Azure B2s_v2 VMs (2 vCPU, 8 GiB each), split between Japan East and Korea Central. Each Trustee VM has only its own share/signing key; Board has none. One test dealer/controller administers the experiment. Distinct physical hardware and independent operators are not established. Artificial RTT is zero. Proving and public verification run separately on the Windows controller.

| n | Repetitions | Proving s | Tally s | Public verify s | Signed messages | Transcript MB | Checks |
|---:|---:|---:|---:|---:|---:|---:|---|
| 8 | 3 | 2.00 | 5.09 | 0.61 | 390 | 0.66 | PASS |
| 64 | 3 | 14.69 | 21.19 | 1.78 | 570 | 5.10 | PASS |
| 256 | 1 | 54.43 | 73.81 | 5.62 | 690 | 20.26 | PASS |
| 1,024 | 1 | 207.29 | 268.24 | 20.17 | 810 | 80.85 | PASS |

Times are medians for three repetitions and individual measurements otherwise. Board tally spans START to all Trustee stats and includes release; it excludes connection setup. Per-host production, verification, waiting, RSS and observed RTT are in [multihost.json](multihost.json). The n=8 and n=64 tally ranges are 4.86–5.11 s and 20.68–21.35 s. All eight runs pass public verification and private-oracle agreement.

Disconnect, tampered signed POST, mismatched setup and wrong key-index experiments all prevent accepted completion. A wrong index rejects before connection and the supervisor stops the waiting Board. These tests establish neither liveness nor fairness. Original manifests retain all values. Two controller dirty flags correspond to concurrent EVM JS edits; the nodes run one pinned clean Rust binary. Board per-peer upstream copies in that revision can count an internal 5-byte EOF notification. The summary uses actual Trustee writer byte counts; source `07a81f8` fixes that bookkeeping. See [the deployment guide](../docs/MULTIHOST.md).

## Replay-authorized governance demonstration

The additional n=8 Arbitrum Sepolia profile completes 18 confirmed transactions. A live receipt-derived Rust replay passes every acceptance component before an authorized EIP-712 signature is generated; the executor then changes a test governed parameter from 0 to 42. The verifier directory contains setup and transcript, with no simulated ledger or private inputs.

- [Execution transaction](https://sepolia.arbiscan.io/tx/0xbe07f559c6665296682840ce9929932452c5db8e77e42e976e990157ab4eb84d), block 331314568, 107,841 gas.
- [Executor](https://sepolia.arbiscan.io/address/0xa7ac2f0da9cf19a76b108ce0adfbbdba3f9d1ac7); [governed target](https://sepolia.arbiscan.io/address/0x10737cc2e23709836ad3711db9cb5be30388625c).
- All 18 receipts cost 0.000231189119576 testnet ETH. A read-only check reconfirms canonical blocks, gas/fees, public replay and state 42.
- [governance.json](governance.json) records the exact setup/board/transcript/action bindings, source revisions, all transactions and 25 passing local EVM checks.

Execution additionally trusts the named honest attesting verifier and an authentic RPC view. The legacy poll exposes a claimed flag; the authority authenticates the exact claim event. An offline receipt JSON is not a chain light-client proof. The executor does not verify CGY on chain and does not automatically inherit the all-malicious-trustee theorem. The original four-scale admission evidence above is unchanged.

## Public download and hashes

Download the [v0.2.0 public evidence](https://github.com/CryptographyBloke/DAOVoting/releases/tag/v0.2.0). The `evidence.zip` contains original manifests, public verifier inputs/transcripts, per-host logs/RTT/RSS, expected-abort logs, real chain receipts and a checksum index. Trustee/voter secrets, RPC credentials, oracle inputs and proving work are excluded.

SHA-256 (`evidence.zip`): `9212d58464c0c149e945016776781ba0eb2c0b80f99b74dbb701fcf85be8fd62`. Size: 101,282,035 bytes. The historical admission archive retains SHA-256 `dcde886e8e7b4d0c90a61380318040b0eb24cbfa9befa37c6a06bc1d7ca163d4`.

For offline replay, copy a successful extracted run into a new working directory and invoke `wod verify --dir COPY`; do not overwrite its frozen `verify.json`. `INDEX.txt` provides the receipt-derived governance replay command. Offline replay verifies the supplied cryptographic evidence; authenticate blocks/receipts separately using a trusted live RPC view.
