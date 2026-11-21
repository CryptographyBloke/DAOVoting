# Arbitrum Sepolia measurements

These measurements cover ballot-proof verification and admission, poll sealing, and publication of the winner-only decision on Arbitrum Sepolia (chain ID `421614`). The weighted encrypted tally remains off-chain; Rust independently verifies the public tally transcript and replays the accepted ballot events.

Each profile completed with all transactions confirmed, public event replay passing, and the Rust result matching the original run and oracle. Each profile contains `n + 5` transactions: two deployments, poll registration, `n` ballot admissions, sealing, and the decision claim.

| Ballots | Admission gas | Average gas per ballot | Setup gas¹ | Seal gas | Claim gas | Total gas | Receipt fees (ETH) | Result |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 8 | 6,192,720 | 774,090.0 | 3,671,697 | 53,755 | 32,502 | 9,950,674 | 0.000200458920670 | PASS |
| 64 | 49,541,388 | 774,084.2 | 3,671,721 | 53,755 | 32,502 | 53,299,366 | 0.001071110119324 | PASS |
| 256 | 198,170,616 | 774,104.8 | 3,671,745 | 53,755 | 32,502 | 201,928,618 | 0.004058359559042 | PASS |
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

The contracts were compiled with Solidity `0.8.30`, optimizer enabled for 200 runs, targeting Shanghai. Gas depends on the deployed bytecode, calldata, and network fee conditions; these values describe the recorded profiles.

## Source and evidence

- The Rust run used source commit [`d5da2ce`](https://github.com/CryptographyBloke/DAOVoting/commit/d5da2ce86b14a79c7498d655bf6e176c79a7c01e).
- The n=8, 64, and 256 transaction manifests identify that source revision. The n=1,024 manifest preserves its original local runner snapshot `b36bc8aaff583b8fa8d98fe1d9dafb618cadeddc`; its complete tree matches public commit [`6031a66`](https://github.com/CryptographyBloke/DAOVoting/commit/6031a66b30501d6b62bd89b8ecabd3ad3c8e2d9a). The interrupted n=1,024 poll resumed with runner commit [`24911d5`](https://github.com/CryptographyBloke/DAOVoting/commit/24911d52fef9d35f60fb86ad2211db0ac4fc70cf), recovered 16 receipts, and continued from 848 accepted ballots without redeployment.
- Solidity source SHA-256: `ad0c4df9bde6105ebf20b7c623b972f0b03852667d6bd8fe056789b3954f8d73`.
- Local run manifests, public inputs, event logs, and SHA-256 checksums are generated under the ignored `results/local/` directory. Private shares, witnesses, wallet credentials, and oracle inputs are not part of the public evidence.

Use [the reproduction guide](../docs/ARBITRUM_SEPOLIA.md) to run a fresh experiment. These transaction records are fixed evidence; a reproduction creates its own poll and pays its own testnet fees.
