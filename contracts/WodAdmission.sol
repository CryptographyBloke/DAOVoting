// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Arkworks BN254 Groth16 verifier. Public inputs follow ballot::Statement order:
/// 32 BabyJubjub ciphertext coordinates, nullifier, registry root, poll id,
/// and the two committee-key coordinates.
contract RustGroth16Verifier {
    uint256 private constant FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 private constant PUBLIC_INPUTS = 37;

    uint256[2] private alpha1;
    // G2 coordinates use EIP-197 order: imaginary coefficient, then real.
    uint256[2][2] private beta2;
    uint256[2][2] private gamma2;
    uint256[2][2] private delta2;
    uint256[2][] private gammaAbc1;

    constructor(
        uint256[2] memory alpha,
        uint256[2][2] memory beta,
        uint256[2][2] memory gamma,
        uint256[2][2] memory delta,
        uint256[2][] memory ic
    ) {
        require(ic.length == PUBLIC_INPUTS + 1, "bad IC length");
        alpha1 = alpha;
        beta2 = beta;
        gamma2 = gamma;
        delta2 = delta;
        for (uint256 i; i < ic.length; ++i) gammaAbc1.push(ic[i]);
    }

    function verify(
        uint256[37] calldata signals,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external view returns (bool) {
        uint256[2] memory vkX = gammaAbc1[0];
        for (uint256 i; i < PUBLIC_INPUTS; ++i) {
            uint256 signal = signals[i];
            if (signal >= FR) return false;
            (bool mulOk, uint256[2] memory term) = _ecMul(gammaAbc1[i + 1], signal);
            if (!mulOk) return false;
            (bool addOk, uint256[2] memory sum) = _ecAdd(vkX, term);
            if (!addOk) return false;
            vkX = sum;
        }

        uint256[24] memory pairingInput;
        // e(A, B)
        pairingInput[0] = proofA[0];
        pairingInput[1] = proofA[1];
        pairingInput[2] = proofB[0][0];
        pairingInput[3] = proofB[0][1];
        pairingInput[4] = proofB[1][0];
        pairingInput[5] = proofB[1][1];
        // e(-alpha, beta)
        pairingInput[6] = alpha1[0];
        pairingInput[7] = _negateY(alpha1[1]);
        pairingInput[8] = beta2[0][0];
        pairingInput[9] = beta2[0][1];
        pairingInput[10] = beta2[1][0];
        pairingInput[11] = beta2[1][1];
        // e(-vkX, gamma)
        pairingInput[12] = vkX[0];
        pairingInput[13] = _negateY(vkX[1]);
        pairingInput[14] = gamma2[0][0];
        pairingInput[15] = gamma2[0][1];
        pairingInput[16] = gamma2[1][0];
        pairingInput[17] = gamma2[1][1];
        // e(-C, delta)
        pairingInput[18] = proofC[0];
        pairingInput[19] = _negateY(proofC[1]);
        pairingInput[20] = delta2[0][0];
        pairingInput[21] = delta2[0][1];
        pairingInput[22] = delta2[1][0];
        pairingInput[23] = delta2[1][1];

        uint256[1] memory output;
        bool ok;
        assembly {
            ok := staticcall(gas(), 8, pairingInput, 0x300, output, 0x20)
        }
        return ok && output[0] == 1;
    }

    function _negateY(uint256 y) private pure returns (uint256) {
        return y == 0 ? 0 : FQ - y;
    }

    function _ecAdd(uint256[2] memory p, uint256[2] memory q)
        private view returns (bool ok, uint256[2] memory result)
    {
        uint256[4] memory input = [p[0], p[1], q[0], q[1]];
        assembly {
            ok := staticcall(gas(), 6, input, 0x80, result, 0x40)
        }
    }

    function _ecMul(uint256[2] memory p, uint256 scalar)
        private view returns (bool ok, uint256[2] memory result)
    {
        uint256[3] memory input = [p[0], p[1], scalar];
        assembly {
            ok := staticcall(gas(), 7, input, 0x60, result, 0x40)
        }
    }
}

/// Minimal poll admission and publication contract. The tally transcript and
/// its cryptographic checks remain off-chain and are independently replayed by
/// Rust. The contract pins the accepted ciphertext board and accepts only a
/// binary claim bound to that sealed commitment.
contract WodAdmission {
    uint256 private constant FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint64 private constant MIN_VOTERS = 8;
    uint64 private constant MAX_VOTERS = 1024;
    string private constant INITIAL_DOMAIN = "wod/accepted-ballots/v1";

    struct Poll {
        uint256 registryRoot;
        uint256 committeeX;
        uint256 committeeY;
        uint64 expectedBallots;
        uint64 acceptedBallots;
        bool registered;
        bool isSealed;
        bool claimed;
        bytes32 accumulator;
        bytes32 sealedCommitment;
    }

    RustGroth16Verifier public immutable verifier;
    address public immutable owner;
    mapping(uint64 => Poll) private polls;
    mapping(uint64 => mapping(uint256 => bool)) private seenNullifier;

    event PollRegistered(uint64 indexed pollId, uint256 registryRoot, uint256 committeeX, uint256 committeeY, uint64 expectedBallots);
    event BallotAccepted(
        uint64 indexed pollId,
        uint64 index,
        uint256 nullifier,
        uint256[32] coordinates,
        uint256[2] proofA,
        uint256[2][2] proofB,
        uint256[2] proofC
    );
    event PollSealed(uint64 indexed pollId, uint64 count, bytes32 commitment);
    event DecisionClaimed(uint64 indexed pollId, bytes32 commitment, bytes32 transcriptHash, uint8 decision);

    constructor(address verifierAddress) {
        require(verifierAddress != address(0), "zero verifier");
        verifier = RustGroth16Verifier(verifierAddress);
        owner = msg.sender;
    }

    function registerPoll(
        uint64 pollId,
        uint256 registryRoot,
        uint256 committeeX,
        uint256 committeeY,
        uint64 expectedBallots
    ) external {
        require(msg.sender == owner, "owner only");
        require(!polls[pollId].registered, "poll exists");
        require(expectedBallots >= MIN_VOTERS && expectedBallots <= MAX_VOTERS, "unsupported size");
        require((expectedBallots & (expectedBallots - 1)) == 0, "size must be power of two");
        require(registryRoot < FR && committeeX < FR && committeeY < FR, "field overflow");

        Poll storage p = polls[pollId];
        p.registryRoot = registryRoot;
        p.committeeX = committeeX;
        p.committeeY = committeeY;
        p.expectedBallots = expectedBallots;
        p.registered = true;
        p.accumulator = keccak256(
            abi.encodePacked(bytes(INITIAL_DOMAIN), pollId, bytes32(registryRoot), bytes32(committeeX), bytes32(committeeY))
        );
        emit PollRegistered(pollId, registryRoot, committeeX, committeeY, expectedBallots);
    }

    function submitBallot(
        uint64 pollId,
        uint256[37] calldata signals,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external {
        Poll storage p = polls[pollId];
        require(p.registered && !p.isSealed, "poll unavailable");
        require(p.acceptedBallots < p.expectedBallots, "poll full");
        require(signals[33] == p.registryRoot, "wrong registry root");
        require(signals[34] == uint256(pollId), "wrong poll id");
        require(signals[35] == p.committeeX && signals[36] == p.committeeY, "wrong committee key");
        uint256 nullifier = signals[32];
        require(nullifier < FR && !seenNullifier[pollId][nullifier], "duplicate nullifier");
        for (uint256 i; i < 8; ++i) {
            require(signals[4 * i] != 0 || signals[4 * i + 1] != 0, "identity ciphertext");
        }
        require(verifier.verify(signals, proofA, proofB, proofC), "invalid ballot proof");

        seenNullifier[pollId][nullifier] = true;
        uint64 index = p.acceptedBallots;
        uint256[32] memory coordinates;
        for (uint256 i; i < 32; ++i) coordinates[i] = signals[i];
        p.accumulator = keccak256(abi.encodePacked(p.accumulator, index, bytes32(nullifier), coordinates));
        p.acceptedBallots = index + 1;
        emit BallotAccepted(pollId, index, nullifier, coordinates, proofA, proofB, proofC);
    }

    function sealPoll(uint64 pollId) external {
        Poll storage p = polls[pollId];
        require(p.registered && !p.isSealed, "poll unavailable");
        require(p.acceptedBallots == p.expectedBallots, "wrong ballot count");
        p.isSealed = true;
        p.sealedCommitment = keccak256(abi.encodePacked(bytes("wod/seal/v1"), p.accumulator, p.expectedBallots));
        emit PollSealed(pollId, p.acceptedBallots, p.sealedCommitment);
    }

    function publishDecision(uint64 pollId, bytes32 commitment, bytes32 transcriptHash, uint8 decision) external {
        require(msg.sender == owner, "owner only");
        Poll storage p = polls[pollId];
        require(p.isSealed && !p.claimed, "poll not claimable");
        require(commitment == p.sealedCommitment, "wrong board commitment");
        require(transcriptHash != bytes32(0), "zero transcript hash");
        require(decision <= 1, "decision must be a bit");
        p.claimed = true;
        emit DecisionClaimed(pollId, commitment, transcriptHash, decision);
    }

    function pollState(uint64 pollId)
        external view returns (bool registered, uint64 expected, uint64 accepted, bool isSealed, bytes32 commitment, bool claimed)
    {
        Poll storage p = polls[pollId];
        return (p.registered, p.expectedBallots, p.acceptedBallots, p.isSealed, p.sealedCommitment, p.claimed);
    }
}
