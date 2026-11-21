// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IAcceptedPoll {
    function pollState(uint64 pollId) external view returns (
        bool registered, uint64 expected, uint64 accepted, bool isSealed,
        bytes32 commitment, bool claimed
    );
}

/// Execution trusts the named verifier to check confirmed chain events and the
/// complete public Rust transcript before signing. ECDSA authentication is not
/// an on-chain CGY proof. The legacy poll exposes its sealed/claimed state;
/// the verifier authenticates the exact claim event's hash and decision.
contract ReplayGatedExecutor {
    address public immutable owner;
    address public immutable verificationAuthority;
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "Verification(address admission,uint64 pollId,bytes32 setupHash,uint64 threshold,bytes32 boardCommitment,bytes32 transcriptHash,uint8 decision,bytes32 actionHash,uint256 nonce)"
    );

    struct Proposal {
        bytes32 setupHash;
        uint64 threshold;
        bytes32 actionHash;
        uint256 nonce;
        bool registered;
        bool executed;
    }
    struct Verification {
        address admission;
        uint64 pollId;
        bytes32 setupHash;
        uint64 threshold;
        bytes32 boardCommitment;
        bytes32 transcriptHash;
        uint8 decision;
        bytes32 actionHash;
        uint256 nonce;
    }
    mapping(bytes32 => Proposal) public proposals;
    event ProposalRegistered(address indexed admission, uint64 indexed pollId,
        bytes32 setupHash, uint64 threshold, bytes32 actionHash);
    event GovernanceExecuted(address indexed admission, uint64 indexed pollId,
        bytes32 transcriptHash, bytes32 actionHash, uint256 nonce, address target);

    constructor(address verifier) {
        require(verifier != address(0), "zero verification authority");
        owner = msg.sender;
        verificationAuthority = verifier;
    }
    function proposalId(address admission, uint64 pollId) public pure returns (bytes32) {
        return keccak256(abi.encode(admission, pollId));
    }
    function actionHash(address target, uint256 value, bytes calldata data) public pure returns (bytes32) {
        return keccak256(abi.encode(target, value, keccak256(data)));
    }
    function registerProposal(address admission, uint64 pollId, bytes32 setupHash,
        uint64 threshold, address target, uint256 value, bytes calldata data) external
    {
        require(msg.sender == owner, "owner only");
        require(admission.code.length != 0 && target.code.length != 0, "contract required");
        require(setupHash != bytes32(0), "zero setup hash");
        bytes32 id = proposalId(admission, pollId);
        require(!proposals[id].registered, "proposal already registered");
        bytes32 action = actionHash(target, value, data);
        proposals[id] = Proposal(setupHash, threshold, action, 0, true, false);
        emit ProposalRegistered(admission, pollId, setupHash, threshold, action);
    }
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("VotingReplayExecutor"),
            keccak256("1"), block.chainid, address(this)));
    }
    function verificationDigest(Verification calldata v) public view returns (bytes32) {
        bytes32 statement = keccak256(abi.encode(ATTESTATION_TYPEHASH,
            v.admission, v.pollId, v.setupHash, v.threshold, v.boardCommitment,
            v.transcriptHash, v.decision, v.actionHash, v.nonce));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), statement));
    }
    function execute(Verification calldata v, address target, uint256 value,
        bytes calldata data, bytes calldata signature) external returns (bytes memory)
    {
        Proposal storage p = proposals[proposalId(v.admission, v.pollId)];
        require(p.registered && !p.executed, "proposal unavailable");
        require(v.nonce == p.nonce, "wrong nonce");
        require(v.decision == 1, "decision is not approval");
        require(v.setupHash == p.setupHash && v.threshold == p.threshold, "wrong setup");
        require(v.transcriptHash != bytes32(0), "zero transcript hash");
        require(v.actionHash == p.actionHash && actionHash(target, value, data) == p.actionHash, "wrong action");
        checkPoll(v);
        require(recover(verificationDigest(v), signature) == verificationAuthority, "unauthorized verification");
        p.executed = true;
        p.nonce++;
        (bool ok, bytes memory result) = target.call{value: value}(data);
        require(ok, "governance action failed");
        emit GovernanceExecuted(v.admission, v.pollId, v.transcriptHash, v.actionHash, v.nonce, target);
        return result;
    }
    function checkPoll(Verification calldata v) private view {
        (bool registered, uint64 expected, uint64 accepted, bool isSealed,
            bytes32 commitment, bool claimed) = IAcceptedPoll(v.admission).pollState(v.pollId);
        require(registered && isSealed && claimed && expected != 0 && expected == accepted, "poll incomplete");
        require(commitment == v.boardCommitment, "wrong accepted board");
    }
    function recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        require(signature.length == 65, "bad signature length");
        bytes32 r; bytes32 s; uint8 recovery;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            recovery := byte(0, calldataload(add(signature.offset, 64)))
        }
        require(recovery == 27 || recovery == 28, "bad recovery id");
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "noncanonical signature");
        return ecrecover(digest, recovery, r, s);
    }
}

/// A deliberately small test-only governed state. No funds are transferred.
contract TestGovernedParameter {
    address public immutable owner;
    address public executor;
    uint256 public value;
    constructor() { owner = msg.sender; }
    function setExecutor(address approvedExecutor) external {
        require(msg.sender == owner && executor == address(0), "executor already fixed");
        require(approvedExecutor.code.length != 0, "executor must be a contract");
        executor = approvedExecutor;
    }
    function setValue(uint256 next) external {
        require(msg.sender == executor, "executor only");
        value = next;
    }
}
