// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IGroth16Verifier.sol";
import "./MerkleRevocationRegistry.sol";

/// @title AccessControlMerkle — Scheme B verification entrypoint.
/// @notice Identical interface to AccessControlNullifier (gas-benchmark parity).
///         Checks the Groth16 proof AND that the proven SMT root equals the registry's
///         current root, emitting exactly one ProofAccepted / ProofRejected event.
///         pubSignals layout: [0] credentialCommitment, [1] smtKey,
///                            [2] threshold,            [3] root.
contract AccessControlMerkle {
    IGroth16Verifier public immutable verifier;
    MerkleRevocationRegistry public immutable registry;

    event ProofAccepted(address indexed prover);
    event ProofRejected(address indexed prover, string reason);

    constructor(address _verifier, address _registry) {
        verifier = IGroth16Verifier(_verifier);
        registry = MerkleRevocationRegistry(_registry);
    }

    /// @notice Verify the proof, then enforce that its SMT root is the current root.
    function verifyAndCheck(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals
    ) external returns (bool) {
        bool proofOk = verifier.verifyProof(pA, pB, pC, pubSignals);
        if (!proofOk) {
            emit ProofRejected(msg.sender, "invalid proof");
            return false;
        }
        uint256 provenRoot = pubSignals[3];
        if (bytes32(provenRoot) != registry.currentRoot()) {
            emit ProofRejected(msg.sender, "revocation root mismatch");
            return false;
        }
        emit ProofAccepted(msg.sender);
        return true;
    }
}
