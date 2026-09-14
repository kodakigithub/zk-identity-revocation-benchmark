// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IGroth16Verifier.sol";
import "./NullifierRegistry.sol";

/// @title AccessControlNullifier — Scheme A verification entrypoint.
/// @notice Checks a Groth16 proof AND the revocation state, then emits exactly one
///         ProofAccepted / ProofRejected event. Interface is kept identical to
///         AccessControlMerkle so the gas benchmark compares revocation logic only.
///         pubSignals layout: [0] credentialCommitment, [1] nullifier,
///                            [2] threshold,            [3] externalNullifier.
contract AccessControlNullifier {
    IGroth16Verifier public immutable verifier;
    NullifierRegistry public immutable registry;

    event ProofAccepted(address indexed prover);
    event ProofRejected(address indexed prover, string reason);

    constructor(address _verifier, address _registry) {
        verifier = IGroth16Verifier(_verifier);
        registry = NullifierRegistry(_registry);
    }

    /// @notice Verify the proof, then enforce that its nullifier is not revoked.
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
        uint256 nullifier = pubSignals[1];
        if (registry.isRevoked(nullifier)) {
            emit ProofRejected(msg.sender, "credential revoked");
            return false;
        }
        emit ProofAccepted(msg.sender);
        return true;
    }
}
