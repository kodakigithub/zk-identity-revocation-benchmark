// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Shared interface for the snarkjs-generated Groth16 verifier contracts.
///         Both circuit variants expose exactly 4 public signals:
///         Scheme A: [credentialCommitment, nullifier, threshold, externalNullifier]
///         Scheme B: [credentialCommitment, smtKey,    threshold, root]
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals
    ) external view returns (bool);
}
