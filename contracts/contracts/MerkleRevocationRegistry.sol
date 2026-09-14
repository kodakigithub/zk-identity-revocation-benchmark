// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MerkleRevocationRegistry — Scheme B revocation state.
/// @notice Stores ONLY the current root of the issuer's off-chain sparse Merkle tree.
///         On-chain storage is CONSTANT (one slot) no matter how many credentials are
///         revoked; the per-revocation cost is one SSTORE of the new root.
contract MerkleRevocationRegistry {
    address public immutable issuer;

    bytes32 public currentRoot;

    event RootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot);

    modifier onlyIssuer() {
        require(msg.sender == issuer, "MerkleRevocationRegistry: caller is not the issuer");
        _;
    }

    constructor(address _issuer) {
        require(_issuer != address(0), "MerkleRevocationRegistry: zero issuer");
        issuer = _issuer;
    }

    /// @notice Publish the new off-chain tree root after a revocation (or batch).
    function updateRoot(bytes32 newRoot) external onlyIssuer {
        bytes32 old = currentRoot;
        currentRoot = newRoot;
        emit RootUpdated(old, newRoot);
    }
}
