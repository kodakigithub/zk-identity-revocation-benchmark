// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title NullifierRegistry — Scheme A revocation state.
/// @notice Maps credential nullifiers to revoked status. One storage slot per revoked
///         credential: on-chain storage grows LINEARLY with the revoked set. This is
///         the property the benchmark measures against Scheme B's constant-size root.
contract NullifierRegistry {
    address public immutable issuer;

    mapping(uint256 => bool) private _usedOrRevoked;

    event NullifierRevoked(uint256 indexed nullifier);

    modifier onlyIssuer() {
        require(msg.sender == issuer, "NullifierRegistry: caller is not the issuer");
        _;
    }

    constructor(address _issuer) {
        require(_issuer != address(0), "NullifierRegistry: zero issuer");
        issuer = _issuer;
    }

    /// @notice Revoke a credential by its nullifier (Poseidon(credentialSecret, externalNullifier)).
    function revoke(uint256 nullifier) external onlyIssuer {
        require(!_usedOrRevoked[nullifier], "NullifierRegistry: already revoked");
        _usedOrRevoked[nullifier] = true;
        emit NullifierRevoked(nullifier);
    }

    function isRevoked(uint256 nullifier) external view returns (bool) {
        return _usedOrRevoked[nullifier];
    }
}
