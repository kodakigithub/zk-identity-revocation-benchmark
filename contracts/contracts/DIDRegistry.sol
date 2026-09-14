// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DIDRegistry — minimal issuer anchor for the research prototype.
/// @notice Stores registered issuer DID hashes. One hardcoded issuer is fine for v1;
///         this contract exists so the architecture has an explicit trust anchor.
contract DIDRegistry {
    mapping(bytes32 => bool) private _issuers;

    event IssuerRegistered(bytes32 indexed didHash);

    /// @notice Register an issuer DID hash. Permissionless in the prototype
    ///         (single hardcoded issuer; no governance framework by design).
    function registerIssuer(bytes32 didHash) external {
        require(!_issuers[didHash], "DIDRegistry: already registered");
        _issuers[didHash] = true;
        emit IssuerRegistered(didHash);
    }

    function isIssuer(bytes32 didHash) external view returns (bool) {
        return _issuers[didHash];
    }
}
