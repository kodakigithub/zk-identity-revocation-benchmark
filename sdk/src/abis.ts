/*
 * Minimal human-readable ABIs (ethers v6 format) for every contract the SDK and
 * apps touch. Hand-written to keep the SDK browser-safe: no artifact JSON / fs
 * reads needed at runtime. Deployment (Node-only) still uses full artifacts.
 */
export const ABIS: Record<string, string[]> = {
  DIDRegistry: [
    "function registerIssuer(bytes32 didHash)",
    "function isIssuer(bytes32 didHash) view returns (bool)",
    "event IssuerRegistered(bytes32 indexed didHash)",
  ],
  NullifierRegistry: [
    "function revoke(uint256 nullifier)",
    "function isRevoked(uint256 nullifier) view returns (bool)",
    "function issuer() view returns (address)",
    "event NullifierRevoked(uint256 indexed nullifier)",
  ],
  MerkleRevocationRegistry: [
    "function updateRoot(bytes32 newRoot)",
    "function currentRoot() view returns (bytes32)",
    "function issuer() view returns (address)",
    "event RootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot)",
  ],
  AccessControlNullifier: [
    "function verifyAndCheck(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[4] pubSignals) returns (bool)",
    "event ProofAccepted(address indexed prover)",
    "event ProofRejected(address indexed prover, string reason)",
  ],
  AccessControlMerkle: [
    "function verifyAndCheck(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[4] pubSignals) returns (bool)",
    "event ProofAccepted(address indexed prover)",
    "event ProofRejected(address indexed prover, string reason)",
  ],
};
