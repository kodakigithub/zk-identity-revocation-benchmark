/** Shared types for the ZK credential revocation SDK. */

export type Scheme = "nullifier" | "merkle";

export interface IssueOptions {
  /** The attribute the predicate is evaluated over, e.g. birth date as Unix seconds. */
  attributeValue: bigint;
  /** Human-readable birth date (ISO) carried in the VC for display purposes. */
  birthDate?: string;
  /** Holder DID/identifier string (free-form in the prototype). */
  holderId?: string;
}

export interface IssuedCredential {
  /** Signed W3C Verifiable Credential (secret NOT inside). */
  vc: Record<string, any>;
  /** Credential-binding secret. Prototype: returned to the caller (the holder). */
  credentialSecret: string;
  /** Poseidon(credentialSecret) — public binding between proof and credential. */
  commitment: string;
  /** Scheme A handle: Poseidon(credentialSecret, EXTERNAL_NULLIFIER). */
  nullifier: string;
  /** Scheme B handle: Poseidon(credentialSecret) mod 2^64. */
  smtKey: string;
  /** IPFS CID of the AES-GCM-encrypted { vc, credentialSecret } blob. */
  ipfsCid: string;
  /** Raw AES-256 key (hex) for decrypting the blob. Prototype convenience. */
  encryptionKey: string;
}

export interface ProofBundle {
  scheme: Scheme;
  proof: any;
  publicSignals: string[];
  /** Convenience decoded view of the 4 public signals. */
  signals: {
    credentialCommitment: string;
    revocationRef: string; // nullifier (A) or smtKey (B)
    threshold: string;
    context: string; // externalNullifier (A) or root (B)
  };
}

export interface VerifyResult {
  scheme: Scheme;
  /** Local (off-chain) Groth16 check against the verification key. */
  localValid: boolean;
  /** On-chain outcome, present when submitted to the access-control contract. */
  onChain?: {
    accepted: boolean;
    txHash: string;
    event: string; // "ProofAccepted" | "ProofRejected"
    reason?: string;
    gasUsed: string;
  };
}

export interface DeployedAddresses {
  didRegistry: string;
  nullifierRegistry: string;
  merkleRegistry: string;
  verifierNullifier: string;
  verifierSMT: string;
  accessNullifier: string;
  accessMerkle: string;
}
