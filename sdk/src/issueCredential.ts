/*
 * Issue a W3C Verifiable Credential (Ed25519-signed), generate the credential-binding
 * secret, encrypt {vc, secret} and store it on IPFS (helia). Only the CID and the
 * on-chain anchors leave the issuer.
 */
import {
  signCredential,
  verifyCredentialSignature,
  encryptBlob,
  bytesToHex,
  IssuerKeys,
} from "./crypto.js";
import { storeBlob } from "./storage.js";
import { computeCommitment, computeNullifier, computeSmtKey } from "./poseidon.js";
import type { IssueOptions, IssuedCredential } from "./types.js";

/** Random 250-bit secret — always below the BN128 field prime. */
export function generateCredentialSecret(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(32)); // WebCrypto: Node 19+ and browsers
  bytes[0] &= 0x03; // clamp to 250 bits
  return BigInt("0x" + bytesToHex(bytes));
}

export async function issueCredential(
  issuer: IssuerKeys,
  opts: IssueOptions
): Promise<IssuedCredential> {
  const credentialSecret = generateCredentialSecret();
  const [commitment, nullifier, smtKey] = await Promise.all([
    computeCommitment(credentialSecret),
    computeNullifier(credentialSecret),
    computeSmtKey(credentialSecret),
  ]);

  const vcCore = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "ZkAttributeCredential"],
    issuer: `did:zkcr:issuer:${issuer.publicKeyHex.slice(0, 16)}`,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: opts.holderId ?? "did:zkcr:holder:anonymous",
      attributeValue: opts.attributeValue.toString(),
      ...(opts.birthDate ? { birthDate: opts.birthDate } : {}),
    },
    // Public binding between this credential and later ZK proofs.
    credentialCommitment: commitment.toString(),
  };
  const vc = await signCredential(vcCore, issuer);

  // Sanity: self-verify the signature before persisting.
  if (!(await verifyCredentialSignature(vc, issuer.publicKeyHex))) {
    throw new Error("internal: freshly signed credential failed verification");
  }

  // Encrypt { vc, secret } and store on IPFS; only the CID leaves the machine.
  const plaintext = new TextEncoder().encode(
    JSON.stringify({ vc, credentialSecret: credentialSecret.toString() })
  );
  const { envelope, keyHex } = await encryptBlob(plaintext);
  const ipfsCid = await storeBlob(envelope);

  return {
    vc,
    credentialSecret: credentialSecret.toString(),
    commitment: commitment.toString(),
    nullifier: nullifier.toString(),
    smtKey: smtKey.toString(),
    ipfsCid,
    encryptionKey: keyHex,
  };
}
