/*
 * Issuer-side revocation. Identical logical interface for both schemes:
 *   - nullifier: recompute the nullifier and flip one mapping slot on-chain.
 *   - merkle:    insert smtKey -> 1 into the off-chain tree, push the new root.
 */
import { ethers } from "ethers";
import { getContract, sendTx, toBytes32 } from "./contracts.js";
import { computeNullifier } from "./poseidon.js";
import { RevocationTree } from "./revocationTree.js";
import type { Scheme } from "./types.js";

export interface RevokeArgs {
  credentialSecret: bigint;
  issuerSigner: ethers.Signer; // must be the registry's issuer
  nullifierRegistryAddress?: string; // scheme "nullifier"
  merkleRegistryAddress?: string; // scheme "merkle"
  revocationTree?: RevocationTree; // scheme "merkle"
}

export interface RevokeResult {
  scheme: Scheme;
  txHash: string;
  gasUsed: string;
  /** Scheme B only: the new root now on-chain. */
  newRoot?: string;
}

export async function revokeCredential(
  scheme: Scheme,
  args: RevokeArgs
): Promise<RevokeResult> {
  if (scheme === "nullifier") {
    if (!args.nullifierRegistryAddress) {
      throw new Error('scheme "nullifier" requires nullifierRegistryAddress');
    }
    const registry = getContract(
      "NullifierRegistry",
      args.nullifierRegistryAddress,
      args.issuerSigner
    );
    const nullifier = await computeNullifier(args.credentialSecret);
    const receipt: any = await sendTx(() => registry.revoke(nullifier));
    return { scheme, txHash: receipt.hash, gasUsed: receipt.gasUsed.toString() };
  }

  if (!args.merkleRegistryAddress || !args.revocationTree) {
    throw new Error('scheme "merkle" requires merkleRegistryAddress and revocationTree');
  }
  const newRoot = await args.revocationTree.revoke(args.credentialSecret);
  const registry = getContract(
    "MerkleRevocationRegistry",
    args.merkleRegistryAddress,
    args.issuerSigner
  );
  const receipt: any = await sendTx(() => registry.updateRoot(toBytes32(newRoot)));
  return {
    scheme,
    txHash: receipt.hash,
    gasUsed: receipt.gasUsed.toString(),
    newRoot: newRoot.toString(),
  };
}
