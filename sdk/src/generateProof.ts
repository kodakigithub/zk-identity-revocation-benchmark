/*
 * Generate a Groth16 attribute proof for either revocation scheme.
 * The predicate and credential-binding portion is identical across schemes;
 * only the revocation witness differs (nullifier output vs SMT non-membership).
 */
import * as path from "path";
import { snarkjs } from "./deps.js";
import { CIRCUITS_BUILD } from "./paths.js";
import { EXTERNAL_NULLIFIER } from "./poseidon.js";
import { RevocationTree } from "./revocationTree.js";
import type { ProofBundle, Scheme } from "./types.js";

export interface GenerateProofArgs {
  credentialSecret: bigint;
  attributeValue: bigint;
  threshold: bigint;
  /** Required for scheme "merkle": the issuer's current revocation tree view. */
  revocationTree?: RevocationTree;
  /** Optional artifact overrides (default: circuits/build outputs). */
  wasmPath?: string;
  zkeyPath?: string;
}

function defaultArtifacts(scheme: Scheme): { wasm: string; zkey: string } {
  return scheme === "nullifier"
    ? {
        wasm: path.join(CIRCUITS_BUILD, "attribute_proof_js", "attribute_proof.wasm"),
        zkey: path.join(CIRCUITS_BUILD, "attribute_proof_final.zkey"),
      }
    : {
        wasm: path.join(CIRCUITS_BUILD, "attribute_proof_smt_js", "attribute_proof_smt.wasm"),
        zkey: path.join(CIRCUITS_BUILD, "attribute_proof_smt_final.zkey"),
      };
}

export async function generateProof(
  scheme: Scheme,
  args: GenerateProofArgs
): Promise<ProofBundle> {
  const artifacts = {
    wasm: args.wasmPath ?? defaultArtifacts(scheme).wasm,
    zkey: args.zkeyPath ?? defaultArtifacts(scheme).zkey,
  };

  let input: Record<string, any>;
  if (scheme === "nullifier") {
    input = {
      attributeValue: args.attributeValue,
      threshold: args.threshold,
      credentialSecret: args.credentialSecret,
      externalNullifier: EXTERNAL_NULLIFIER,
    };
  } else {
    if (!args.revocationTree) {
      throw new Error('scheme "merkle" requires args.revocationTree');
    }
    // Throws if the credential is revoked — no valid non-membership witness exists.
    const witness = await args.revocationTree.nonMembershipWitness(args.credentialSecret);
    input = {
      attributeValue: args.attributeValue,
      threshold: args.threshold,
      credentialSecret: args.credentialSecret,
      siblings: witness.siblings,
      oldKey: witness.oldKey,
      oldValue: witness.oldValue,
      isOld0: witness.isOld0,
      root: witness.root,
    };
  }

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    artifacts.wasm,
    artifacts.zkey
  );

  // Public signal order (see circuit comments): outputs first, then public inputs.
  return {
    scheme,
    proof,
    publicSignals,
    signals: {
      credentialCommitment: publicSignals[0],
      revocationRef: publicSignals[1],
      threshold: publicSignals[2],
      context: publicSignals[3],
    },
  };
}
