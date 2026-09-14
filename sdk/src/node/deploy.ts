/*
 * Node-only helpers (use `fs`): Hardhat artifact loading, full-system deployment,
 * deployment-file loading, verification-key loading. NOT for browser bundles —
 * import these via `@zkcr/sdk/node`.
 */
import * as fs from "fs";
import * as path from "path";
import { ethers } from "ethers";
import { ARTIFACTS_DIR, CIRCUITS_BUILD, DEPLOYMENTS_DIR } from "../paths.js";
import type { DeployedAddresses, Scheme } from "../types.js";

function artifactPath(name: string): string {
  // Generated verifiers live one directory deeper.
  const verifier = path.join(ARTIFACTS_DIR, "verifiers", `${name}.sol`, `${name}.json`);
  if (fs.existsSync(verifier)) return verifier;
  return path.join(ARTIFACTS_DIR, `${name}.sol`, `${name}.json`);
}

export function loadArtifact(name: string): { abi: any; bytecode: string } {
  const p = artifactPath(name);
  if (!fs.existsSync(p)) {
    throw new Error(
      `artifact for ${name} not found at ${p}. Run: npm run compile -w @zkcr/contracts`
    );
  }
  const j = JSON.parse(fs.readFileSync(p, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode };
}

export async function deployContract(
  signer: ethers.Signer,
  name: string,
  args: any[] = []
): Promise<string> {
  const { abi, bytecode } = loadArtifact(name);
  const factory = new ethers.ContractFactory(abi, bytecode, signer);
  let lastErr: any;
  for (let i = 0; i < 5; i++) {
    try {
      const c = await factory.deploy(...args);
      await c.waitForDeployment();
      return c.getAddress();
    } catch (err: any) {
      const msg = `${err?.code ?? ""} ${err?.message ?? ""}`;
      const race = /NONCE_EXPIRED|Nonce too low|nonce has already been used/i.test(msg);
      if (!race || i === 4) throw err;
      await new Promise((r) => setTimeout(r, 300 * (i + 1)));
      lastErr = err;
    }
  }
  throw lastErr;
}

/** Deploy the full system with the signer's address as the revocation issuer. */
export async function deploySystem(signer: ethers.Signer): Promise<DeployedAddresses> {
  const issuerAddress = await signer.getAddress();
  const didRegistry = await deployContract(signer, "DIDRegistry");
  const nullifierRegistry = await deployContract(signer, "NullifierRegistry", [issuerAddress]);
  const merkleRegistry = await deployContract(signer, "MerkleRevocationRegistry", [issuerAddress]);
  const verifierNullifier = await deployContract(signer, "Groth16VerifierNullifier");
  const verifierSMT = await deployContract(signer, "Groth16VerifierSMT");
  const accessNullifier = await deployContract(signer, "AccessControlNullifier", [
    verifierNullifier,
    nullifierRegistry,
  ]);
  const accessMerkle = await deployContract(signer, "AccessControlMerkle", [
    verifierSMT,
    merkleRegistry,
  ]);
  return {
    didRegistry,
    nullifierRegistry,
    merkleRegistry,
    verifierNullifier,
    verifierSMT,
    accessNullifier,
    accessMerkle,
  };
}

/** Load the deployment file written by contracts/scripts/deploy.ts. */
export function loadDeployment(network: string): DeployedAddresses {
  const p = path.join(DEPLOYMENTS_DIR, `${network}.json`);
  if (!fs.existsSync(p)) {
    throw new Error(`no deployment file for network "${network}" at ${p}`);
  }
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

const VKEY_FILES: Record<Scheme, string> = {
  nullifier: "attribute_proof_verification_key.json",
  merkle: "attribute_proof_smt_verification_key.json",
};

/** Load the exported Groth16 verification key for a scheme (Node only). */
export function loadVerificationKey(scheme: Scheme): any {
  return JSON.parse(fs.readFileSync(path.join(CIRCUITS_BUILD, VKEY_FILES[scheme]), "utf8"));
}
