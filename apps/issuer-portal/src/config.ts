/*
 * App chain config (prototype): local Hardhat node + the well-known account #0 key.
 * No MetaMask by design — deterministic, scriptable demo flows.
 */
import { ethers } from "ethers";

export const RPC_URL = "http://127.0.0.1:8545";
export const DEPLOYER_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

export interface Deployment {
  didRegistry: string;
  nullifierRegistry: string;
  merkleRegistry: string;
  verifierNullifier: string;
  verifierSMT: string;
  accessNullifier: string;
  accessMerkle: string;
}

export async function loadDeployment(): Promise<Deployment> {
  const res = await fetch("/deployment.json", { cache: "no-store" });
  if (!res.ok) {
    throw new Error(
      "deployment.json not found — run: npm run node && npm run deploy:local -w @zkcr/contracts && npm run sync:apps"
    );
  }
  return res.json();
}

export function getProvider(): ethers.JsonRpcProvider {
  return new ethers.JsonRpcProvider(RPC_URL);
}

export function getSigner(provider: ethers.JsonRpcProvider): ethers.Wallet {
  return new ethers.Wallet(DEPLOYER_KEY, provider);
}
