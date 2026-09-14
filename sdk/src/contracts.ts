/*
 * Browser-safe chain helpers: contract handles from minimal ABIs, nonce-race-resilient
 * sending, and bytes32 encoding. Deployment/artifact loading lives in node/deploy.ts.
 */
import { ethers } from "ethers";
import { ABIS } from "./abis.js";

/** True for the stale-nonce race seen with Hardhat automine + ethers v6 polling. */
function isNonceRace(err: any): boolean {
  const msg = `${err?.code ?? ""} ${err?.message ?? ""} ${err?.info?.error?.message ?? ""}`;
  return /NONCE_EXPIRED|Nonce too low|nonce has already been used/i.test(msg);
}

/**
 * Send a contract transaction with retry on transient nonce races.
 * `send` must build a FRESH transaction per attempt (nonce re-fetched each time).
 */
export async function sendTx<T = ethers.TransactionReceipt>(
  send: () => Promise<ethers.TransactionResponse>,
  attempts = 5
): Promise<T> {
  let lastErr: any;
  for (let i = 0; i < attempts; i++) {
    try {
      const tx = await send();
      return (await tx.wait()) as T;
    } catch (err: any) {
      if (!isNonceRace(err) || i === attempts - 1) throw err;
      await new Promise((r) => setTimeout(r, 300 * (i + 1)));
      lastErr = err;
    }
  }
  throw lastErr;
}

/** Contract handle by name using the minimal ABI set. Works in Node and browser. */
export function getContract(
  name: keyof typeof ABIS | string,
  address: string,
  runner: ethers.ContractRunner
): ethers.Contract {
  const abi = ABIS[name as string];
  if (!abi) throw new Error(`no minimal ABI registered for contract "${name}"`);
  return new ethers.Contract(address, abi, runner);
}

/** bytes32 encoding of a (possibly large) uint256 root, matching Solidity's bytes32(uint256). */
export function toBytes32(value: bigint): string {
  return ethers.zeroPadValue(ethers.toBeHex(value), 32);
}
