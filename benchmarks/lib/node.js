/*
 * Shared benchmark plumbing: local chain lifecycle, signer, CSV writer.
 */
import { spawn } from "child_process";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { ethers } from "ethers";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(__dirname, "..", "..");
export const RESULTS_DIR = path.join(ROOT, "benchmarks", "results");

export const RPC_URL = process.env.LOCAL_RPC_URL || "http://127.0.0.1:8545";
// Hardhat node account #0 (well-known local key; benchmarks only).
export const DEPLOYER_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

let _spawned = null;

/** Connect to the local node; spawn a fresh `hardhat node` if none is listening. */
export async function ensureNode() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  try {
    await provider.getBlockNumber();
    return { provider, spawned: false };
  } catch {
    // fall through and spawn
  }
  _spawned = spawn("npx", ["hardhat", "node"], {
    cwd: path.join(ROOT, "contracts"),
    stdio: "ignore",
  });
  const t0 = Date.now();
  for (;;) {
    try {
      await provider.getBlockNumber();
      break;
    } catch {
      if (Date.now() - t0 > 30000) throw new Error("local node did not start");
      await new Promise((r) => setTimeout(r, 400));
    }
  }
  return { provider, spawned: true };
}

export function getSigner(provider) {
  return new ethers.Wallet(DEPLOYER_KEY, provider);
}

export function cleanupNode() {
  if (_spawned) {
    _spawned.kill();
    _spawned = null;
  }
}

/** Append rows (arrays) to a CSV in results/, writing a header if the file is new. */
export function writeCsv(fileName, header, rows) {
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const file = path.join(RESULTS_DIR, fileName);
  const exists = fs.existsSync(file);
  const lines = rows.map((r) => r.join(",")).join("\n") + "\n";
  if (!exists) fs.writeFileSync(file, header.join(",") + "\n" + lines);
  else fs.appendFileSync(file, lines);
  console.log(`  wrote ${rows.length} rows -> benchmarks/results/${fileName}`);
}

export function mean(xs) {
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}
export function std(xs) {
  const m = mean(xs);
  return Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / (xs.length - 1 || 1));
}
