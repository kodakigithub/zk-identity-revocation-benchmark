/*
 * Proof-generation time benchmark (Section 7.2).
 *
 * For each circuit variant, run T Groth16 proving trials (WASM witness generation +
 * proving) with fresh random secrets, recording wall-clock time (performance.now)
 * and heap delta (process.memoryUsage) per trial.
 *
 * CSV columns: scheme,trial,time_ms,memory_delta_bytes
 * Prints mean and standard deviation per scheme.
 *
 * Usage: node proof-time/bench-proof-time.js [T=30]
 */
import { createRequire } from "module";
import { RevocationTree, generateCredentialSecret } from "@zkcr/sdk/node";
import { writeCsv, mean, std } from "../lib/node.js";

const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");

const T = parseInt(process.argv[2] || "30", 10);

const ATTRIBUTE = 946684800n;
const THRESHOLD = BigInt(Math.floor(Date.now() / 1000) - Math.floor(18 * 365.25 * 86400));
const EXTERNAL_NULLIFIER = 42n;

const ARTIFACTS = {
  nullifier: {
    wasm: "../circuits/build/attribute_proof_js/attribute_proof.wasm",
    zkey: "../circuits/build/attribute_proof_final.zkey",
  },
  merkle: {
    wasm: "../circuits/build/attribute_proof_smt_js/attribute_proof_smt.wasm",
    zkey: "../circuits/build/attribute_proof_smt_final.zkey",
  },
};

async function runScheme(scheme, tree) {
  console.log(`\n[${scheme}] ${T} proving trials...`);
  const rows = [];
  for (let t = 0; t < T; t++) {
    const secret = generateCredentialSecret();

    // Witness input prep is NOT timed (mirrors the spec: measure the circuit work).
    let input;
    if (scheme === "nullifier") {
      input = {
        attributeValue: ATTRIBUTE,
        threshold: THRESHOLD,
        credentialSecret: secret,
        externalNullifier: EXTERNAL_NULLIFIER,
      };
    } else {
      const w = await tree.nonMembershipWitness(secret);
      input = {
        attributeValue: ATTRIBUTE,
        threshold: THRESHOLD,
        credentialSecret: secret,
        siblings: w.siblings,
        oldKey: w.oldKey,
        oldValue: w.oldValue,
        isOld0: w.isOld0,
        root: w.root,
      };
    }

    const memBefore = process.memoryUsage().heapUsed;
    const t0 = performance.now();
    await snarkjs.groth16.fullProve(input, ARTIFACTS[scheme].wasm, ARTIFACTS[scheme].zkey);
    const timeMs = performance.now() - t0;
    const memDelta = process.memoryUsage().heapUsed - memBefore;

    rows.push([scheme, t, timeMs.toFixed(1), memDelta]);
    if ((t + 1) % 10 === 0) console.log(`  ${t + 1}/${T} done`);
  }
  return rows;
}

async function main() {
  console.log(`proof-time benchmark: T=${T} trials per scheme (Node.js ${process.version})`);
  // A tree with some existing revocations, so Scheme B witnesses are realistic.
  const tree = await RevocationTree.create();
  for (let i = 0; i < 50; i++) await tree.revoke(generateCredentialSecret());

  const rows = [];
  rows.push(...(await runScheme("nullifier", tree)));
  rows.push(...(await runScheme("merkle", tree)));

  writeCsv(
    "proof_time.csv",
    ["scheme", "trial", "time_ms", "memory_delta_bytes"],
    rows
  );

  console.log("\n--- summary (proof generation wall time) ---");
  for (const scheme of ["nullifier", "merkle"]) {
    const times = rows.filter((r) => r[0] === scheme).map((r) => Number(r[2]));
    console.log(
      `  ${scheme.padEnd(10)} mean ${mean(times).toFixed(1)} ms   std ${std(times).toFixed(1)} ms   (n=${times.length})`
    );
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error(err);
    process.exit(1);
  }
);
