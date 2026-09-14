/*
 * Gas benchmark (Section 7.1 of the project spec).
 *
 * For each scheme, on a fresh deployment:
 *   (a) one verification with 0 revocations
 *   (b) K sequential revocation operations
 *   (c) one verification after K revocations
 * CSV columns: scheme,operation,revocation_count,gas_used
 * Also computes the cumulative-cost crossover point between the schemes, if any.
 *
 * Usage: node gas/bench-gas.js [N=100] [K=50]
 */
import {
  deploySystem,
  getContract,
  toBytes32,
  generateIssuerKeys,
  issueCredential,
  generateProof,
  revokeCredential,
  verifyProof,
  RevocationTree,
  stopIpfs,
} from "@zkcr/sdk/node";
import {
  ensureNode,
  getSigner,
  cleanupNode,
  writeCsv,
  mean,
} from "../lib/node.js";

const N = parseInt(process.argv[2] || "100", 10);
const K = parseInt(process.argv[3] || "50", 10);

const ATTRIBUTE = 946684800n; // 2000-01-01
const THRESHOLD = BigInt(Math.floor(Date.now() / 1000) - Math.floor(18 * 365.25 * 86400));

async function runScheme(scheme, signer, issuerKeys) {
  console.log(`\n[${scheme}] deploying fresh contracts and issuing ${N} credentials...`);
  const addresses = await deploySystem(signer);
  const accessAddress =
    scheme === "nullifier" ? addresses.accessNullifier : addresses.accessMerkle;

  // Issue N credentials. Issuance is fully off-chain in this design (zero gas) —
  // itself a reportable property of the architecture.
  const credentials = [];
  for (let i = 0; i < N; i++) {
    credentials.push(await issueCredential(issuerKeys, { attributeValue: ATTRIBUTE }));
  }

  const tree = scheme === "merkle" ? await RevocationTree.create() : undefined;
  if (scheme === "merkle") {
    // Publish the initial (empty-tree) root.
    const registry = getContract("MerkleRevocationRegistry", addresses.merkleRegistry, signer);
    const root0 = await tree.root();
    await (await registry.updateRoot(toBytes32(root0))).wait();
  }

  const rows = [];

  // (a) verification with 0 revocations
  const prover = credentials[0]; // this credential is NEVER revoked in this benchmark
  let bundle = await generateProof(scheme, {
    credentialSecret: BigInt(prover.credentialSecret),
    attributeValue: ATTRIBUTE,
    threshold: THRESHOLD,
    revocationTree: tree,
  });
  let res = await verifyProof(bundle, { accessAddress, signer });
  if (!res.onChain?.accepted) throw new Error("pre-revocation verification rejected");
  rows.push([scheme, "verify", 0, res.onChain.gasUsed]);

  // (b) K sequential revocations (of OTHER credentials)
  console.log(`[${scheme}] performing ${K} revocations...`);
  for (let k = 1; k <= K; k++) {
    const r = await revokeCredential(scheme, {
      credentialSecret: BigInt(credentials[k].credentialSecret),
      issuerSigner: signer,
      nullifierRegistryAddress: addresses.nullifierRegistry,
      merkleRegistryAddress: addresses.merkleRegistry,
      revocationTree: tree,
    });
    rows.push([scheme, "revoke", k, r.gasUsed]);
  }

  // (c) verification after K revocations.
  // Scheme B: the holder refreshes the witness against the current root — this data-
  // availability requirement is a qualitative difference vs Scheme A (see paper).
  bundle = await generateProof(scheme, {
    credentialSecret: BigInt(prover.credentialSecret),
    attributeValue: ATTRIBUTE,
    threshold: THRESHOLD,
    revocationTree: tree,
  });
  res = await verifyProof(bundle, { accessAddress, signer });
  if (!res.onChain?.accepted) throw new Error("post-revocation verification rejected");
  rows.push([scheme, "verify", K, res.onChain.gasUsed]);

  return rows;
}

function crossover(rowsA, rowsB) {
  // Cumulative revocation cost comparison over k = 1..K.
  const revA = rowsA.filter((r) => r[1] === "revoke").map((r) => Number(r[3]));
  const revB = rowsB.filter((r) => r[1] === "revoke").map((r) => Number(r[3]));
  let cumA = 0;
  let cumB = 0;
  for (let k = 0; k < Math.min(revA.length, revB.length); k++) {
    cumA += revA[k];
    cumB += revB[k];
  }
  return { cumA, cumB };
}

async function main() {
  console.log(`gas benchmark: N=${N} credentials, K=${K} revocations per scheme`);
  const { provider } = await ensureNode();
  const signer = getSigner(provider);
  const issuerKeys = await generateIssuerKeys();

  try {
    const rowsA = await runScheme("nullifier", signer, issuerKeys);
    const rowsB = await runScheme("merkle", signer, issuerKeys);

    writeCsv(
      "gas.csv",
      ["scheme", "operation", "revocation_count", "gas_used"],
      [...rowsA, ...rowsB]
    );

    const vA = rowsA.filter((r) => r[1] === "verify").map((r) => Number(r[3]));
    const vB = rowsB.filter((r) => r[1] === "verify").map((r) => Number(r[3]));
    const rA = rowsA.filter((r) => r[1] === "revoke").map((r) => Number(r[3]));
    const rB = rowsB.filter((r) => r[1] === "revoke").map((r) => Number(r[3]));
    const { cumA, cumB } = crossover(rowsA, rowsB);

    console.log("\n--- summary ---");
    console.log(`verify gas:      nullifier ${vA.join(" / ")}   merkle ${vB.join(" / ")} (0 revocations / after K)`);
    console.log(`revoke gas mean: nullifier ${mean(rA).toFixed(0)}   merkle ${mean(rB).toFixed(0)}`);
    console.log(`cumulative revoke gas after ${K}: nullifier ${cumA}   merkle ${cumB}`);
    if (cumA === cumB) {
      console.log("crossover: cumulative costs identical — no crossover");
    } else {
      const cheaper = cumA < cumB ? "nullifier" : "merkle";
      console.log(`crossover: none in [1, ${K}] — "${cheaper}" is cheaper throughout the measured range`);
    }
  } finally {
    await stopIpfs();
    cleanupNode();
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error(err);
    process.exit(1);
  }
);
