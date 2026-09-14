/*
 * On-chain storage growth benchmark (Section 7.4).
 *
 * Grows the revoked set from 0 to K for both schemes and measures actual on-chain
 * storage occupation via eth_getStorageAt:
 *   - Scheme A: probes each revoked nullifier's mapping slot (keccak256(key . 0))
 *     and counts non-zero slots  -> expected LINEAR growth.
 *   - Scheme B: probes the single currentRoot slot of the registry -> expected FLAT.
 * Cumulative revocation gas is recorded as a secondary proxy column.
 *
 * CSV columns: scheme,revocation_count,storage_slots_used,cumulative_gas
 *
 * Usage: node storage/bench-storage.js [K=50]
 */
import { ethers } from "ethers";
import {
  deploySystem,
  generateIssuerKeys,
  issueCredential,
  revokeCredential,
  RevocationTree,
  computeNullifier,
  stopIpfs,
} from "@zkcr/sdk/node";
import { ensureNode, getSigner, cleanupNode, writeCsv } from "../lib/node.js";

const K = parseInt(process.argv[2] || "50", 10);
const ATTRIBUTE = 946684800n;

/** Storage slot of `nullifier` in NullifierRegistry's mapping at slot 0. */
function mappingSlot(nullifier) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [nullifier, 0])
  );
}

async function countNonZeroSlots(provider, address, slots) {
  let n = 0;
  for (const s of slots) {
    const v = await provider.getStorage(address, s);
    if (v !== ethers.ZeroHash) n++;
  }
  return n;
}

async function runScheme(scheme, provider, signer, issuerKeys) {
  console.log(`\n[${scheme}] growing revoked set 0..${K}...`);
  const addresses = await deploySystem(signer);
  const registryAddress =
    scheme === "nullifier" ? addresses.nullifierRegistry : addresses.merkleRegistry;

  const credentials = [];
  for (let i = 0; i <= K; i++) {
    credentials.push(await issueCredential(issuerKeys, { attributeValue: ATTRIBUTE }));
  }
  const tree = scheme === "merkle" ? await RevocationTree.create() : undefined;

  const rows = [];
  let cumulativeGas = 0;
  for (let k = 0; k <= K; k++) {
    if (k > 0) {
      const r = await revokeCredential(scheme, {
        credentialSecret: BigInt(credentials[k - 1].credentialSecret),
        issuerSigner: signer,
        nullifierRegistryAddress: addresses.nullifierRegistry,
        merkleRegistryAddress: addresses.merkleRegistry,
        revocationTree: tree,
      });
      cumulativeGas += Number(r.gasUsed);
    }

    let slotsUsed;
    if (scheme === "nullifier") {
      const slots = [];
      for (let i = 0; i < k; i++) {
        slots.push(mappingSlot(await computeNullifier(BigInt(credentials[i].credentialSecret))));
      }
      slotsUsed = await countNonZeroSlots(provider, registryAddress, slots);
    } else {
      // MerkleRevocationRegistry: `currentRoot` is the only storage variable (slot 0;
      // `issuer` is immutable => not in storage). Empty-tree root is 0 => 0 slots used.
      slotsUsed = await countNonZeroSlots(provider, registryAddress, [0]);
    }
    rows.push([scheme, k, slotsUsed, cumulativeGas]);
  }
  return rows;
}

async function main() {
  console.log(`storage benchmark: K=${K} revocations per scheme`);
  const { provider } = await ensureNode();
  const signer = getSigner(provider);
  const issuerKeys = await generateIssuerKeys();

  try {
    const rowsA = await runScheme("nullifier", provider, signer, issuerKeys);
    const rowsB = await runScheme("merkle", provider, signer, issuerKeys);

    writeCsv(
      "storage.csv",
      ["scheme", "revocation_count", "storage_slots_used", "cumulative_gas"],
      [...rowsA, ...rowsB]
    );

    console.log("\n--- summary ---");
    console.log(
      `nullifier: slots at 0 / ${K} revocations = ${rowsA[0][2]} / ${rowsA[K][2]}  (expected linear)`
    );
    console.log(
      `merkle:    slots at 0 / ${K} revocations = ${rowsB[0][2]} / ${rowsB[K][2]}  (expected flat)`
    );
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
