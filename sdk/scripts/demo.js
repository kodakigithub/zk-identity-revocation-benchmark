/*
 * End-to-end demo for one revocation scheme (usage: node scripts/demo.js nullifier|merkle).
 *
 * Flow: start/connect local chain -> deploy system -> register issuer -> issue credential
 * (encrypted blob to IPFS) -> holder generates ZK proof -> on-chain ACCEPT -> issuer
 * revokes -> post-revocation attempt -> on-chain REJECT.
 *
 * Target runtime: well under a minute.
 */
import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { ethers } from "ethers";
import {
  deploySystem,
  getContract,
  sendTx,
  toBytes32,
  generateIssuerKeys,
  issueCredential,
  generateProof,
  verifyProof,
  revokeCredential,
  RevocationTree,
  sha256Hex,
  stopIpfs,
} from "../dist/node.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");
const RPC_URL = process.env.LOCAL_RPC_URL || "http://127.0.0.1:8545";
// Hardhat node account #0 (public, well-known; local demo only)
const DEPLOYER_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const scheme = process.argv[2];
if (scheme !== "nullifier" && scheme !== "merkle") {
  console.error("usage: node scripts/demo.js nullifier|merkle");
  process.exit(1);
}

const ok = (msg) => console.log(`  ✔ ${msg}`);
const fail = (msg) => console.log(`  ✘ ${msg}`);

async function waitForNode(provider, timeoutMs = 30000) {
  const t0 = Date.now();
  for (;;) {
    try {
      await provider.getBlockNumber();
      return;
    } catch {
      if (Date.now() - t0 > timeoutMs) throw new Error("local node did not come up");
      await new Promise((r) => setTimeout(r, 400));
    }
  }
}

async function main() {
  const t0 = Date.now();
  console.log(`\n=== Demo: Scheme ${scheme === "nullifier" ? "A (Nullifier Registry)" : "B (SMT non-membership)"} ===\n`);

  // 1. Chain ----------------------------------------------------------------
  let nodeProc = null;
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  try {
    await provider.getBlockNumber();
    console.log(`1. Connected to existing node at ${RPC_URL}`);
  } catch {
    console.log(`1. No node at ${RPC_URL} — starting hardhat node...`);
    nodeProc = spawn("npx", ["hardhat", "node"], {
      cwd: path.join(ROOT, "contracts"),
      stdio: "ignore",
    });
    await waitForNode(provider);
    console.log("   node started");
  }
  const signer = new ethers.Wallet(DEPLOYER_KEY, provider);
  const deployer = await signer.getAddress();

  try {
    // 2. Deploy --------------------------------------------------------------
    console.log("2. Deploying contracts...");
    const addresses = await deploySystem(signer);
    ok(`system deployed (access entrypoint: ${scheme === "nullifier" ? addresses.accessNullifier : addresses.accessMerkle})`);

    // 3. Register issuer -------------------------------------------------------
    console.log("3. Registering issuer DID...");
    const issuerKeys = await generateIssuerKeys();
    const issuerDid = `did:zkcr:issuer:${issuerKeys.publicKeyHex.slice(0, 16)}`;
    const didHash = "0x" + sha256Hex(issuerDid);
    const didRegistry = getContract("DIDRegistry", addresses.didRegistry, signer);
    await sendTx(() => didRegistry.registerIssuer(didHash));
    ok(`issuer ${issuerDid} anchored`);

    // 4. Issue credential ------------------------------------------------------
    // Predicate: birthDate <= (now - 18 years). Holder born 2000-01-01 => always passes.
    console.log("4. Issuing credential (birthDate=2000-01-01, proving age >= 18)...");
    const attributeValue = 946684800n; // 2000-01-01T00:00:00Z
    const threshold = BigInt(Math.floor(Date.now() / 1000) - Math.floor(18 * 365.25 * 86400));
    const tree = scheme === "merkle" ? await RevocationTree.create() : undefined;

    const issued = await issueCredential(issuerKeys, {
      attributeValue,
      birthDate: "2000-01-01",
      holderId: "did:zkcr:holder:alice",
    });
    ok(`credential issued; encrypted blob at ipfs://${issued.ipfsCid}`);
    ok(`commitment=${issued.commitment.slice(0, 20)}... nullifier/smtKey=${issued.nullifier.slice(0, 16)}...`);

    // Scheme B: the issuer's (empty) revocation tree root must be on-chain first.
    if (scheme === "merkle") {
      const registry = getContract("MerkleRevocationRegistry", addresses.merkleRegistry, signer);
      const root0 = await tree.root();
      await sendTx(() => registry.updateRoot(toBytes32(root0)));
      ok(`initial empty-tree root published`);
    }

    // 5. Holder generates proof ------------------------------------------------
    console.log("5. Holder generating ZK proof...");
    const tp0 = performance.now();
    const bundle = await generateProof(scheme, {
      credentialSecret: BigInt(issued.credentialSecret),
      attributeValue,
      threshold,
      revocationTree: tree,
    });
    ok(`proof generated in ${(performance.now() - tp0).toFixed(0)} ms`);

    // 6. Verify (pre-revocation) ------------------------------------------------
    console.log("6. Verifying on-chain (expect ACCEPT)...");
    const accessAddress =
      scheme === "nullifier" ? addresses.accessNullifier : addresses.accessMerkle;
    const before = await verifyProof(bundle, { accessAddress, signer });
    if (!before.onChain?.accepted) throw new Error(`expected accept, got ${before.onChain?.event}`);
    ok(`ACCEPTED on-chain (tx ${before.onChain.txHash.slice(0, 14)}..., gas ${before.onChain.gasUsed})`);

    // 7. Revoke -----------------------------------------------------------------
    console.log("7. Issuer revoking the credential...");
    const rev = await revokeCredential(scheme, {
      credentialSecret: BigInt(issued.credentialSecret),
      issuerSigner: signer,
      nullifierRegistryAddress: addresses.nullifierRegistry,
      merkleRegistryAddress: addresses.merkleRegistry,
      revocationTree: tree,
    });
    ok(`revoked (tx ${rev.txHash.slice(0, 14)}..., gas ${rev.gasUsed})${rev.newRoot ? ` new root ${rev.newRoot.slice(0, 18)}...` : ""}`);

    // 8. Post-revocation attempts ------------------------------------------------
    console.log("8. Post-revocation attempts (expect REJECT)...");
    if (scheme === "nullifier") {
      // Holder can still produce a valid proof — the REGISTRY rejects it.
      const bundle2 = await generateProof(scheme, {
        credentialSecret: BigInt(issued.credentialSecret),
        attributeValue,
        threshold,
      });
      const after = await verifyProof(bundle2, { accessAddress, signer });
      if (after.onChain?.accepted) throw new Error("revoked credential was accepted!");
      ok(`REJECTED on-chain (${after.onChain?.event}: "${after.onChain?.reason}")`);
    } else {
      // (a) Fresh proof against the new root: impossible at the circuit level.
      let circuitFailed = false;
      try {
        await generateProof(scheme, {
          credentialSecret: BigInt(issued.credentialSecret),
          attributeValue,
          threshold,
          revocationTree: tree,
        });
      } catch {
        circuitFailed = true;
      }
      if (!circuitFailed) throw new Error("revoked credential produced a fresh proof!");
      ok("fresh non-membership proof impossible (credential is in the revocation tree)");
      // (b) Replaying the stale proof: rejected on-chain (root mismatch).
      const after = await verifyProof(bundle, { accessAddress, signer });
      if (after.onChain?.accepted) throw new Error("stale proof was accepted!");
      ok(`stale proof REJECTED on-chain (${after.onChain?.event}: "${after.onChain?.reason}")`);
    }

    console.log(`\nDemo PASSED for scheme "${scheme}" in ${((Date.now() - t0) / 1000).toFixed(1)}s\n`);
  } finally {
    await stopIpfs();
    if (nodeProc) nodeProc.kill();
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    fail(err.message || String(err));
    process.exit(1);
  }
);
