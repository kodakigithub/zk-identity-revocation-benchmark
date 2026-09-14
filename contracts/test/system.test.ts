/*
 * End-to-end system tests over the in-process Hardhat network:
 *   - happy path for both schemes (real Groth16 proofs generated with snarkjs)
 *   - revoked-credential rejection (Scheme A nullifier / Scheme B stale root)
 *   - wrong-root rejection (Scheme B)
 *   - unauthorized revoke / updateRoot rejection
 * Requires `npm run build:circuits` to have produced zkeys/wasm in circuits/build/.
 */
import { ethers } from "hardhat";
import { expect } from "chai";
import * as path from "path";

// Untyped CJS modules — pulled in via require to keep the prototype test simple.
const snarkjs = require("snarkjs");
const { buildPoseidon, newMemEmptyTrie } = require("circomlibjs");

const BUILD = path.join(__dirname, "..", "..", "circuits", "build");
const WASM_NULLIFIER = path.join(BUILD, "attribute_proof_js", "attribute_proof.wasm");
const ZKEY_NULLIFIER = path.join(BUILD, "attribute_proof_final.zkey");
const WASM_SMT = path.join(BUILD, "attribute_proof_smt_js", "attribute_proof_smt.wasm");
const ZKEY_SMT = path.join(BUILD, "attribute_proof_smt_final.zkey");

const SECRET = 12345678901234567890n;
const EXT_NULLIFIER = 42n;
const N_LEVELS = 64n;

function smtKeyOf(poseidon: any, F: any, secret: bigint) {
  return F.toObject(poseidon([secret])) % (1n << N_LEVELS);
}

async function exclusionInputs(tree: any, key: bigint) {
  const F = tree.F;
  const res = await tree.find(key);
  if (res.found) throw new Error("key present; cannot build non-membership inputs");
  const siblings = res.siblings.map((s: any) => F.toObject(s));
  while (siblings.length < Number(N_LEVELS)) siblings.push(0n);
  return {
    siblings,
    oldKey: res.isOld0 ? 0n : F.toObject(res.notFoundKey),
    oldValue: res.isOld0 ? 0n : F.toObject(res.notFoundValue),
    isOld0: res.isOld0 ? 1n : 0n,
  };
}

async function fullProveToCalldata(wasm: string, zkey: string, input: any) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
  const cd = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [pA, pB, pC, pub] = JSON.parse(`[${cd}]`);
  return { pA, pB, pC, pub };
}

describe("ZK credential revocation system", function () {
  this.timeout(180000);

  let issuer: any, stranger: any;
  let poseidon: any, F: any;
  let nullifierValue: bigint;

  let didRegistry: any, nullifierRegistry: any, merkleRegistry: any;
  let accessNullifier: any, accessMerkle: any;

  before(async () => {
    [issuer, stranger] = await ethers.getSigners();
    poseidon = await buildPoseidon();
    F = poseidon.F;
    nullifierValue = F.toObject(poseidon([SECRET, EXT_NULLIFIER]));

    const deploy = async (name: string, args: any[] = []) => {
      const factory = await ethers.getContractFactory(name);
      const c = await factory.deploy(...args);
      await c.waitForDeployment();
      return c;
    };

    didRegistry = await deploy("DIDRegistry");
    nullifierRegistry = await deploy("NullifierRegistry", [issuer.address]);
    merkleRegistry = await deploy("MerkleRevocationRegistry", [issuer.address]);
    const verifierN = await deploy("Groth16VerifierNullifier");
    const verifierS = await deploy("Groth16VerifierSMT");
    accessNullifier = await deploy("AccessControlNullifier", [
      await verifierN.getAddress(),
      await nullifierRegistry.getAddress(),
    ]);
    accessMerkle = await deploy("AccessControlMerkle", [
      await verifierS.getAddress(),
      await merkleRegistry.getAddress(),
    ]);
  });

  it("DIDRegistry registers an issuer", async () => {
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:example:issuer"));
    await expect(didRegistry.connect(stranger).registerIssuer(didHash))
      .to.emit(didRegistry, "IssuerRegistered")
      .withArgs(didHash);
    expect(await didRegistry.isIssuer(didHash)).to.equal(true);
  });

  describe("Scheme A — Nullifier Registry", () => {
    let calldata: any;

    before(async () => {
      calldata = await fullProveToCalldata(WASM_NULLIFIER, ZKEY_NULLIFIER, {
        attributeValue: 1000n,
        threshold: 2000n,
        credentialSecret: SECRET,
        externalNullifier: EXT_NULLIFIER,
      });
    });

    it("accepts a valid, unrevoked proof (happy path)", async () => {
      await expect(
        accessNullifier.verifyAndCheck(calldata.pA, calldata.pB, calldata.pC, calldata.pub)
      ).to.emit(accessNullifier, "ProofAccepted");
    });

    it("rejects a cryptographically invalid proof", async () => {
      const badA = [0, 0];
      await expect(
        accessNullifier.verifyAndCheck(badA, calldata.pB, calldata.pC, calldata.pub)
      ).to.emit(accessNullifier, "ProofRejected");
    });

    it("revoke() is restricted to the issuer", async () => {
      await expect(
        nullifierRegistry.connect(stranger).revoke(nullifierValue)
      ).to.be.revertedWith("NullifierRegistry: caller is not the issuer");
    });

    it("after revocation, the same proof is rejected on-chain", async () => {
      await expect(nullifierRegistry.revoke(nullifierValue))
        .to.emit(nullifierRegistry, "NullifierRevoked")
        .withArgs(nullifierValue);
      expect(await nullifierRegistry.isRevoked(nullifierValue)).to.equal(true);
      await expect(
        accessNullifier.verifyAndCheck(calldata.pA, calldata.pB, calldata.pC, calldata.pub)
      ).to.emit(accessNullifier, "ProofRejected");
    });

    it("double revoke reverts", async () => {
      await expect(
        nullifierRegistry.revoke(nullifierValue)
      ).to.be.revertedWith("NullifierRegistry: already revoked");
    });
  });

  describe("Scheme B — Merkle (SMT) non-membership", () => {
    let tree: any;
    let smtKey: bigint;
    let cd: any;

    before(async () => {
      tree = await newMemEmptyTrie();
      smtKey = smtKeyOf(poseidon, F, SECRET);
      // Revoke two OTHER credentials so the tree is non-trivial.
      for (const other of [111n, 222n]) {
        await tree.insert(smtKeyOf(poseidon, F, other), 1n);
      }
      const root = F.toObject(tree.root);
      await merkleRegistry.updateRoot(ethers.zeroPadValue(ethers.toBeHex(root), 32));

      const excl = await exclusionInputs(tree, smtKey);
      cd = await fullProveToCalldata(WASM_SMT, ZKEY_SMT, {
        attributeValue: 1000n,
        threshold: 2000n,
        credentialSecret: SECRET,
        ...excl,
        root,
      });
    });

    it("accepts a valid proof against the current root (happy path)", async () => {
      await expect(accessMerkle.verifyAndCheck(cd.pA, cd.pB, cd.pC, cd.pub)).to.emit(
        accessMerkle,
        "ProofAccepted"
      );
    });

    it("updateRoot() is restricted to the issuer", async () => {
      const someRoot = ethers.keccak256(ethers.toUtf8Bytes("x"));
      await expect(
        merkleRegistry.connect(stranger).updateRoot(someRoot)
      ).to.be.revertedWith("MerkleRevocationRegistry: caller is not the issuer");
    });

    it("rejects a proof whose root no longer matches after revocation (wrong-root)", async () => {
      // Issuer revokes smtKey off-chain and pushes the new root.
      await tree.insert(smtKey, 1n);
      const newRoot = F.toObject(tree.root);
      await merkleRegistry.updateRoot(ethers.zeroPadValue(ethers.toBeHex(newRoot), 32));

      // Holder re-uses the OLD proof: on-chain root mismatch => rejected.
      await expect(accessMerkle.verifyAndCheck(cd.pA, cd.pB, cd.pC, cd.pub)).to.emit(
        accessMerkle,
        "ProofRejected"
      );
    });
  });
});
