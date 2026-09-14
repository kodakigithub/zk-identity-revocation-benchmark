/*
 * Unit tests for the Scheme A (nullifier) attribute-proof circuit.
 * Covers: (a) valid unrevoked-style proof inputs succeed, (b) predicate violation fails,
 * plus output-correctness checks for the commitment and nullifier.
 */
const chai = require("chai");
const path = require("path");
const { wasm: wasmTester } = require("circom_tester");
const { buildPoseidon } = require("circomlibjs");

const assert = chai.assert;

// circomlib is hoisted to the workspace root node_modules
const INCLUDE = [path.join(__dirname, "..", "..", "node_modules")];

const SECRET = 12345678901234567890n;
const EXT_NULLIFIER = 42n; // constant context for v1

describe("attribute_proof.circom (Scheme A — nullifier)", function () {
  this.timeout(120000);

  let circuit;
  let poseidon, F;

  before(async () => {
    poseidon = await buildPoseidon();
    F = poseidon.F;
    circuit = await wasmTester(
      path.join(__dirname, "..", "attribute-proof-nullifier", "attribute_proof.circom"),
      { include: INCLUDE }
    );
  });

  it("(a) accepts a predicate-satisfying credential and exposes correct outputs", async () => {
    const w = await circuit.calculateWitness(
      {
        attributeValue: 1000n, // "birth timestamp"
        threshold: 2000n,      // "18-years-ago cutoff" — 1000 <= 2000 holds
        credentialSecret: SECRET,
        externalNullifier: EXT_NULLIFIER,
      },
      true
    );
    await circuit.checkConstraints(w);
    await circuit.assertOut(w, {
      credentialCommitment: F.toObject(poseidon([SECRET])),
      nullifier: F.toObject(poseidon([SECRET, EXT_NULLIFIER])),
    });
  });

  it("accepts the boundary case attributeValue == threshold", async () => {
    const w = await circuit.calculateWitness(
      {
        attributeValue: 2000n,
        threshold: 2000n,
        credentialSecret: SECRET,
        externalNullifier: EXT_NULLIFIER,
      },
      true
    );
    await circuit.checkConstraints(w);
  });

  it("(b) rejects a predicate-violating input (attributeValue > threshold)", async () => {
    let failed = false;
    try {
      await circuit.calculateWitness(
        {
          attributeValue: 2001n,
          threshold: 2000n,
          credentialSecret: SECRET,
          externalNullifier: EXT_NULLIFIER,
        },
        true
      );
    } catch (err) {
      failed = true;
      assert.match(err.message, /Assert Failed|Error in template/i);
    }
    assert.isTrue(failed, "expected witness generation to fail");
  });

  it("produces a different nullifier for a different externalNullifier (context binding)", async () => {
    const OTHER_CTX = 77n;
    const w = await circuit.calculateWitness(
      {
        attributeValue: 1000n,
        threshold: 2000n,
        credentialSecret: SECRET,
        externalNullifier: OTHER_CTX,
      },
      true
    );
    await circuit.assertOut(w, {
      nullifier: F.toObject(poseidon([SECRET, OTHER_CTX])),
    });
  });
});
