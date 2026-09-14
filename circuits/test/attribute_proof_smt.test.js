/*
 * Unit tests for the Scheme B (SMT non-membership) attribute-proof circuit.
 * Covers: (a) valid proof for an unrevoked, predicate-satisfying credential succeeds;
 * (b) predicate violation fails; (c) a credential whose key IS in the revocation tree
 * cannot produce a valid non-membership witness.
 */
const chai = require("chai");
const path = require("path");
const { wasm: wasmTester } = require("circom_tester");
const { buildPoseidon, newMemEmptyTrie } = require("circomlibjs");

const assert = chai.assert;

const INCLUDE = [path.join(__dirname, "..", "..", "node_modules")];
const N_LEVELS = 64;

const SECRET = 999888777666555444n;

// Derive the SMT leaf key exactly as the circuit does: Poseidon(secret) mod 2^64.
function smtKeyOf(poseidon, F, secret) {
  return F.toObject(poseidon([secret])) % (1n << BigInt(N_LEVELS));
}

// Build circuit inputs proving non-membership of `key` in `tree`.
async function exclusionInputs(tree, key) {
  const F = tree.F;
  const res = await tree.find(key);
  assert.isFalse(res.found, "key must be absent to build a non-membership proof");
  const siblings = res.siblings.map((s) => F.toObject(s));
  while (siblings.length < N_LEVELS) siblings.push(0n); // pad below the leaf level
  return {
    siblings,
    oldKey: res.isOld0 ? 0n : F.toObject(res.notFoundKey),
    oldValue: res.isOld0 ? 0n : F.toObject(res.notFoundValue),
    isOld0: res.isOld0 ? 1n : 0n,
    root: F.toObject(tree.root),
  };
}

describe("attribute_proof_smt.circom (Scheme B — SMT non-membership)", function () {
  this.timeout(300000);

  let circuit;
  let poseidon, F;
  let tree;
  let smtKey;

  before(async () => {
    poseidon = await buildPoseidon();
    F = poseidon.F;
    smtKey = smtKeyOf(poseidon, F, SECRET);

    // Issuer-side revocation tree with a few OTHER revoked credentials.
    tree = await newMemEmptyTrie();
    for (const other of [111n, 222n, 333n]) {
      await tree.insert(smtKeyOf(poseidon, F, other), 1n);
    }

    circuit = await wasmTester(
      path.join(__dirname, "..", "attribute-proof-smt", "attribute_proof_smt.circom"),
      { include: INCLUDE }
    );
  });

  it("(a) accepts an unrevoked, predicate-satisfying credential", async () => {
    const excl = await exclusionInputs(tree, smtKey);
    const w = await circuit.calculateWitness(
      {
        attributeValue: 1000n,
        threshold: 2000n,
        credentialSecret: SECRET,
        ...excl,
      },
      true
    );
    await circuit.checkConstraints(w);
    await circuit.assertOut(w, {
      credentialCommitment: F.toObject(poseidon([SECRET])),
      smtKey,
    });
  });

  it("(b) rejects a predicate-violating input even with a valid non-membership witness", async () => {
    const excl = await exclusionInputs(tree, smtKey);
    let failed = false;
    try {
      await circuit.calculateWitness(
        {
          attributeValue: 5000n, // > threshold
          threshold: 2000n,
          credentialSecret: SECRET,
          ...excl,
        },
        true
      );
    } catch (err) {
      failed = true;
      assert.match(err.message, /Assert Failed|Error in template/i);
    }
    assert.isTrue(failed, "expected witness generation to fail");
  });

  it("(c) rejects a credential whose key IS in the revocation tree", async () => {
    // Revoke this credential: insert its key with value 1.
    await tree.insert(smtKey, 1n);

    // Any honest attempt to build exclusion inputs now fails at the JS level...
    const res = await tree.find(smtKey);
    assert.isTrue(res.found, "key should now be present");

    // ...and even a hand-crafted exclusion witness violates the circuit's
    // keysOk constraint (oldKey == key with isOld0 == 0 under fnc == 1).
    const F2 = tree.F;
    const siblings = res.siblings.map((s) => F2.toObject(s));
    while (siblings.length < N_LEVELS) siblings.push(0n);
    let failed = false;
    try {
      await circuit.calculateWitness(
        {
          attributeValue: 1000n,
          threshold: 2000n,
          credentialSecret: SECRET,
          siblings,
          oldKey: smtKey,          // the leaf at this path IS our key
          oldValue: 1n,
          isOld0: 0n,
          root: F2.toObject(tree.root),
        },
        true
      );
    } catch (err) {
      failed = true;
      assert.match(err.message, /Assert Failed|Error in template/i);
    }
    assert.isTrue(failed, "expected witness generation to fail for a revoked credential");
  });

  it("rejects a stale root after the tree changes", async () => {
    // Proof inputs were built against the pre-revocation root; the tree has since changed.
    const freshTree = await newMemEmptyTrie();
    const excl = await exclusionInputs(freshTree, smtKey); // root of a DIFFERENT tree
    let failed = false;
    try {
      await circuit.calculateWitness(
        {
          attributeValue: 1000n,
          threshold: 2000n,
          credentialSecret: SECRET,
          ...excl,
          root: F.toObject(tree.root), // claim it against the revoked tree's root
        },
        true
      );
    } catch (err) {
      failed = true;
      assert.match(err.message, /Assert Failed|Error in template/i);
    }
    assert.isTrue(failed, "expected witness generation to fail for a mismatched root");
  });
});
