pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/smt/smtverifier.circom";

/*
 * Attribute proof — Scheme B (Sparse Merkle Tree non-membership revocation).
 *
 * Proves:  attributeValue <= threshold          (shared predicate, identical to Scheme A)
 * Binds:   proof to one issued credential via credentialCommitment = Poseidon(credentialSecret)
 * Revoke:  proves the leaf at key = Poseidon(credentialSecret) mod 2^nLevels is ABSENT from
 *          the issuer's revocation SMT (revoked leaves map to 1). Uses SMTVerifier in
 *          exclusion mode (fnc = 1) against the public root.
 *
 * The SMT path uses only the low nLevels bits of the key (SMTVerifier decomposes the key
 * with Num2Bits_strict and walks bits 0..nLevels-1), so the full Poseidon output is reduced
 * mod 2^nLevels in-circuit; the issuer's off-chain tree applies the same reduction.
 *
 * Public signal order (circom 2: outputs first, then public inputs):
 *   [0] credentialCommitment
 *   [1] smtKey
 *   [2] threshold
 *   [3] root
 */
template AttributeProofSMT(nLevels) {
    // --- private inputs ---
    signal input attributeValue;
    signal input credentialSecret;

    // --- public inputs ---
    signal input threshold;
    signal input root;                      // must equal MerkleRevocationRegistry.currentRoot

    // --- private SMT non-membership witness (from the issuer's off-chain tree) ---
    signal input siblings[nLevels];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;

    // --- public outputs ---
    signal output credentialCommitment;
    signal output smtKey;

    // 1. Shared predicate: attributeValue <= threshold (identical to Scheme A).
    component leq = LessEqThan(64);
    leq.in[0] <== attributeValue;
    leq.in[1] <== threshold;
    leq.out === 1;

    // 2. Credential commitment (identical to Scheme A).
    component commitHash = Poseidon(1);
    commitHash.inputs[0] <== credentialSecret;
    credentialCommitment <== commitHash.out;

    // 3. Leaf key derivation: smtKey = Poseidon(credentialSecret) mod 2^nLevels.
    //    Poseidon output < p < 2^254, so a 254-bit decomposition is sound and we
    //    simply recompose the low nLevels bits.
    component keyHash = Poseidon(1);
    keyHash.inputs[0] <== credentialSecret;

    component keyBits = Num2Bits(254);
    keyBits.in <== keyHash.out;

    component keyReduce = Bits2Num(nLevels);
    for (var i = 0; i < nLevels; i++) {
        keyReduce.in[i] <== keyBits.out[i];
    }
    smtKey <== keyReduce.out;

    // 4. Non-membership proof: the leaf at smtKey is not in the revocation tree.
    //    fnc = 1 (exclusion): circuit enforces oldKey != smtKey when isOld0 = 0.
    component smt = SMTVerifier(nLevels);
    smt.enabled <== 1;
    smt.fnc <== 1;
    smt.root <== root;
    for (var i = 0; i < nLevels; i++) {
        smt.siblings[i] <== siblings[i];
    }
    smt.oldKey <== oldKey;
    smt.oldValue <== oldValue;
    smt.isOld0 <== isOld0;
    smt.key <== smtKey;
    smt.value <== 0;
}

component main {public [threshold, root]} = AttributeProofSMT(64);
