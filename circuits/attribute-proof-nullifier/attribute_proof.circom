pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * Attribute proof — Scheme A (Nullifier Registry revocation).
 *
 * Proves:  attributeValue <= threshold          (shared predicate, e.g. birthdate <= 18y cutoff)
 * Binds:   proof to one issued credential via credentialCommitment = Poseidon(credentialSecret)
 * Revoke:  exposes nullifier = Poseidon(credentialSecret, externalNullifier) as a public output;
 *          the on-chain NullifierRegistry rejects proofs whose nullifier was revoked.
 *
 * Public signal order (circom 2: outputs first, then public inputs):
 *   [0] credentialCommitment
 *   [1] nullifier
 *   [2] threshold
 *   [3] externalNullifier
 */
template AttributeProofNullifier() {
    // --- private inputs ---
    signal input attributeValue;        // e.g. birth date as Unix timestamp
    signal input credentialSecret;      // credential-binding secret issued inside the (encrypted) VC

    // --- public inputs ---
    signal input threshold;             // predicate cutoff chosen by the verifier
    signal input externalNullifier;     // context/verifier binding; constant in v1

    // --- public outputs ---
    signal output credentialCommitment;
    signal output nullifier;

    // 1. Shared predicate: attributeValue <= threshold.
    //    LessEqThan(n) assumes both inputs fit in n bits; Unix timestamps fit in 64.
    component leq = LessEqThan(64);
    leq.in[0] <== attributeValue;
    leq.in[1] <== threshold;
    leq.out === 1;

    // 2. Credential commitment: binds the proof to a specific issued credential so it
    //    cannot be replayed against a different credential.
    component commitHash = Poseidon(1);
    commitHash.inputs[0] <== credentialSecret;
    credentialCommitment <== commitHash.out;

    // 3. Revocation nullifier: deterministic per (credential, context). The issuer,
    //    who generated credentialSecret at issuance time, recomputes this to revoke.
    component nullHash = Poseidon(2);
    nullHash.inputs[0] <== credentialSecret;
    nullHash.inputs[1] <== externalNullifier;
    nullifier <== nullHash.out;
}

component main {public [threshold, externalNullifier]} = AttributeProofNullifier();
