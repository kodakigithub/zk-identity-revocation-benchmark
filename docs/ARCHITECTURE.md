# Architecture

## System overview

```
ISSUER                                   HOLDER                                VERIFIER
────────────────────────────────────────────────────────────────────────────────────────
Ed25519 key ──signs──▶ W3C VC ──▶ AES-GCM ──▶ IPFS (helia)
     │
     │ creates credentialSecret ────────▶ in-circuit private input
     │ (delivered inside the encrypted holder payload)
     │
     │ revocation handles (computable by issuer):
     │   Scheme A: nullifier = Poseidon(secret, 42)
     │   Scheme B: smtKey   = Poseidon(secret) mod 2^64
     │
     ▼
 registers didHash on DIDRegistry        holder builds proof bundle ──▶ ┌─────────────────┐
                                                                       │ Groth16 verifier │
     ┌───────────────────────────────────────────────────────────────▶└─────────────────┘
     │                                                                         │
     │                          revocation check: A: NullifierRegistry.isRevoked
     │                                          B: proven root == MerkleRevocation
     │                                             Registry.currentRoot
     ▼
 AccessControl{Nullifier,Merkle}.verifyAndCheck
       emits exactly one ProofAccepted / ProofRejected event
```

The two schemes share **everything** except the revocation-proof portion: same VC
format, same predicate (`LessEqThan(64)`), same credential commitment
(`Poseidon(credentialSecret)`), same `verifyAndCheck` interface.

## Circuits (public signal layout — identical length 4 for both schemes)

Outputs first, then public inputs (circom 2 ordering):

| index | Scheme A (`attribute_proof.circom`) | Scheme B (`attribute_proof_smt.circom`) |
| ----- | ----------------------------------- | --------------------------------------- |
| 0     | `credentialCommitment`              | `credentialCommitment`                  |
| 1     | `nullifier`                         | `smtKey`                                 |
| 2     | `threshold`                         | `threshold`                              |
| 3     | `externalNullifier`                 | `root`                                   |

Constraint counts: **A ≈ 1.0k** / **B ≈ 37.6k** (a 2^16 powers-of-tau covers both).

## Contracts

| Contract                        | Role                                          | Storage            |
| ------------------------------- | --------------------------------------------- | ------------------ |
| `DIDRegistry`                   | issuer DID anchor (permissionless in proto)   | per-issuer slot    |
| `NullifierRegistry`             | Scheme A revocation state                     | 1 slot / revoked   |
| `MerkleRevocationRegistry`      | Scheme B current root only                    | 1 slot total       |
| `Groth16VerifierNullifier/SMT`  | snarkjs-generated, do not hand-edit           | —                  |
| `AccessControlNullifier/Merkle` | identical `verifyAndCheck` entrypoints        | —                  |

`verifyAndCheck`: (1) call the matching verifier, (2) check revocation
(A: `!isRevoked(pubSignals[1])`; B: `pubSignals[3] == currentRoot()`), (3) emit
exactly one `ProofAccepted` / `ProofRejected` event.

## SDK module map

Browser-safe barrel (`@zkcr/sdk`): `types, crypto (vc sign/verify, AES-GCM),
poseidon, storage (helia), revocationTree, abis, contracts (getContract/sendTx),
issueCredential, generateProof, verify, revokeCredential`.

Node entry (`@zkcr/sdk/node`): adds `deploySystem, loadArtifact, loadDeployment,
loadVerificationKey` (`fs`-bound; used by demos/benchmarks).

## Trust model & what each party learns

- **Verifier** learns only the predicate bit and the public nullifier/smtKey.
- **Issuer** knows `credentialSecret` by construction (prototype simplification).
- **Holder** reveals nothing about `attributeValue`; the commitment binding prevents
  proof replay with another credential.
- Revocation is unlinkable across contexts in principle (externalNullifier), but v1
  uses a fixed context constant as permitted by the spec.
