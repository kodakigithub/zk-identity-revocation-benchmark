/*
 * Poseidon helpers mirroring exactly what the circuits compute.
 * Keep these in sync with the circuits under circuits/attribute-proof-*.
 */
import { buildPoseidon } from "./deps.js";

/** Fixed context nullifier for v1 (spec: a constant is fine). */
export const EXTERNAL_NULLIFIER = 42n;
/** SMT depth — must match AttributeProofSMT(64) in the circuit. */
export const SMT_LEVELS = 64n;

let _poseidon: any = null;

export async function getPoseidon(): Promise<any> {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}

export async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const p = await getPoseidon();
  return p.F.toObject(p(inputs));
}

/** credentialCommitment = Poseidon(credentialSecret) */
export async function computeCommitment(credentialSecret: bigint): Promise<bigint> {
  return poseidonHash([credentialSecret]);
}

/** nullifier = Poseidon(credentialSecret, externalNullifier) */
export async function computeNullifier(
  credentialSecret: bigint,
  externalNullifier: bigint = EXTERNAL_NULLIFIER
): Promise<bigint> {
  return poseidonHash([credentialSecret, externalNullifier]);
}

/** smtKey = Poseidon(credentialSecret) mod 2^64 (in-circuit reduction matched off-chain) */
export async function computeSmtKey(credentialSecret: bigint): Promise<bigint> {
  return (await poseidonHash([credentialSecret])) % (1n << SMT_LEVELS);
}
