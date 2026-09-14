/*
 * Issuer-side sparse Merkle revocation tree (Scheme B).
 * Wraps circomlibjs's SMT, which is hash-compatible with the circuit's
 * SMTVerifier (Poseidon leaf H(key, value, 1), internal H(L, R)).
 * Revoked credential => leaf key smtKey mapped to value 1; absence => not revoked.
 */
import { newMemEmptyTrie } from "./deps.js";
import { computeSmtKey, SMT_LEVELS } from "./poseidon.js";

export interface NonMembershipWitness {
  siblings: bigint[];
  oldKey: bigint;
  oldValue: bigint;
  isOld0: bigint;
  root: bigint;
}

export class RevocationTree {
  private constructor(private tree: any) {}

  static async create(): Promise<RevocationTree> {
    return new RevocationTree(await newMemEmptyTrie());
  }

  /** Rebuild a tree from a list of revoked secrets (simple prototype persistence). */
  static async fromRevokedSecrets(secrets: bigint[]): Promise<RevocationTree> {
    const t = await RevocationTree.create();
    for (const s of secrets) await t.revoke(s);
    return t;
  }

  /**
   * Rebuild a tree from public revoked smtKeys — this is the HOLDER's view:
   * the issuer publishes revoked leaf keys (not secrets) and holders reconstruct
   * the same tree to compute their non-membership witnesses.
   */
  static async fromRevokedKeys(keys: bigint[]): Promise<RevocationTree> {
    const t = await RevocationTree.create();
    for (const k of keys) await t.insertKey(k);
    return t;
  }

  /** Insert an already-derived leaf key. Returns the new root. */
  async insertKey(smtKey: bigint): Promise<bigint> {
    await this.tree.insert(smtKey, 1n);
    return this.root();
  }

  get F(): any {
    return this.tree.F;
  }

  async root(): Promise<bigint> {
    return this.tree.F.toObject(this.tree.root);
  }

  /** Insert smtKey -> 1. Returns the new root. */
  async revoke(credentialSecret: bigint): Promise<bigint> {
    const key = await computeSmtKey(credentialSecret);
    await this.tree.insert(key, 1n);
    return this.root();
  }

  async isRevoked(credentialSecret: bigint): Promise<boolean> {
    const key = await computeSmtKey(credentialSecret);
    const res = await this.tree.find(key);
    return !!res.found;
  }

  /** Non-membership witness for the circuit. Throws if the credential is revoked. */
  async nonMembershipWitness(credentialSecret: bigint): Promise<NonMembershipWitness> {
    const key = await computeSmtKey(credentialSecret);
    const res = await this.tree.find(key);
    if (res.found) {
      throw new Error(
        "credential is revoked: no non-membership witness exists (circuit would reject it)"
      );
    }
    const F = this.tree.F;
    const siblings: bigint[] = res.siblings.map((s: any) => F.toObject(s));
    while (siblings.length < Number(SMT_LEVELS)) siblings.push(0n);
    return {
      siblings,
      oldKey: res.isOld0 ? 0n : F.toObject(res.notFoundKey),
      oldValue: res.isOld0 ? 0n : F.toObject(res.notFoundValue),
      isOld0: res.isOld0 ? 1n : 0n,
      root: await this.root(),
    };
  }
}
