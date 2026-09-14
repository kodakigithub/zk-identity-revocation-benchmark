/*
 * snarkjs and circomlibjs are CJS packages. Namespace imports work uniformly in
 * Node ESM (via CJS named-export detection) and in the browser (vite pre-bundles
 * CJS into an equivalent ESM namespace) — one code path for both environments.
 */
import * as snarkjsNs from "snarkjs";
import * as circomlibjs from "circomlibjs";

export const snarkjs: any = snarkjsNs;
export const buildPoseidon: () => Promise<any> = circomlibjs.buildPoseidon;
export const newMemEmptyTrie: () => Promise<any> = circomlibjs.newMemEmptyTrie;
