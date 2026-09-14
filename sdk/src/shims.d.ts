// Minimal shims for untyped CJS dependencies (research prototype).
declare module "snarkjs" {
  const snarkjs: any;
  export default snarkjs;
}

declare module "circomlibjs" {
  export function buildPoseidon(): Promise<any>;
  export function newMemEmptyTrie(): Promise<any>;
}
