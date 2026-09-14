/*
 * Filesystem layout constants. Uses only `path` (polyfillable) — no `fs` — so this
 * module is safe to import in the browser. In the browser, fileURLToPath throws
 * (import.meta.url is http(s)); we catch that and the constants simply go unused
 * (apps always pass explicit artifact URLs).
 */
import * as path from "path";
import { fileURLToPath } from "url";

function detectRoot(): string {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    // sdk/dist -> repo root
    return path.resolve(here, "..", "..");
  } catch {
    return "/"; // browser environment
  }
}

export const ROOT = detectRoot();
export const CONTRACTS_DIR = path.join(ROOT, "contracts");
export const ARTIFACTS_DIR = path.join(CONTRACTS_DIR, "artifacts", "contracts");
export const CIRCUITS_BUILD = path.join(ROOT, "circuits", "build");
export const DEPLOYMENTS_DIR = path.join(CONTRACTS_DIR, "deployments");
