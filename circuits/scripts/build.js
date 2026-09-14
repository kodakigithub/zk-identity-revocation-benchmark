/*
 * Circuit build pipeline (research prototype — deterministic where practical).
 *
 * For each circuit variant:
 *   1. compile with the project-local circom binary (../tools/bin/circom)
 *   2. create a local powers-of-tau (bn128, 2^16) with FIXED entropy — no external
 *      ceremony download; regenerated identically on any machine (ptau contribution
 *      uses fixed entropy; zkey contributions likewise)
 *   3. groth16 setup + fixed-entropy contribution -> final zkey + verification key
 *   4. export the Solidity verifier into contracts/verifiers/ (contract renamed so
 *      both variants can coexist)
 *   5. copy browser artifacts (.wasm/.zkey) into apps/holder-wallet/public/circuits/
 *      for the on-device benchmark page
 *
 * Usage: npm run build -w @zkcr/circuits
 */
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const CIRCUITS_DIR = path.resolve(__dirname, "..");
const ROOT_DIR = path.resolve(CIRCUITS_DIR, "..");
const BUILD_DIR = path.join(CIRCUITS_DIR, "build");
const CIRCOM = path.join(ROOT_DIR, "tools", "bin", "circom");
const NODE_MODULES = path.join(ROOT_DIR, "node_modules");
// Hardhat compiles everything under paths.sources ("contracts/"), so generated
// verifiers must live in contracts/contracts/verifiers/.
const VERIFIERS_OUT = path.join(ROOT_DIR, "contracts", "contracts", "verifiers");
const WALLET_PUBLIC = path.join(ROOT_DIR, "apps", "holder-wallet", "public", "circuits");

// 2^16 fits the largest circuit (~37.6k constraints for the SMT variant).
const PTAU_POWER = 16;
// Fixed entropy => reproducible ceremony. NOT secure for production; fine for research.
const ENTROPY_PTAU = "zkcr-ptau-fixed-entropy-v1";
const ENTROPY_ZKEY = "zkcr-zkey-fixed-entropy-v1";

const VARIANTS = [
  {
    name: "attribute_proof",
    file: path.join(CIRCUITS_DIR, "attribute-proof-nullifier", "attribute_proof.circom"),
    verifierName: "Groth16VerifierNullifier",
    browserTag: "nullifier",
  },
  {
    name: "attribute_proof_smt",
    file: path.join(CIRCUITS_DIR, "attribute-proof-smt", "attribute_proof_smt.circom"),
    verifierName: "Groth16VerifierSMT",
    browserTag: "smt",
  },
];

function sh(file, args) {
  console.log(`  $ ${path.basename(file)} ${args.join(" ")}`);
  return execFileSync(file, args, { stdio: ["ignore", "pipe", "inherit"] }).toString();
}

async function ensurePtau(logger) {
  const ptau0 = path.join(BUILD_DIR, `pot${PTAU_POWER}_0.ptau`);
  const ptau1 = path.join(BUILD_DIR, `pot${PTAU_POWER}_1.ptau`);
  const ptauFinal = path.join(BUILD_DIR, `pot${PTAU_POWER}_final.ptau`);
  if (fs.existsSync(ptauFinal)) {
    console.log(`powers-of-tau: reusing cached ${path.basename(ptauFinal)}`);
    return ptauFinal;
  }
  console.log(`powers-of-tau: generating bn128 2^${PTAU_POWER} locally (one-time, fixed entropy)...`);
  const curve = await snarkjs.curves.getCurveFromName("bn128");
  await snarkjs.powersOfTau.newAccumulator(curve, PTAU_POWER, ptau0, logger);
  await snarkjs.powersOfTau.contribute(ptau0, ptau1, "zkcr-fixed", ENTROPY_PTAU, logger);
  await snarkjs.powersOfTau.preparePhase2(ptau1, ptauFinal, logger);
  await curve.terminate();
  return ptauFinal;
}

async function main() {
  fs.mkdirSync(BUILD_DIR, { recursive: true });
  fs.mkdirSync(VERIFIERS_OUT, { recursive: true });
  fs.mkdirSync(WALLET_PUBLIC, { recursive: true });

  const logger = null; // set to console for verbose snarkjs logs

  // 1. Compile circuits
  for (const v of VARIANTS) {
    console.log(`\n[compile] ${v.name}`);
    const out = sh(CIRCOM, [
      v.file, "-l", NODE_MODULES, "--r1cs", "--wasm", "--sym", "-o", BUILD_DIR,
    ]);
    const m = out.match(/non-linear constraints: (\d+)/);
    if (m) console.log(`  non-linear constraints: ${m[1]}`);
  }

  // 2. Powers of tau (shared by both circuits)
  const ptauFinal = await ensurePtau(logger);

  // ejs template for the Solidity verifier, loaded the same way the snarkjs CLI does.
  const templatesDir = path.join(path.dirname(require.resolve("snarkjs")), "..", "templates");
  const templates = {
    groth16: fs.readFileSync(path.join(templatesDir, "verifier_groth16.sol.ejs"), "utf8"),
  };

  // 3-5. Per-circuit setup, keys, verifiers, browser artifacts
  for (const v of VARIANTS) {
    console.log(`\n[setup] ${v.name}`);
    const r1cs = path.join(BUILD_DIR, `${v.name}.r1cs`);
    const zkey0 = path.join(BUILD_DIR, `${v.name}_0.zkey`);
    const zkeyFinal = path.join(BUILD_DIR, `${v.name}_final.zkey`);
    const vkeyPath = path.join(BUILD_DIR, `${v.name}_verification_key.json`);

    await snarkjs.zKey.newZKey(r1cs, ptauFinal, zkey0, logger);
    await snarkjs.zKey.contribute(zkey0, zkeyFinal, "zkcr-fixed", ENTROPY_ZKEY, logger);

    const vkey = await snarkjs.zKey.exportVerificationKey(zkeyFinal, logger);
    fs.writeFileSync(vkeyPath, JSON.stringify(vkey, null, 2));
    console.log(`  public signals: ${vkey.nPublic}`);

    // 4. Solidity verifier (renamed so both variants coexist in contracts/verifiers/)
    let sol = await snarkjs.zKey.exportSolidityVerifier(zkeyFinal, templates, logger);
    sol = sol.split("Groth16Verifier").join(v.verifierName);
    fs.writeFileSync(path.join(VERIFIERS_OUT, `${v.verifierName}.sol`), sol);
    console.log(`  wrote contracts/contracts/verifiers/${v.verifierName}.sol`);

    // 5. Browser artifacts for the holder-wallet /benchmark page
    const wasmSrc = path.join(BUILD_DIR, `${v.name}_js`, `${v.name}.wasm`);
    fs.copyFileSync(wasmSrc, path.join(WALLET_PUBLIC, `${v.browserTag}.wasm`));
    fs.copyFileSync(zkeyFinal, path.join(WALLET_PUBLIC, `${v.browserTag}.zkey`));
    console.log(`  copied browser artifacts (${v.browserTag}.wasm/.zkey)`);
  }

  console.log("\nBuild complete.");
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error(err);
    process.exit(1);
  }
);
