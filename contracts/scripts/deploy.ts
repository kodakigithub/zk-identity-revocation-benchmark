/*
 * Full-system deployment (local Hardhat node or Sepolia).
 * Deploy order: DIDRegistry -> registries -> verifiers -> access-control entrypoints.
 * Writes addresses to contracts/deployments/<network>.json for the SDK/apps to load.
 */
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = (await ethers.provider.getNetwork()).name;
  console.log(`deploying on "${network}" with ${deployer.address}`);

  const deploy = async (name: string, args: any[] = []) => {
    const factory = await ethers.getContractFactory(name);
    const c = await factory.deploy(...args);
    await c.waitForDeployment();
    const addr = await c.getAddress();
    console.log(`  ${name}: ${addr}`);
    return addr;
  };

  const didRegistry = await deploy("DIDRegistry");
  const nullifierRegistry = await deploy("NullifierRegistry", [deployer.address]);
  const merkleRegistry = await deploy("MerkleRevocationRegistry", [deployer.address]);
  const verifierNullifier = await deploy("Groth16VerifierNullifier");
  const verifierSMT = await deploy("Groth16VerifierSMT");
  const accessNullifier = await deploy("AccessControlNullifier", [verifierNullifier, nullifierRegistry]);
  const accessMerkle = await deploy("AccessControlMerkle", [verifierSMT, merkleRegistry]);

  const out = {
    network,
    deployer: deployer.address,
    didRegistry,
    nullifierRegistry,
    merkleRegistry,
    verifierNullifier,
    verifierSMT,
    accessNullifier,
    accessMerkle,
    deployedAt: new Date().toISOString(),
  };
  const dir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${network === "unknown" ? "localhost" : network}.json`);
  fs.writeFileSync(file, JSON.stringify(out, null, 2));
  console.log(`addresses written to ${path.relative(process.cwd(), file)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
