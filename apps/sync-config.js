/*
 * Sync deployment config into the apps: copies contracts/deployments/localhost.json
 * into each app's public/ dir so the Vite dev servers can fetch it at /deployment.json.
 * Run after `npm run deploy:local -w @zkcr/contracts` (or it is called for you).
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const src = path.join(ROOT, "contracts", "deployments", "localhost.json");

if (!fs.existsSync(src)) {
  console.error(
    "contracts/deployments/localhost.json not found. Start a node and deploy first:\n" +
      "  npm run node            # terminal 1\n" +
      "  npm run deploy:local -w @zkcr/contracts   # terminal 2"
  );
  process.exit(1);
}

const apps = ["issuer-portal", "holder-wallet", "verifier-app"];
for (const app of apps) {
  const destDir = path.join(ROOT, "apps", app, "public");
  fs.mkdirSync(destDir, { recursive: true });
  fs.copyFileSync(src, path.join(destDir, "deployment.json"));
}
console.log(`deployment.json synced to ${apps.length} apps`);
