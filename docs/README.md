# ZK Credential Revocation — Research Prototype

Zero-knowledge selective disclosure over W3C Verifiable Credentials with **two
independently working, benchmarkable revocation schemes**:

- **Scheme A — Nullifier Registry**: the proof exposes a public nullifier
  `Poseidon(credentialSecret, externalNullifier)`; an on-chain mapping marks revoked
  nullifiers. Linear on-chain storage growth, cheap constant-size circuit.
- **Scheme B — Merkle (Sparse Merkle Tree) non-membership**: the proof shows the
  credential's leaf `Poseidon(credentialSecret) mod 2^64` is **absent** from the
  issuer's off-chain revocation tree, against a single on-chain root. Constant
  on-chain storage, larger circuit.

Both schemes attach to the **same base credential and the same base predicate
circuit** (`attributeValue <= threshold`, e.g. "age ≥ 18" from a birth timestamp);
only the revocation-proof portion differs, so the benchmarks isolate the revocation
mechanism itself.

## Repository layout

```
circuits/    circom circuits (2 variants) + build pipeline + circom_tester tests
contracts/   Solidity (registries, access-control, generated verifiers) + Hardhat tests
sdk/         TypeScript SDK (browser-safe core + @zkcr/sdk/node entry)
apps/        issuer-portal · holder-wallet (incl. /benchmark page) · verifier-app
benchmarks/  gas / proof-time / storage measurement scripts + results/
docs/        this file + ARCHITECTURE.md
tools/bin/   project-local circom 2.2.3 binary
```

## Prerequisites

- Node.js ≥ 20 (developed and tested on v23.11.1), npm ≥ 10
- Linux x86_64 (the bundled circom binary is linux-amd64; on other platforms replace
  `tools/bin/circom` with the matching release from https://github.com/iden3/circom/releases)
- No global circom/snarkjs installs needed — everything is project-local

## Setup

```bash
npm install                 # one hoisted install for the whole workspace
npm run setup:circom        # fetch the project-local circom 2.2.3 binary (linux-amd64)
npm run build:circuits      # compile circuits, local powers-of-tau (2^16, fixed entropy),
                            # groth16 setup, export Solidity verifiers + browser artifacts
npm run compile:contracts   # hardhat compile
npm run build:sdk           # tsc -> sdk/dist
```

Run the test suites:

```bash
npm run test:circuits       # 8 circom_tester tests (valid / predicate-violation / revoked)
npm run test:contracts      # 9 Hardhat tests (happy path, revoked, wrong-root, unauthorized)
```

## End-to-end demo (definition of done)

Each run: starts a local node if needed → deploys → registers issuer → issues an
encrypted credential to IPFS → holder proves → **on-chain ACCEPT** → issuer revokes →
post-revocation attempt → **on-chain REJECT**. Under ~15 s each.

```bash
npm run demo:nullifier      # Scheme A
npm run demo:merkle         # Scheme B
```

## Benchmarks

All write CSVs to `benchmarks/results/` (see `benchmarks/results/README.md`).

```bash
npm run bench:gas           # [N=100] [K=50]  verify/revoke gas + crossover analysis
npm run bench:proof-time    # [T=30]          proving wall time + heap delta, mean/std
npm run bench:storage       # [K=50]          on-chain slot growth via eth_getStorageAt
```

Defaults are the spec values (N=100, K=50, T=30); override via positional args, e.g.
`node benchmarks/gas/bench-gas.js 200 100`.

### On-device (mobile) benchmark page

Circuit proving is measured on real devices with the holder-wallet's `/benchmark`
debug page — a headless Node benchmark cannot represent a phone. It needs **no
backend**:

```bash
npm run node &                       # terminal 1: local chain (only needed for the wallet flows)
npm run deploy:local                 # deploy + sync addresses into the apps
npm run dev -w @zkcr/holder-wallet & # holder wallet on :5174
```

Open `http://<your-laptop-ip>:5174/benchmark` on a laptop, a high-end phone, and a
budget Android phone in turn (same Wi-Fi; vite binds all interfaces by default).
Configure trials, press **Run benchmark**, then **Copy as JSON** and paste into
`benchmarks/results/mobile.json` (see `benchmarks/results/README.md`).

A headless smoke test of this page (used in CI-style checks):

```bash
cd apps/holder-wallet && npx vite build && (npx vite preview --port 4199 --strictPort &)
# then open http://localhost:4199/benchmark?auto=1&trials=2 in a headless browser
```

## Apps (manual demo flow)

```bash
npm run node &                       # terminal 1
npm run deploy:local                 # once: deploy to localhost + sync into apps
npm run dev -w @zkcr/issuer-portal & # :5173
npm run dev -w @zkcr/holder-wallet & # :5174
npm run dev -w @zkcr/verifier-app &  # :5175
```

Flow (repeat for both schemes):

1. **issuer portal** (:5173): set a birth date → *Issue credential* → *Copy holder payload*
2. **holder wallet** (:5174): paste payload → *Import* → pick scheme → (Scheme B only:
   paste the revoked smtKey list from the issuer portal's *Copy revoked smtKey list*
   button) → *Generate proof* → *Copy proof bundle*
3. **verifier app** (:5175): paste bundle → *Verify on-chain* → **PROOF ACCEPTED**
4. **issuer portal**: *Revoke* the credential under that scheme
5. **holder wallet**: regenerate (Scheme A) or attempt (Scheme B — fails at the
   circuit level; replaying the old proof fails on-chain) → **verifier** shows
   **PROOF REJECTED**

## Sepolia deployment

Copy `.env.example` to `.env` and fill in `SEPOLIA_RPC_URL` and
`DEPLOYER_PRIVATE_KEY` (testnet funds only). Never commit real keys.

```bash
npm run deploy:sepolia    # writes contracts/deployments/sepolia.json
```

## Environment variables

| Variable                     | Used by            | Purpose                              |
| ---------------------------- | ------------------ | ------------------------------------ |
| `SEPOLIA_RPC_URL`            | contracts deploy   | Sepolia RPC endpoint                 |
| `DEPLOYER_PRIVATE_KEY`       | contracts deploy   | deployer/issuer EOA (testnet only)   |
| `LOCAL_RPC_URL`              | sdk, benchmarks    | local node URL (default 127.0.0.1:8545) |
| `ISSUER_ED25519_PRIVATE_KEY` | sdk (optional)     | fixed issuer key; generated if unset |

## Design decisions & prototype simplifications

These are deliberate; they are listed here so the paper's methodology section is honest:

- **Issuer generates and knows `credentialSecret`.** It is delivered inside the
  encrypted holder payload, so revocation handles (nullifier / smtKey) are computable
  by the issuer. ZK privacy is protected against the *verifier*, not the issuer —
  standard in prototype DID revocation systems.
- **Signature scheme**: raw Ed25519 over SHA-256 of canonicalized VC JSON (not a full
  W3C Data Integrity suite). The VC model (context/types/subject/proof) follows the
  W3C VC Data Model shape.
- **Storage**: helia runs with `start: false` — a local in-memory IPFS blockstore.
  CIDs are real; a networked helia node is a one-line change.
- **`externalNullifier` is a fixed constant (42)** for v1, as the spec allows.
- **Access contracts** expose an identical `verifyAndCheck(pA,pB,pC,pubSignals[4])`
  interface for both schemes so the gas comparison is not confounded by interface shape.
- **No TypeChain**: contract handles in tests/SDK use minimal ABIs / `any` types.
- **Holder reconstructs the Scheme B tree from public revoked leaf keys** (siblings
  are public data published by the issuer) — this data-availability requirement is a
  qualitative Scheme A vs B difference the paper discusses.
- **Known quirk handled in-code**: Hardhat automine + ethers v6 occasionally serves a
  stale nonce; SDK sends transactions through a retry wrapper (`sendTx`).

## Circom / Solidity gotchas discovered

- `SMTVerifier` splits the key with `Num2Bits_strict`, so a full ~254-bit Poseidon
  output cannot be a leaf key directly; we reduce `Poseidon(secret) mod 2^64`
  in-circuit and identically off-chain (needs reduced keys; JS tree can overflow otherwise).
- JS SMT `find()` returns siblings ordered root→leaf; pad with zeros at the END
  (leaf side) to reach `nLevels`.
- `circom_tester` needs the circom binary on `PATH` — this repo's test script prepends
  `../tools/bin`.
- snarkjs's `exportSolidityVerifier()` requires the ejs template explicitly loaded
  (as its CLI does) — our build script does that.
- circom block comments containing `*/` (e.g. in a path like `attribute-proof-*/`)
  break compilation — mind comment text.

## Rebuild cheatsheet

```bash
npm install
npm run build:circuits && npm run compile:contracts && npm run build:sdk
npm run test:circuits && npm run test:contracts
npm run demo:nullifier && npm run demo:merkle
npm run bench:gas && npm run bench:proof-time && npm run bench:storage
```
