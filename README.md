# ZK Credential Revocation System

Research prototype comparing two privacy-preserving credential-revocation schemes —
**Nullifier Registry** vs **Sparse-Merkle-Tree non-membership** — over a shared
zero-knowledge predicate circuit (`attributeValue ≤ threshold`, e.g. "age ≥ 18").

**Full documentation: [docs/README.md](docs/README.md)** · architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

Quick start:

```bash
npm install
npm run build:circuits && npm run compile:contracts && npm run build:sdk
npm run demo:nullifier   # end-to-end demo, Scheme A (~7 s)
npm run demo:merkle      # end-to-end demo, Scheme B (~13 s)
```
