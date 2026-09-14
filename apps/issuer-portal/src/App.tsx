import { useEffect, useMemo, useState } from "react";
import {
  generateIssuerKeys,
  issueCredential,
  revokeCredential,
  RevocationTree,
  getContract,
  sendTx,
  sha256Hex,
  stopIpfs,
  type IssuedCredential,
  type IssuerKeys,
} from "@zkcr/sdk";
import { loadDeployment, getProvider, getSigner, type Deployment } from "./config";

interface RevokedRecord {
  credentialSecret: string;
  smtKey: string;
  nullifier: string;
  schemes: string[]; // which schemes this credential was revoked under
}

interface PersistedState {
  issuerKeys: IssuerKeys;
  issued: IssuedCredential[];
  revoked: RevokedRecord[];
}

const LS_KEY = "zkcr_issuer_state_v1";

function loadState(): PersistedState | null {
  try {
    const raw = localStorage.getItem(LS_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export default function App() {
  const [deployment, setDeployment] = useState<Deployment | null>(null);
  const [deployError, setDeployError] = useState("");
  const [state, setState] = useState<PersistedState | null>(null);
  const [birthDate, setBirthDate] = useState("2000-01-01");
  const [holderId, setHolderId] = useState("did:zkcr:holder:alice");
  const [busy, setBusy] = useState("");
  const [log, setLog] = useState<string[]>([]);
  const [onchainRoot, setOnchainRoot] = useState("");

  const say = (m: string) => setLog((l) => [`[${new Date().toLocaleTimeString()}] ${m}`, ...l]);

  useEffect(() => {
    loadDeployment()
      .then(setDeployment)
      .catch((e) => setDeployError(e.message));
    (async () => {
      let s = loadState();
      if (!s) {
        s = { issuerKeys: await generateIssuerKeys(), issued: [], revoked: [] };
        localStorage.setItem(LS_KEY, JSON.stringify(s));
      }
      setState(s);
    })();
  }, []);

  const persist = (s: PersistedState) => {
    localStorage.setItem(LS_KEY, JSON.stringify(s));
    setState({ ...s });
  };

  const provider = useMemo(() => getProvider(), []);
  const signer = useMemo(() => getSigner(provider), [provider]);

  const refreshRoot = async () => {
    if (!deployment) return;
    const reg = getContract("MerkleRevocationRegistry", deployment.merkleRegistry, provider);
    setOnchainRoot(await reg.currentRoot());
  };
  useEffect(() => {
    refreshRoot().catch(() => {});
  }, [deployment]);

  const registerDid = async () => {
    if (!deployment || !state) return;
    setBusy("register");
    try {
      const did = `did:zkcr:issuer:${state.issuerKeys.publicKeyHex.slice(0, 16)}`;
      const reg = getContract("DIDRegistry", deployment.didRegistry, signer);
      await sendTx(() => reg.registerIssuer("0x" + sha256Hex(did)));
      say(`issuer DID registered: ${did}`);
    } catch (e: any) {
      say(`register failed: ${e.message?.slice(0, 120)}`);
    } finally {
      setBusy("");
    }
  };

  const issue = async () => {
    if (!state) return;
    setBusy("issue");
    try {
      const attributeValue = BigInt(Math.floor(new Date(birthDate + "T00:00:00Z").getTime() / 1000));
      const cred = await issueCredential(state.issuerKeys, { attributeValue, birthDate, holderId });
      persist({ ...state, issued: [cred, ...state.issued] });
      say(`issued credential for ${holderId} (commitment ${cred.commitment.slice(0, 16)}…)`);
    } catch (e: any) {
      say(`issue failed: ${e.message?.slice(0, 160)}`);
    } finally {
      setBusy("");
    }
  };

  const revoke = async (cred: IssuedCredential, scheme: "nullifier" | "merkle") => {
    if (!deployment || !state) return;
    setBusy(cred.credentialSecret + scheme);
    try {
      const tree = await RevocationTree.fromRevokedSecrets(
        state.revoked.map((r) => BigInt(r.credentialSecret))
      );
      const res = await revokeCredential(scheme, {
        credentialSecret: BigInt(cred.credentialSecret),
        issuerSigner: signer,
        nullifierRegistryAddress: deployment.nullifierRegistry,
        merkleRegistryAddress: deployment.merkleRegistry,
        revocationTree: tree,
      });
      const revoked = [...state.revoked];
      const existing = revoked.find((r) => r.credentialSecret === cred.credentialSecret);
      if (existing) existing.schemes = [...new Set([...existing.schemes, scheme])];
      else
        revoked.push({
          credentialSecret: cred.credentialSecret,
          smtKey: cred.smtKey,
          nullifier: cred.nullifier,
          schemes: [scheme],
        });
      persist({ ...state, revoked });
      if (scheme === "merkle") await refreshRoot();
      say(`revoked (scheme ${scheme}) tx ${res.txHash.slice(0, 14)}… gas ${res.gasUsed}`);
    } catch (e: any) {
      say(`revoke failed: ${e.message?.slice(0, 140)}`);
    } finally {
      setBusy("");
    }
  };

  const copy = async (text: string, what: string) => {
    await navigator.clipboard.writeText(text);
    say(`copied ${what} to clipboard`);
  };

  const revokedOf = (cred: IssuedCredential) =>
    state?.revoked.find((r) => r.credentialSecret === cred.credentialSecret);

  return (
    <div>
      <h1>
        ZKCR <span className="pill">issuer portal</span>
      </h1>
      {deployError ? (
        <div className="card err">
          {deployError}
        </div>
      ) : !deployment || !state ? (
        <div className="dim">loading…</div>
      ) : (
        <>
          <div className="card">
            <span className="pill">chain</span> contracts @ {deployment.accessNullifier.slice(0, 12)}… /{" "}
            {deployment.accessMerkle.slice(0, 12)}…
            <br />
            <span className="pill">issuer</span> did:zkcr:issuer:{state.issuerKeys.publicKeyHex.slice(0, 16)}
            <button onClick={registerDid} disabled={busy === "register"}>
              Register issuer DID
            </button>
            <br />
            <span className="pill">merkle root</span> <span className="dim">{onchainRoot}</span>
          </div>

          <h2>Issue credential</h2>
          <div className="card">
            <label>birth date (attribute; predicate will prove "age ≥ 18" without revealing it)</label>
            <input type="date" value={birthDate} onChange={(e) => setBirthDate(e.target.value)} />
            <label>holder id</label>
            <input value={holderId} onChange={(e) => setHolderId(e.target.value)} size={40} />
            <br />
            <button onClick={issue} disabled={busy === "issue"}>
              Issue credential
            </button>
          </div>

          <h2>Issued credentials ({state.issued.length})</h2>
          {state.issued.map((c, i) => {
            const rev = revokedOf(c);
            return (
              <div className="card" key={i}>
                <div className="dim">
                  commitment {c.commitment.slice(0, 24)}… · nullifier {c.nullifier.slice(0, 16)}… · smtKey{" "}
                  {c.smtKey.slice(0, 12)}… · ipfs {c.ipfsCid.slice(0, 18)}…
                </div>
                {rev && <div className="err">revoked under: {rev.schemes.join(", ")}</div>}
                <button
                  onClick={() =>
                    copy(
                      JSON.stringify({
                        vc: c.vc,
                        credentialSecret: c.credentialSecret,
                        encryptionKey: c.encryptionKey,
                        ipfsCid: c.ipfsCid,
                        commitment: c.commitment,
                      }),
                      "holder payload"
                    )
                  }
                >
                  Copy holder payload
                </button>
                <button
                  className="danger"
                  disabled={!!busy}
                  onClick={() => revoke(c, "nullifier")}
                >
                  Revoke (A: nullifier)
                </button>
                <button className="danger" disabled={!!busy} onClick={() => revoke(c, "merkle")}>
                  Revoke (B: merkle)
                </button>
              </div>
            );
          })}

          <h2>Holder support</h2>
          <div className="card">
            <button
              onClick={() =>
                copy(JSON.stringify(state.revoked.map((r) => r.smtKey)), "revoked smtKey list")
              }
            >
              Copy revoked smtKey list (holders need this for Scheme B)
            </button>
            <div className="dim">
              Holders rebuild the issuer's revocation tree from these PUBLIC keys to produce
              non-membership witnesses. Secrets are never shared.
            </div>
          </div>

          <h2>Log</h2>
          <pre>{log.join("\n")}</pre>
        </>
      )}
    </div>
  );
}
