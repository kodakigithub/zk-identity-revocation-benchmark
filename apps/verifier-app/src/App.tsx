import { useEffect, useMemo, useState } from "react";
import { verifyProof, getContract, type ProofBundle, type Scheme } from "@zkcr/sdk";
import { loadDeployment, getProvider, getSigner, type Deployment } from "./config";

export default function App() {
  const [deployment, setDeployment] = useState<Deployment | null>(null);
  const [deployError, setDeployError] = useState("");
  const [bundleText, setBundleText] = useState("");
  const [scheme, setScheme] = useState<Scheme>("nullifier");
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<null | {
    accepted: boolean;
    event: string;
    reason?: string;
    txHash: string;
    gasUsed: string;
  }>(null);
  const [error, setError] = useState("");
  const [currentRoot, setCurrentRoot] = useState("");

  useEffect(() => {
    loadDeployment()
      .then(setDeployment)
      .catch((e) => setDeployError(e.message));
  }, []);

  const provider = useMemo(() => getProvider(), []);
  const signer = useMemo(() => getSigner(provider), [provider]);

  useEffect(() => {
    if (!deployment) return;
    const reg = getContract("MerkleRevocationRegistry", deployment.merkleRegistry, provider);
    reg.currentRoot().then(setCurrentRoot).catch(() => {});
  }, [deployment, provider, outcome]);

  const verify = async () => {
    if (!deployment) return;
    setBusy(true);
    setOutcome(null);
    setError("");
    try {
      const bundle: ProofBundle = JSON.parse(bundleText);
      if (bundle.scheme !== scheme) {
        throw new Error(`bundle is for scheme "${bundle.scheme}", but "${scheme}" is selected`);
      }
      const accessAddress =
        scheme === "nullifier" ? deployment.accessNullifier : deployment.accessMerkle;
      // Local check is skipped in the browser (no vkey shipped); the on-chain
      // Groth16 verification is the authoritative check anyway.
      const res = await verifyProof(bundle, { accessAddress, signer });
      setOutcome(res.onChain!);
    } catch (e: any) {
      setError(e.message?.slice(0, 200) ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1>
        ZKCR <span className="pill">verifier</span>
      </h1>
      {deployError ? (
        <div className="card err">{deployError}</div>
      ) : !deployment ? (
        <div className="dim">loading…</div>
      ) : (
        <>
          <div className="card">
            <span className="pill">scheme</span>
            <select value={scheme} onChange={(e) => setScheme(e.target.value as Scheme)}>
              <option value="nullifier">A — nullifier registry</option>
              <option value="merkle">B — merkle (SMT) non-membership</option>
            </select>
            {scheme === "merkle" && (
              <div className="dim">current on-chain root: {currentRoot}</div>
            )}
          </div>

          <h2>Verify proof bundle</h2>
          <div className="card">
            <textarea
              rows={8}
              placeholder="paste the proof bundle JSON from the holder wallet"
              value={bundleText}
              onChange={(e) => setBundleText(e.target.value)}
            />
            <button onClick={verify} disabled={busy || !bundleText.trim()}>
              {busy ? "verifying…" : "Verify on-chain"}
            </button>
            {error && <div className="err">{error}</div>}
            {outcome && (
              <div className={outcome.accepted ? "ok" : "err"}>
                {outcome.accepted ? "PROOF ACCEPTED" : `PROOF REJECTED (${outcome.reason})`}
                <div className="dim">
                  event {outcome.event} · tx {outcome.txHash.slice(0, 18)}… · gas {outcome.gasUsed}
                </div>
              </div>
            )}
          </div>

          <div className="dim">
            The verifier learns ONLY the predicate result: the attribute value and the
            credential secret never leave the holder's browser.
          </div>
        </>
      )}
    </div>
  );
}
