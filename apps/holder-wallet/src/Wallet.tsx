import { useMemo, useState } from "react";
import { generateProof, RevocationTree, type ProofBundle, type Scheme } from "@zkcr/sdk";

interface HolderPayload {
  vc: any;
  credentialSecret: string;
  encryptionKey: string;
  ipfsCid: string;
  commitment: string;
}

const ARTIFACTS: Record<Scheme, { wasm: string; zkey: string }> = {
  nullifier: { wasm: "/circuits/nullifier.wasm", zkey: "/circuits/nullifier.zkey" },
  merkle: { wasm: "/circuits/smt.wasm", zkey: "/circuits/smt.zkey" },
};

export default function Wallet() {
  const [payloadText, setPayloadText] = useState("");
  const [payload, setPayload] = useState<HolderPayload | null>(null);
  const [scheme, setScheme] = useState<Scheme>("nullifier");
  const [revokedKeysText, setRevokedKeysText] = useState("[]");
  const [bundle, setBundle] = useState<ProofBundle | null>(null);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<string[]>([]);

  const say = (m: string) => setLog((l) => [`[${new Date().toLocaleTimeString()}] ${m}`, ...l]);

  // Predicate cutoff: "at least 18 years old" evaluated at import time.
  const threshold = useMemo(
    () => BigInt(Math.floor(Date.now() / 1000) - Math.floor(18 * 365.25 * 86400)),
    []
  );

  const importPayload = () => {
    try {
      const p = JSON.parse(payloadText);
      if (!p.vc || !p.credentialSecret) throw new Error("missing vc / credentialSecret");
      setPayload(p);
      setBundle(null);
      say(`credential imported (commitment ${String(p.commitment).slice(0, 20)}…)`);
    } catch (e: any) {
      say(`import failed: ${e.message?.slice(0, 120)}`);
    }
  };

  const prove = async () => {
    if (!payload) return;
    setBusy(true);
    setBundle(null);
    try {
      const attributeValue = BigInt(payload.vc.credentialSubject.attributeValue);
      let revocationTree: RevocationTree | undefined;
      if (scheme === "merkle") {
        const keys: string[] = JSON.parse(revokedKeysText);
        revocationTree = await RevocationTree.fromRevokedKeys(keys.map((k) => BigInt(k)));
        say(`rebuilt revocation tree (${keys.length} revoked leaves)`);
      }
      const t0 = performance.now();
      const b = await generateProof(scheme, {
        credentialSecret: BigInt(payload.credentialSecret),
        attributeValue,
        threshold,
        revocationTree,
        wasmPath: ARTIFACTS[scheme].wasm,
        zkeyPath: ARTIFACTS[scheme].zkey,
      });
      say(`proof generated in ${(performance.now() - t0).toFixed(0)} ms (scheme ${scheme})`);
      setBundle(b);
    } catch (e: any) {
      say(`proof failed: ${e.message?.slice(0, 160)}`);
    } finally {
      setBusy(false);
    }
  };

  const copyBundle = async () => {
    if (!bundle) return;
    await navigator.clipboard.writeText(JSON.stringify(bundle));
    say("proof bundle copied — paste it into the verifier app");
  };

  return (
    <div>
      <h1>
        ZKCR <span className="pill">holder wallet</span>
      </h1>
      <div className="dim">
        debug page: <a href="/benchmark" style={{ color: "#9ecbff" }}>/benchmark (on-device proving)</a>
      </div>

      <h2>1. Import credential</h2>
      <div className="card">
        <textarea
          rows={5}
          placeholder="paste the holder payload JSON from the issuer portal"
          value={payloadText}
          onChange={(e) => setPayloadText(e.target.value)}
        />
        <button onClick={importPayload}>Import</button>
        {payload && (
          <div className="ok">
            imported · attributeValue {payload.vc.credentialSubject.attributeValue} · commitment{" "}
            {payload.commitment.slice(0, 20)}…
          </div>
        )}
      </div>

      <h2>2. Generate proof (predicate: age ≥ 18)</h2>
      <div className="card">
        <label>revocation scheme</label>
        <select value={scheme} onChange={(e) => setScheme(e.target.value as Scheme)}>
          <option value="nullifier">A — nullifier registry</option>
          <option value="merkle">B — merkle (SMT) non-membership</option>
        </select>
        {scheme === "merkle" && (
          <>
            <label>revoked smtKey list (JSON, from the issuer portal)</label>
            <textarea
              rows={3}
              value={revokedKeysText}
              onChange={(e) => setRevokedKeysText(e.target.value)}
            />
          </>
        )}
        <br />
        <button onClick={prove} disabled={!payload || busy}>
          {busy ? "proving…" : "Generate proof"}
        </button>
      </div>

      {bundle && (
        <>
          <h2>3. Proof bundle</h2>
          <div className="card">
            <div className="dim">
              commitment {bundle.signals.credentialCommitment.slice(0, 20)}… · ref{" "}
              {bundle.signals.revocationRef.slice(0, 20)}…
            </div>
            <pre>{JSON.stringify(bundle, null, 2).slice(0, 1200)}…</pre>
            <button onClick={copyBundle}>Copy proof bundle</button>
          </div>
        </>
      )}

      <h2>Log</h2>
      <pre>{log.join("\n")}</pre>
    </div>
  );
}
