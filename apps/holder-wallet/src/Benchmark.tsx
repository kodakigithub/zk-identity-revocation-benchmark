/*
 * On-device proving benchmark (spec §7.3). No backend required:
 * loads both circuits' .wasm/.zkey from /public/circuits, runs T Groth16 proving
 * trials per scheme IN THIS BROWSER (laptop, phone, budget Android — same page),
 * times each trial with performance.now(), shows a table + mean/std, and exports
 * JSON via a copy button. Paste results into benchmarks/results/mobile.json.
 */
import { useEffect, useRef, useState } from "react";
import * as snarkjsNs from "snarkjs";
import { generateCredentialSecret, RevocationTree, EXTERNAL_NULLIFIER } from "@zkcr/sdk";

const snarkjs: any = snarkjsNs;

const ARTIFACTS = {
  nullifier: { wasm: "/circuits/nullifier.wasm", zkey: "/circuits/nullifier.zkey" },
  merkle: { wasm: "/circuits/smt.wasm", zkey: "/circuits/smt.zkey" },
};

const ATTRIBUTE = 946684800n;

interface Trial {
  trial: number;
  time_ms: number;
  memory_delta_bytes: number | null;
}

interface SchemeResult {
  trials: Trial[];
  mean_ms: number;
  std_ms: number;
}

function mean(xs: number[]) {
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}

function std(xs: number[]) {
  const m = mean(xs);
  return Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / (xs.length - 1 || 1));
}

function heapUsed(): number | null {
  // Chrome-only non-standard API; null elsewhere (trials are still timed).
  const m = (performance as any).memory;
  return m ? m.usedJSHeapSize : null;
}

export default function Benchmark() {
  const [T, setT] = useState(10);
  const [revokedCount, setRevokedCount] = useState(50);
  const [running, setRunning] = useState("");
  const [results, setResults] = useState<Record<string, SchemeResult> | null>(null);
  const [copied, setCopied] = useState(false);
  const runRef = useRef<() => Promise<void>>(async () => {});

  // Test hook: /benchmark?auto=1&trials=2 auto-runs and exposes results on window
  // (used by the headless smoke test in docs/README.md).
  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    if (q.get("auto") === "1") {
      const n = parseInt(q.get("trials") || "2", 10);
      if (n > 0) setT(n);
      setTimeout(() => runRef.current(), 500);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    (window as any).__zkcrResults = results;
  }, [results]);

  const buildInput = async (scheme: "nullifier" | "merkle", tree: any, threshold: bigint) => {
    const secret = generateCredentialSecret();
    if (scheme === "nullifier") {
      return {
        attributeValue: ATTRIBUTE,
        threshold,
        credentialSecret: secret,
        externalNullifier: EXTERNAL_NULLIFIER,
      };
    }
    const w = await tree.nonMembershipWitness(secret);
    return {
      attributeValue: ATTRIBUTE,
      threshold,
      credentialSecret: secret,
      siblings: w.siblings,
      oldKey: w.oldKey,
      oldValue: w.oldValue,
      isOld0: w.isOld0,
      root: w.root,
    };
  };

  const run = async () => {
    setResults(null);
    setCopied(false);
    const threshold = BigInt(Math.floor(Date.now() / 1000) - Math.floor(18 * 365.25 * 86400));
    const out: Record<string, SchemeResult> = {};

    setRunning("building revocation tree…");
    const tree = await RevocationTree.create();
    for (let i = 0; i < revokedCount; i++) await tree.revoke(generateCredentialSecret());

    for (const scheme of ["nullifier", "merkle"] as const) {
      const trials: Trial[] = [];
      for (let t = 0; t < T; t++) {
        setRunning(`${scheme} trial ${t + 1}/${T}`);
        // Witness prep is NOT timed (mirrors the Node benchmark).
        const input = await buildInput(scheme, tree, threshold);
        const m0 = heapUsed();
        const t0 = performance.now();
        await snarkjs.groth16.fullProve(input, ARTIFACTS[scheme].wasm, ARTIFACTS[scheme].zkey);
        const timeMs = performance.now() - t0;
        const m1 = heapUsed();
        trials.push({
          trial: t,
          time_ms: Math.round(timeMs * 10) / 10,
          memory_delta_bytes: m0 !== null && m1 !== null ? m1 - m0 : null,
        });
        // Let the UI breathe between trials (mobile browsers throttle heavy JS).
        await new Promise((r) => setTimeout(r, 30));
      }
      const times = trials.map((x) => x.time_ms);
      out[scheme] = {
        trials,
        mean_ms: Math.round(mean(times) * 10) / 10,
        std_ms: Math.round(std(times) * 10) / 10,
      };
    }
    setResults(out);
    setRunning("");
  };
  runRef.current = run;

  const copyJson = async () => {
    const payload = {
      device: navigator.userAgent,
      hardwareConcurrency: navigator.hardwareConcurrency ?? null,
      timestamp: new Date().toISOString(),
      trials_per_scheme: T,
      revoked_leaves_in_tree: revokedCount,
      results,
    };
    await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
    setCopied(true);
  };

  return (
    <div>
      <h1>
        ZKCR <span className="pill">on-device proving benchmark</span>
      </h1>
      <div className="dim">
        Open this page on a laptop, a high-end phone, and a budget Android phone; run it on
        each, then paste the JSON into benchmarks/results/mobile.json. No backend needed.
      </div>

      <div className="card">
        <label>trials per scheme</label>
        <input
          type="number"
          min={1}
          max={200}
          value={T}
          onChange={(e) => setT(parseInt(e.target.value || "10", 10))}
        />
        <label>revoked leaves in the SMT (Scheme B witness realism)</label>
        <input
          type="number"
          min={0}
          max={1000}
          value={revokedCount}
          onChange={(e) => setRevokedCount(parseInt(e.target.value || "50", 10))}
        />
        <br />
        <button onClick={run} disabled={!!running}>
          {running ? running : "Run benchmark"}
        </button>
      </div>

      {results && (
        <>
          <h2>Results</h2>
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>scheme</th>
                  <th>trials</th>
                  <th>mean (ms)</th>
                  <th>std (ms)</th>
                  <th>min (ms)</th>
                  <th>max (ms)</th>
                </tr>
              </thead>
              <tbody>
                {(["nullifier", "merkle"] as const).map((s) => {
                  const r = results[s];
                  const times = r.trials.map((x) => x.time_ms);
                  return (
                    <tr key={s}>
                      <td>{s}</td>
                      <td>{r.trials.length}</td>
                      <td>{r.mean_ms}</td>
                      <td>{r.std_ms}</td>
                      <td>{Math.min(...times)}</td>
                      <td>{Math.max(...times)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <button onClick={copyJson}>{copied ? "copied!" : "Copy as JSON"}</button>
          </div>

          <h2>Per-trial (CSV)</h2>
          <pre>
            {(["nullifier", "merkle"] as const)
              .map(
                (s) =>
                  results[s].trials
                    .map((t) => `${s},${t.trial},${t.time_ms},${t.memory_delta_bytes ?? ""}`)
                    .join("\n")
              )
              .join("\n")}
          </pre>
        </>
      )}
    </div>
  );
}
