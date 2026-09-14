/*
 * Verification: local Groth16 check against a verification key, then the
 * authoritative on-chain check via the scheme's access-control contract.
 * Browser-safe: the caller supplies the verification key JSON (apps fetch it
 * from a URL; Node callers can use loadVerificationKey from @zkcr/sdk/node).
 */
import { ethers } from "ethers";
import { snarkjs } from "./deps.js";
import { getContract, sendTx } from "./contracts.js";
import type { ProofBundle, VerifyResult } from "./types.js";

/** Off-chain Groth16 verification (fast sanity check; NOT the trust anchor). */
export async function verifyLocally(bundle: ProofBundle, vkey: any): Promise<boolean> {
  return snarkjs.groth16.verify(vkey, bundle.publicSignals, bundle.proof);
}

/** Convert a snarkjs proof into the Solidity calldata layout. */
export async function toSolidityCalldata(
  bundle: ProofBundle
): Promise<{ pA: any; pB: any; pC: any; pub: any }> {
  const cd = await snarkjs.groth16.exportSolidityCallData(bundle.proof, bundle.publicSignals);
  const [pA, pB, pC, pub] = JSON.parse(`[${cd}]`);
  return { pA, pB, pC, pub };
}

/**
 * Full verification: local check + on-chain verifyAndCheck transaction.
 * The on-chain call enforces BOTH proof validity and revocation state, and emits
 * exactly one ProofAccepted / ProofRejected event.
 */
export async function verifyProof(
  bundle: ProofBundle,
  opts: {
    accessAddress: string;
    signer: ethers.Signer;
    /** Verification key JSON for the local check. Omit to skip the local check. */
    vkey?: any;
    /** default true: send the transaction. false: local check only. */
    submit?: boolean;
  }
): Promise<VerifyResult> {
  const localValid = opts.vkey ? await verifyLocally(bundle, opts.vkey) : true;
  const result: VerifyResult = { scheme: bundle.scheme, localValid };
  if (opts.submit === false) return result;

  const access = getContract(
    bundle.scheme === "nullifier" ? "AccessControlNullifier" : "AccessControlMerkle",
    opts.accessAddress,
    opts.signer
  );
  const { pA, pB, pC, pub } = await toSolidityCalldata(bundle);
  const receipt: any = await sendTx(() => access.verifyAndCheck(pA, pB, pC, pub));

  let event = "none";
  let reason: string | undefined;
  let accepted = false;
  for (const log of receipt.logs) {
    try {
      const parsed = access.interface.parseLog(log);
      if (parsed && (parsed.name === "ProofAccepted" || parsed.name === "ProofRejected")) {
        event = parsed.name;
        accepted = parsed.name === "ProofAccepted";
        if (parsed.name === "ProofRejected") reason = parsed.args.reason;
      }
    } catch {
      // not our contract's log — skip
    }
  }

  result.onChain = {
    accepted,
    txHash: receipt.hash,
    event,
    reason,
    gasUsed: receipt.gasUsed.toString(),
  };
  return result;
}
