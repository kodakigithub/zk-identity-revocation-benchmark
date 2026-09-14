/*
 * Cryptographic helpers: canonical JSON, Ed25519 credential signatures, AES-GCM
 * encryption for at-rest credential storage.
 *
 * Prototype simplifications (documented in docs/):
 *  - Signature is Ed25519 over SHA-256 of a canonical JSON serialization of the VC
 *    (not a full Data Integrity / JWS suite).
 *  - Encryption key is returned alongside the CID to the caller (the "holder").
 */
import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { sha512 } from "@noble/hashes/sha2";

// @noble/ed25519 v2 requires an explicit sha512 implementation (from @noble/hashes).
ed.etc.sha512Sync = (...messages: Uint8Array[]) => sha512(ed.etc.concatBytes(...messages));
ed.etc.sha512Async = async (...messages: Uint8Array[]) =>
  sha512(ed.etc.concatBytes(...messages));

/** Deterministic JSON: recursively sorts object keys. */
export function canonicalize(value: any): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
}

export function sha256Hex(data: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(data)));
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export interface IssuerKeys {
  privateKeyHex: string;
  publicKeyHex: string;
}

export async function generateIssuerKeys(): Promise<IssuerKeys> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { privateKeyHex: bytesToHex(priv), publicKeyHex: bytesToHex(pub) };
}

/** Sign a VC (without `proof`) and return a copy with an Ed25519 proof attached. */
export async function signCredential(
  vcWithoutProof: Record<string, any>,
  issuer: IssuerKeys
): Promise<Record<string, any>> {
  const digest = sha256(new TextEncoder().encode(canonicalize(vcWithoutProof)));
  const sig = await ed.signAsync(digest, hexToBytes(issuer.privateKeyHex));
  return {
    ...vcWithoutProof,
    proof: {
      type: "Ed25519Signature2020",
      created: new Date().toISOString(),
      verificationMethod: `did:zkcr:issuer:${issuer.publicKeyHex.slice(0, 16)}#key-1`,
      proofPurpose: "assertionMethod",
      proofValue: bytesToHex(sig),
    },
  };
}

/** Verify the Ed25519 proof attached to a VC. */
export async function verifyCredentialSignature(
  vc: Record<string, any>,
  issuerPublicKeyHex: string
): Promise<boolean> {
  const { proof, ...rest } = vc;
  if (!proof?.proofValue) return false;
  const digest = sha256(new TextEncoder().encode(canonicalize(rest)));
  return ed.verifyAsync(hexToBytes(proof.proofValue), digest, hexToBytes(issuerPublicKeyHex));
}

/** AES-GCM encrypt; returns the envelope bytes plus the raw key (hex). */
export async function encryptBlob(
  plaintext: Uint8Array
): Promise<{ envelope: Uint8Array; keyHex: string }> {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  const envelope = new TextEncoder().encode(
    JSON.stringify({ v: 1, alg: "A256GCM", iv: bytesToHex(iv), ct: bytesToHex(ct) })
  );
  return { envelope, keyHex: bytesToHex(rawKey) };
}

/** AES-GCM decrypt of an envelope produced by encryptBlob. */
export async function decryptBlob(envelope: Uint8Array, keyHex: string): Promise<Uint8Array> {
  const parsed = JSON.parse(new TextDecoder().decode(envelope));
  const key = await crypto.subtle.importKey("raw", hexToBytes(keyHex), "AES-GCM", false, [
    "decrypt",
  ]);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: hexToBytes(parsed.iv) },
    key,
    hexToBytes(parsed.ct)
  );
  return new Uint8Array(pt);
}
