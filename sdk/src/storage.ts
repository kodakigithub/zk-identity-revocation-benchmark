/*
 * IPFS storage via helia. The prototype runs helia with `start: false`:
 * a fully local, in-memory blockstore — no network, no external daemon.
 * CIDs are real content identifiers; pinning/swapping to a networked helia
 * node is a one-line change for deployment scenarios.
 */
import { createHelia } from "helia";
import { unixfs } from "@helia/unixfs";
import { CID } from "multiformats/cid";

let _helia: any = null;
let _fs: any = null;

export async function getIpfs(): Promise<any> {
  if (!_fs) {
    _helia = await createHelia({ start: false });
    _fs = unixfs(_helia);
  }
  return _fs;
}

export async function storeBlob(bytes: Uint8Array): Promise<string> {
  const fs = await getIpfs();
  const cid = await fs.addBytes(bytes);
  return cid.toString();
}

export async function loadBlob(cidStr: string): Promise<Uint8Array> {
  const fs = await getIpfs();
  const cid = CID.parse(cidStr);
  let out = new Uint8Array(0);
  for await (const chunk of fs.cat(cid)) {
    const next = new Uint8Array(out.length + chunk.length);
    next.set(out);
    next.set(chunk, out.length);
    out = next;
  }
  return out;
}

/** Release the helia node so the process can exit cleanly (demo/scripts). */
export async function stopIpfs(): Promise<void> {
  if (_helia) {
    await _helia.stop();
    _helia = null;
    _fs = null;
  }
}
