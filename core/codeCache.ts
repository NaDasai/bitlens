/**
 * Last-known-good copy of fetched contract code, for when the RPC is
 * unreachable (conference wifi). Written after every successful fetch; read
 * only when every RPC endpoint fails. Cards built from it say so
 * (`source: "cache"`, `cached_at`). Never used for demo contracts.
 *
 * Layout: <dir>/<network>/<account_id>.wasm + .json. Account ids are validated
 * before they get here (no "/" and no ".." possible), so they are safe file names.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AccessKeySummary } from "./scan.js";

/** Read at call time so tests (and users) can redirect it with $XRAY_CACHE_DIR. */
export const cacheDir = () => process.env.XRAY_CACHE_DIR ?? fileURLToPath(new URL("../.cache/code/", import.meta.url));

export interface CachedCode {
  wasm: Uint8Array;
  rpc_url: string;
  rpc_hash: string;
  block_height: number;
  fetched_at: string;
  access_keys: AccessKeySummary | null;
}

const paths = (network: string, accountId: string) => {
  const dir = join(cacheDir(), network.replace(/[^a-z0-9-]/gi, "_"));
  return { dir, wasm: join(dir, `${accountId}.wasm`), meta: join(dir, `${accountId}.json`) };
};

export async function saveCachedCode(network: string, accountId: string, c: CachedCode): Promise<void> {
  try {
    const p = paths(network, accountId);
    await mkdir(p.dir, { recursive: true });
    await writeFile(p.wasm, c.wasm);
    const { wasm: _w, ...meta } = c;
    await writeFile(p.meta, JSON.stringify(meta, null, 2));
  } catch {
    // best effort: a read-only checkout just means no offline fallback
  }
}

export async function loadCachedCode(network: string, accountId: string): Promise<CachedCode | null> {
  try {
    const p = paths(network, accountId);
    const meta = JSON.parse(await readFile(p.meta, "utf8"));
    const wasm = new Uint8Array(await readFile(p.wasm));
    return { ...meta, wasm };
  } catch {
    return null;
  }
}
