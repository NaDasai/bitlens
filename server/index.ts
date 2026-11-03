/**
 * HTTP front door — a thin wrapper over core/. No scan/attack logic here.
 *   GET  /health
 *   GET  /scan?account_id=wrap.near
 *   POST /scan   {"account_id":"wrap.near"}
 *   GET  /       static web UI (web/)
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scan, toErrorPayload } from "../core/index.js";

const PORT = Number(process.env.PORT ?? 8787);
const WEB_DIR = resolve(fileURLToPath(new URL("../web/", import.meta.url)));
const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
};

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body, null, 2));
}

async function readJson(req: IncomingMessage): Promise<any> {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 64 * 1024) throw new Error("request body too large");
  }
  return raw ? JSON.parse(raw) : {};
}

async function serveStatic(pathname: string, res: ServerResponse) {
  const rel = normalize(pathname === "/" ? "/index.html" : pathname).replace(/^(\.\.[/\\])+/, "");
  const file = join(WEB_DIR, rel);
  if (!file.startsWith(WEB_DIR)) return sendJson(res, 403, { error: { code: "FORBIDDEN", message: "forbidden" } });
  try {
    const data = await readFile(file);
    res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
    res.end(data);
  } catch {
    sendJson(res, 404, { error: { code: "NOT_FOUND", message: `no route ${pathname}` } });
  }
}

export const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  try {
    if (url.pathname === "/health") return sendJson(res, 200, { ok: true });

    if (url.pathname === "/scan") {
      const accountId =
        req.method === "POST" ? (await readJson(req)).account_id : url.searchParams.get("account_id");
      const card = await scan(accountId); // validates account_id
      return sendJson(res, 200, card);
    }

    if (req.method === "GET") return serveStatic(url.pathname, res);
    return sendJson(res, 405, { error: { code: "METHOD_NOT_ALLOWED", message: req.method } });
  } catch (e) {
    const { status, body } = toErrorPayload(e);
    return sendJson(res, status, body);
  }
});

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  server.listen(PORT, () => {
    console.log(`NEAR X-Ray backend on http://localhost:${PORT}  (try: curl "http://localhost:${PORT}/scan?account_id=wrap.near")`);
  });
}
