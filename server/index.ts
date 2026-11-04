/**
 * HTTP front door — a thin wrapper over core/. No scan/attack logic here.
 *   GET  /health
 *   GET  /scan?account_id=wrap.near
 *   POST /scan   {"account_id":"wrap.near"}
 *   GET  /attacks?account_id=…      suggested attack scenarios (no sim run)
 *   POST /attack {"account_id","scenario_ids"?}   run them in near-contract-sim
 *   GET  /engine                     attack-engine warm-up status
 *   POST /attack {"account_id","scenarios":[…]}  run custom scenario JSON instead
 *   POST /translate {"account_id","sentence"}    English → scenario JSON (NEAR AI Cloud, fallback OpenRouter)
 *   GET  /llm                        text-to-test LLM configuration (never the key)
 *   GET  /       landing page;  GET /app  the web app (static, web/)
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  InputError,
  llmStatus,
  scan as scanCard,
  translateToScenario,
  engineStatus,
  EngineNotReadyError,
  listAttacks,
  runAttacks,
  scan,
  startWarmup,
  toErrorPayload,
  verdictOf,
  warmReady,
  warmupSpec,
} from "../core/index.js";

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
    if (raw.length > 64 * 1024) throw new InputError("request body larger than 64 KB");
  }
  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    throw new InputError("request body is not valid JSON");
  }
}

async function serveStatic(pathname: string, res: ServerResponse) {
  const page = pathname === "/" ? "/index.html" : pathname === "/app" || pathname === "/app/" ? "/app.html" : pathname;
  const rel = normalize(page).replace(/^(\.\.[/\\])+/, "");
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

    if (url.pathname === "/engine") return sendJson(res, 200, engineStatus());

    if (url.pathname === "/llm") return sendJson(res, 200, llmStatus());

    if (url.pathname === "/translate" && req.method === "POST") {
      const body = await readJson(req);
      const card = await scanCard(body.account_id); // validates account_id
      const t = await translateToScenario(body.sentence, card);
      return sendJson(res, 200, { account_id: card.account_id, ...t });
    }

    if (url.pathname === "/attacks") {
      const { card, attacks } = await listAttacks(url.searchParams.get("account_id") ?? "");
      return sendJson(res, 200, { account_id: card.account_id, attacks });
    }

    if (url.pathname === "/attack" && req.method === "POST") {
      const body = await readJson(req);
      if (body.scenario_ids !== undefined && !(Array.isArray(body.scenario_ids) && body.scenario_ids.every((s: unknown) => typeof s === "string")))
        return sendJson(res, 400, { error: { code: "BAD_REQUEST", message: "scenario_ids must be an array of strings" } });
      if (body.scenarios !== undefined && !Array.isArray(body.scenarios))
        return sendJson(res, 400, { error: { code: "BAD_REQUEST", message: "scenarios must be an array of scenario objects" } });
      if (!warmReady()) {
        const st = engineStatus();
        throw new EngineNotReadyError(`Attack engine still warming up (${st.state}${st.detail ? `: ${st.detail}` : ""}, ${st.elapsed_s}s). Retry shortly; /scan works meanwhile.`);
      }
      const { card, report } = await runAttacks(body.account_id, body.scenario_ids, { custom: body.scenarios });
      return sendJson(res, 200, { report, ...verdictOf(card, report) });
    }

    if (req.method === "GET") return serveStatic(url.pathname, res);
    return sendJson(res, 405, { error: { code: "METHOD_NOT_ALLOWED", message: req.method } });
  } catch (e) {
    const { status, body } = toErrorPayload(e);
    return sendJson(res, status, body);
  }
});

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // Warm the attack engine in the background; never block startup.
  void startWarmup((m) => console.log(m), warmupSpec);
  server.listen(PORT, () => {
    console.log(`BitLens backend on http://localhost:${PORT}  (try: curl "http://localhost:${PORT}/scan?account_id=wrap.near")`);
  });
}
