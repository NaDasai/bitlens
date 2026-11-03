// NEAR X-Ray web UI: address → /scan → risk card.
// Everything from the contract (method names etc.) is untrusted, so the DOM is
// built with textContent only. No innerHTML anywhere.

const $ = (s) => document.querySelector(s);
const form = $("#scan-form");
const input = $("#account");
const btn = $("#scan-btn");
const statusEl = $("#status");
const cardEl = $("#card");
const attacksEl = $("#attacks");
let current = null; // account id of the card on screen

/** Tiny element builder: h("div", {class:"x"}, "text", childEl, ...) */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function setStatus(text, isError = false) {
  statusEl.textContent = text;
  statusEl.className = isError ? "error" : "";
}

async function runScan(accountId) {
  accountId = accountId.trim();
  if (!accountId) return;
  input.value = accountId;
  history.replaceState(null, "", `?account=${encodeURIComponent(accountId)}`);
  btn.disabled = true;
  cardEl.hidden = true;
  attacksEl.hidden = true;
  setStatus(`Fetching bytecode for ${accountId} via view_code…`);
  try {
    const res = await fetch(`/scan?account_id=${encodeURIComponent(accountId)}`);
    const body = await res.json();
    if (!res.ok) {
      setStatus(`${body.error?.code ?? res.status}: ${body.error?.message ?? "scan failed"}`, true);
      return;
    }
    setStatus("");
    renderCard(body);
    current = body.account_id;
    loadAttacks(body.account_id);
  } catch (e) {
    setStatus(`Could not reach the X-Ray backend: ${e.message}`, true);
  } finally {
    btn.disabled = false;
  }
}

function renderCard(c) {
  const verified =
    c.code_hash_verified === true ? " ✔ matches RPC" : c.code_hash_verified === false ? " ✘ MISMATCH vs RPC" : "";
  const head = h(
    "div",
    { class: "card-head" },
    h(
      "div",
      { class: "who" },
      h("h2", {}, c.account_id),
      h(
        "div",
        { class: "meta" },
        c.source === "demo"
          ? "built-in demo contract (local WASM, no RPC)"
          : `${c.rpc_network ?? c.source} · block ${c.block_height ?? "–"} · ${(c.code_size_bytes / 1024).toFixed(0)} KiB`,
      ),
      c.source === "cache" && h("div", { class: "meta cached" }, `⚠ RPC unreachable: showing the copy of this code fetched ${new Date(c.cached_at).toLocaleString()}`),
      h("div", { class: "meta" }, `code hash ${c.code_hash}${verified}`),
    ),
    h("div", { class: `badge ${c.risk.level}` }, `${c.risk.level.toUpperCase()} RISK`),
  );

  const summary = h(
    "div",
    { class: "summary" },
    c.risk.reasons.length
      ? h("ul", { class: "reasons" }, c.risk.reasons.map((r) => h("li", {}, r)))
      : h("div", {}, "✅ No dangerous host capabilities and no privileged-looking methods."),
  );

  const standards = h(
    "div",
    { class: "block" },
    h("h3", {}, "Standards"),
    c.standards.length
      ? h("div", { class: "chips" }, c.standards.map((s) => h("span", { class: "chip std", title: s.name }, `${s.id.toUpperCase()} · ${s.name.replace(/ \(NEP-\d+\)/, "")}`)))
      : h("div", { class: "note" }, "No NEP standards detected (custom contract)."),
  );

  const caps = [...c.capabilities].sort(
    (a, b) => Number(a.confidence === "weak") - Number(b.confidence === "weak") || sevRank(a.severity) - sevRank(b.severity),
  );
  const capabilities = h(
    "div",
    { class: "block" },
    h("h3", {}, "What it can do (WASM host imports)"),
    h("p", { class: "note" }, c.import_profile.note),
    caps.length
      ? caps.map((cap) =>
          h(
            "div",
            { class: `cap ${cap.confidence}` },
            h("div", { class: "ico" }, cap.icon),
            h(
              "div",
              { class: "lbl" },
              cap.label,
              h("span", { class: `sev ${cap.severity}` }, cap.severity),
              cap.confidence === "weak" && h("span", { class: "sev weak", title: "Linked, but no public method name points at it. Likely SDK boilerplate." }, "weak"),
            ),
            h("div", { class: "why" }, cap.why),
            h(
              "div",
              { class: "ev" },
              "evidence: ",
              cap.evidence.map((e, i) => [i ? ", " : "", h("code", {}, e)]),
              cap.corroborated_by.length ? ` · via ${cap.corroborated_by.slice(0, 4).join(", ")}` : "",
            ),
          ),
        )
      : h("div", { class: "note" }, "None. This contract cannot transfer NEAR, deploy code, add keys or make calls."),
  );

  const keys = c.access_keys
    ? h(
        "div",
        { class: "block" },
        h("h3", {}, "Account access keys"),
        h(
          "div",
          {},
          `${c.access_keys.full_access} full-access, ${c.access_keys.function_call} function-call. `,
          c.access_keys.locked
            ? "🔒 Locked: no full-access keys, so code can only change through the contract's own logic."
            : "🔑 Whoever holds a full-access key can replace this contract's code at any time.",
        ),
      )
    : null;

  const priv = c.notable_methods.filter((m) => m.privileged);
  const custom = c.notable_methods.filter((m) => !m.privileged);
  const methods = h(
    "div",
    { class: "block" },
    h("h3", {}, `Privileged-looking methods (${priv.length})`),
    priv.length
      ? h("ul", { class: "priv" }, priv.map((m) => h("li", {}, `⚠️ ${m.name} `, h("span", {}, `matches ${m.matched.join(", ")}. Check who can call it.`))))
      : h("div", { class: "note" }, "None."),
    h(
      "details",
      {},
      h("summary", {}, `All ${c.methods.length} methods (${custom.length} other custom)`),
      h("div", { class: "methods" }, c.methods.join("  ·  ")),
    ),
  );

  cardEl.replaceChildren(...[head, summary, capabilities, keys, standards, methods].filter(Boolean));
  cardEl.hidden = false;
}

function sevRank(s) {
  return { critical: 0, high: 1, medium: 2, info: 3 }[s] ?? 4;
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  runScan(input.value);
});
document.querySelectorAll(".ex").forEach((b) => b.addEventListener("click", () => runScan(b.dataset.id)));

const initial = new URLSearchParams(location.search).get("account");
if (initial) runScan(initial);

// ---------------------------------------------------------------------------
// Layer 2: attacks
// ---------------------------------------------------------------------------

const STATUS_LABEL = { held: "✅ HELD", broken: "❌ BROKEN", inconclusive: "❔ INCONCLUSIVE", not_applicable: "➖ N/A", error: "⚠️ ERROR" };
const VERDICT_LABEL = { safe: "SAFE", caution: "CAUTION", dangerous: "DANGEROUS" };

async function engineState() {
  try {
    return await (await fetch("/engine")).json();
  } catch {
    return { state: "unknown" };
  }
}

function enginePill(st) {
  const text =
    st.state === "ready"
      ? "attack engine ready"
      : st.state === "building"
        ? `attack engine building nearcore (${Math.round(st.elapsed_s / 60)} min so far; first build only)`
        : st.state === "failed"
          ? `attack engine failed: ${st.detail}`
          : `attack engine warming up (${st.elapsed_s}s)`;
  return h("span", { class: `pill ${st.state}` }, text);
}

async function loadAttacks(accountId) {
  const res = await fetch(`/attacks?account_id=${encodeURIComponent(accountId)}`);
  const body = await res.json();
  if (!res.ok || accountId !== current) return;
  const st = await engineState();
  const list = body.attacks;
  const head = h(
    "div",
    { class: "card-head" },
    h("div", { class: "who" }, h("h2", { class: "plain" }, "Attack proof"), h("div", { class: "meta" }, "Runs the real bytecode in near-contract-sim (local nearcore runtime). Nothing is sent to any network.")),
    enginePill(st),
  );
  const ai = await nearAiState();
  if (accountId !== current) return;
  if (!list.length) {
    attacksEl.replaceChildren(
      head,
      h("div", { class: "block note" }, "No attack templates apply to this contract (no privileged-looking methods, no withdraw flow, no yields)."),
      customBlock(accountId, list, ai),
    );
    attacksEl.hidden = false;
    return;
  }
  const boxes = list.map((a) =>
    h(
      "label",
      { class: "atk" },
      h("input", { type: "checkbox", value: a.id, checked: "checked" }),
      h("div", {}, h("div", { class: "lbl" }, a.name), h("div", { class: "why" }, a.description)),
    ),
  );
  const run = h("button", { id: "run-btn", type: "button" }, `Run ${list.length} attack${list.length > 1 ? "s" : ""}`);
  const results = h("div", { id: "results" });
  run.addEventListener("click", () => {
    const ids = boxes.map((b) => b.querySelector("input")).filter((i) => i.checked).map((i) => i.value);
    runAttacks(accountId, { scenario_ids: ids }, run, results);
  });
  boxes.forEach((b) =>
    b.querySelector("input").addEventListener("change", () => {
      const n = boxes.filter((x) => x.querySelector("input").checked).length;
      run.textContent = `Run ${n} attack${n === 1 ? "" : "s"}`;
      run.disabled = n === 0;
    }),
  );
  attacksEl.replaceChildren(
    head,
    h("div", { class: "block" }, h("h3", {}, `Suggested from the risk card (${list.length})`), boxes, h("div", { class: "actions" }, run)),
    results,
    customBlock(accountId, list, ai),
  );
  attacksEl.hidden = false;
}

async function runAttacks(accountId, payload, button, results) {
  button.disabled = true;
  const label = button.textContent;
  button.textContent = "Running in near-contract-sim…";
  results.replaceChildren();
  try {
    const res = await fetch("/attack", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ account_id: accountId, ...payload }),
    });
    const body = await res.json();
    if (accountId !== current) return;
    if (!res.ok) {
      results.replaceChildren(h("div", { class: "block" }, h("div", { class: "error-box" }, `${body.error?.code}: ${body.error?.message}`)));
      return;
    }
    renderResults(body, results);
  } catch (e) {
    results.replaceChildren(h("div", { class: "block" }, h("div", { class: "error-box" }, `Request failed: ${e.message}`)));
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

function renderResults(body, el) {
  const { report, verdict, reasons } = body;
  const s = report.summary;
  const verdictBox = h(
    "div",
    { class: `verdict ${verdict}` },
    h("div", { class: "v" }, VERDICT_LABEL[verdict]),
    h("div", {}, h("div", { class: "counts" }, `${s.broken} broken · ${s.held} held · ${s.inconclusive} inconclusive${s.not_applicable ? ` · ${s.not_applicable} n/a` : ""} · ${(report.duration_ms / 1000).toFixed(1)} s`), h("ul", { class: "reasons" }, reasons.map((r) => h("li", {}, r)))),
  );
  const init = h(
    "div",
    { class: "meta sim-setup" },
    `sim setup: ${report.accounts.owner} deployed and owns the contract${report.init.ok ? ` (init: ${report.init.method})` : " (no init call succeeded)"}; ${report.accounts.victim} deposited 20 NEAR; ${report.accounts.attacker} attacks.`,
  );
  const items = report.results.map((r) =>
    h(
      "div",
      { class: `result ${r.status}` },
      h("div", { class: "rhead" }, h("span", { class: `st ${r.status}` }, STATUS_LABEL[r.status]), h("span", { class: "lbl" }, r.name)),
      h("div", { class: "expl" }, r.explanation),
      r.event_sequence.length
        ? h(
            "ol",
            { class: "events" },
            r.event_sequence.map((e) =>
              h(
                "li",
                { class: e.ok ? "" : "bad" },
                h("span", { class: "blk" }, `#${e.block}`),
                h("code", {}, e.from), " → ", h("code", {}, e.to), ` ${e.action}`,
                e.deposit_near !== "0.0000" ? h("span", { class: "amt" }, ` ${e.deposit_near} NEAR`) : "",
                e.ok ? " ✓" : h("span", { class: "fail" }, ` ✗ ${e.detail}`),
              ),
            ),
          )
        : null,
      Object.keys(r.token_deltas).length
        ? h(
            "div",
            { class: "deltas" },
            "net NEAR: ",
            Object.entries(r.token_deltas).map(([who, d]) => h("span", { class: `delta ${d.near.startsWith("-") ? "neg" : "pos"}` }, `${who} ${d.near}`)),
          )
        : null,
      r.findings.length ? h("div", { class: "why" }, `sim findings: ${r.findings.join(" | ")}`) : null,
      r.trace ? h("details", {}, h("summary", {}, "full receipt trace (near-contract-sim)"), h("pre", { class: "trace" }, r.trace)) : null,
    ),
  );
  el.replaceChildren(h("div", { class: "block" }, verdictBox, init), h("div", { class: "block" }, items));
}

// ---------------------------------------------------------------------------
// Speech-to-test: plain English (typed or spoken) → scenario JSON → runner
// ---------------------------------------------------------------------------

async function nearAiState() {
  try {
    return await (await fetch("/nearai")).json();
  } catch {
    return { configured: false };
  }
}

async function postJson(url, body) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const out = await res.json();
  if (!res.ok) throw new Error(`${out.error?.code}: ${out.error?.message}`);
  return out;
}

function customBlock(accountId, presets, ai) {
  const say = h("textarea", { id: "say", rows: "2", placeholder: "e.g. the attacker calls admin_drain and keeps the money", spellcheck: "true" });
  const json = h("textarea", { id: "scenario-json", rows: "12", spellcheck: "false", placeholder: '{ "id": "custom:...", "name": "...", "steps": [ ... ], "checks": [ ... ] }' });
  const note = h("div", { class: "meta custom-note" });
  const out = h("div", { id: "custom-results" });
  const translate = h("button", { type: "button", class: "secondary", disabled: ai.configured ? false : "disabled" }, "Translate with NEAR AI");
  const runBtn = h("button", { id: "run-custom", type: "button" }, "Run this scenario");
  const canRecord = ai.configured && navigator.mediaDevices?.getUserMedia && window.MediaRecorder;
  const mic = canRecord ? h("button", { type: "button", class: "secondary mic", title: "Speak your attack (transcribed by Whisper on NEAR AI Cloud)" }, "🎤 Speak") : null;
  const pick = h(
    "select",
    { "aria-label": "Start from a preset" },
    h("option", { value: "" }, "start from a preset…"),
    presets.map((p) => h("option", { value: p.id }, p.name)),
  );
  const status = (msg, cls = "") => note.replaceChildren(h("span", { class: cls }, msg));

  pick.addEventListener("change", () => {
    const p = presets.find((x) => x.id === pick.value);
    if (p) json.value = JSON.stringify({ ...p.scenario, id: "custom:" + p.scenario.id.replace(/[^A-Za-z0-9_-]/g, "_") }, null, 2);
  });

  async function doTranslate() {
    const sentence = say.value.trim();
    if (!sentence) return status("Describe the attack first.", "warn");
    translate.disabled = true;
    status(`NEAR AI Cloud (${ai.model}) is writing the scenario JSON…`);
    try {
      const t = await postJson("/translate", { account_id: accountId, sentence });
      if (accountId !== current) return;
      json.value = JSON.stringify(t.scenario, null, 2);
      status(`Translated by ${t.model}${t.attempts > 1 ? ` (${t.attempts} attempts)` : ""}. Check the JSON, edit if you like, then run it.`, "ok");
    } catch (e) {
      status(e.message, "warn");
    } finally {
      translate.disabled = false;
    }
  }
  translate.addEventListener("click", doTranslate);

  let rec = null;
  mic?.addEventListener("click", async () => {
    if (rec) return rec.stop();
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const chunks = [];
      rec = new MediaRecorder(stream);
      rec.ondataavailable = (ev) => chunks.push(ev.data);
      rec.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        rec = null;
        mic.textContent = "🎤 Speak";
        mic.classList.remove("recording");
        const blob = new Blob(chunks, { type: chunks[0]?.type || "audio/webm" });
        status("Transcribing with Whisper on NEAR AI Cloud…");
        try {
          const res = await fetch("/transcribe", { method: "POST", headers: { "content-type": blob.type.split(";")[0] || "audio/webm" }, body: blob });
          const body = await res.json();
          if (!res.ok) throw new Error(`${body.error?.code}: ${body.error?.message}`);
          say.value = body.text;
          await doTranslate();
        } catch (e) {
          status(e.message, "warn");
        }
      };
      rec.start();
      mic.textContent = "■ Stop";
      mic.classList.add("recording");
      status("Recording… click Stop when done.");
    } catch (e) {
      status(`Microphone unavailable: ${e.message}`, "warn");
    }
  });

  runBtn.addEventListener("click", () => {
    let scenario;
    try {
      scenario = JSON.parse(json.value);
    } catch (e) {
      return status(`The scenario is not valid JSON: ${e.message}`, "warn");
    }
    status("");
    runAttacks(accountId, { scenarios: [scenario] }, runBtn, out);
  });

  status(
    ai.configured
      ? `Describe an attack (or speak it). NEAR AI Cloud (${ai.model}) translates it into scenario JSON; the same runner as the presets executes it in the local sim.`
      : "Speech-to-test is off: the server has no NEAR_AI_API_KEY. You can still write or paste scenario JSON (start from a preset), and run it.",
  );
  return h(
    "div",
    { class: "block custom" },
    h("h3", {}, "Your own attack (speech-to-test)"),
    note,
    h("div", { class: "say-row" }, say, h("div", { class: "say-btns" }, mic, translate)),
    h("div", { class: "json-head" }, h("span", { class: "meta" }, "Scenario JSON (what the runner executes)"), pick),
    json,
    h("div", { class: "actions" }, runBtn),
    out,
  );
}
