// NEAR X-Ray web UI: address → /scan → risk card.
// Everything from the contract (method names etc.) is untrusted, so the DOM is
// built with textContent only. No innerHTML anywhere.

const $ = (s) => document.querySelector(s);
const form = $("#scan-form");
const input = $("#account");
const btn = $("#scan-btn");
const statusEl = $("#status");
const cardEl = $("#card");

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
        `${c.rpc_network ?? c.source} · block ${c.block_height ?? "–"} · ${(c.code_size_bytes / 1024).toFixed(0)} KiB`,
      ),
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
