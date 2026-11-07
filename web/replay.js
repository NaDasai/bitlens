// Attack replay: the receipt chain of one result, played back as an animated
// timeline. Each account is a card with a live net-NEAR counter; each receipt
// is a token that travels from sender to receiver (gold = NEAR moving, red =
// failed). Built from the report's event_sequence and token_deltas only; all
// text goes through textContent (contract data is untrusted).

const REDUCED = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const amount = (s) => Number.parseFloat(s) || 0;
const fmt = (n) => `${n > 0 ? "+" : n < 0 ? "−" : ""}${Math.abs(n).toFixed(4)} NEAR`;

function actionLabel(e) {
  const a = String(e.action);
  if (a.startsWith("call ")) return `${a.slice(5)}()`;
  if (a === "DeleteAccount") return "delete account";
  if (a === "Transfer") return "transfer";
  return a.length > 28 ? a.slice(0, 27) + "…" : a;
}

/**
 * @param {object} r one entry of report.results
 * @param {Record<string,string>} accounts report.accounts (role → account id)
 * @param {string} contract the contract under test
 * @param {{controls?: boolean, maxLog?: number, endText?: (r: object) => string, onFinish?: () => void}} [opts]
 *   controls: show play/pause/step/speed (default true); maxLog: keep only the last N log rows;
 *   endText: replaces the explanation shown at the end; onFinish: called when the last receipt has played.
 */
export function replayPanel(r, accounts, contract, opts = {}) {
  // Chronological: stable sort by block shows same-block races side by side.
  const events = r.event_sequence.map((e, i) => ({ ...e, i })).sort((a, b) => a.block - b.block || a.i - b.i);
  const roleOf = Object.fromEntries(Object.entries(accounts).map(([role, id]) => [id, role]));
  const ids = [...new Set(events.flatMap((e) => [e.from, e.to]))];
  // Contract in the middle, the people around it: attacker on the left.
  const people = ids.filter((id) => id !== contract);
  const left = people.filter((id) => roleOf[id] === "attacker");
  const right = people.filter((id) => roleOf[id] !== "attacker");
  const order = [...left, ...(ids.includes(contract) ? [contract] : []), ...right];

  const root = el("div", "replay");
  const stage = el("div", "replay-stage");
  const lanes = el("div", "replay-lanes");
  const fly = el("div", "replay-fly");
  stage.append(lanes, fly);

  const nodes = new Map();
  for (const id of order) {
    const node = el("div", `replay-node ${id === contract ? "contract" : roleOf[id] || "other"}`);
    node.append(el("div", "rn-role", id === contract ? "contract" : roleOf[id] || "account"), el("div", "rn-id", id));
    const bal = el("div", "rn-bal", fmt(0));
    node.append(bal);
    lanes.append(node);
    nodes.set(id, { node, bal, value: 0 });
  }

  const log = el("ol", "replay-log");
  log.setAttribute("aria-live", "polite");
  const end = el("div", "replay-end");

  const controls = el("div", "replay-controls");
  const playBtn = el("button", "rp-play", "▶ Play");
  const stepBtn = el("button", "rp-step", "Step");
  const speedBtn = el("button", "rp-speed", "1×");
  const restartBtn = el("button", "rp-restart", "↺ Restart");
  for (const b of [playBtn, stepBtn, speedBtn, restartBtn]) b.type = "button";
  const progress = el("span", "rp-progress", `0 / ${events.length}`);
  controls.append(playBtn, stepBtn, speedBtn, restartBtn, progress);

  if (opts.controls === false) root.classList.add("compact");
  root.append(...(opts.controls === false ? [] : [controls]), stage, log, end);

  let next = 0; // index of the next event to play
  let playing = false;
  let busy = false;
  let speed = 1;
  let run = 0; // bumps on restart, so a stale playback loop stops

  const center = (id) => {
    const s = stage.getBoundingClientRect();
    const b = nodes.get(id).node.getBoundingClientRect();
    return { x: b.left - s.left + b.width / 2, y: b.top - s.top + b.height / 2 };
  };

  function setBalance(id, value, animate) {
    const n = nodes.get(id);
    if (!n) return;
    const from = n.value;
    n.value = value;
    n.node.classList.toggle("up", value > 0.00005);
    n.node.classList.toggle("down", value < -0.00005);
    if (!animate || REDUCED) {
      n.bal.textContent = fmt(value);
      return;
    }
    const t0 = performance.now();
    const dur = 600 / speed;
    const tick = (t) => {
      const k = Math.min(1, (t - t0) / dur);
      n.bal.textContent = fmt(from + (value - from) * (1 - (1 - k) ** 3));
      if (k < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
    n.node.animate?.([{ transform: "scale(1)" }, { transform: "scale(1.06)" }, { transform: "scale(1)" }], { duration: 380 / speed });
  }

  async function travel(e, myRun) {
    const amt = amount(e.deposit_near);
    const token = el("div", `replay-token ${!e.ok ? "bad" : amt > 0 ? "near" : "call"}`, amt > 0 ? `${e.deposit_near} NEAR` : actionLabel(e));
    fly.append(token);
    let a = center(e.from);
    let b = center(e.to);
    // Side by side: fly from the sender's edge to the receiver's edge, so the
    // token crosses the gap instead of covering the cards' text.
    if (e.from !== e.to && Math.abs(b.x - a.x) > Math.abs(b.y - a.y)) {
      const s = stage.getBoundingClientRect();
      const ra = nodes.get(e.from).node.getBoundingClientRect();
      const rb = nodes.get(e.to).node.getBoundingClientRect();
      const right = b.x > a.x;
      a = { x: (right ? ra.right : ra.left) - s.left, y: a.y };
      b = { x: (right ? rb.left : rb.right) - s.left, y: b.y };
    }
    const place = (p) => `translate(${p.x}px, ${p.y}px) translate(-50%, -50%)`;
    if (REDUCED) {
      token.style.transform = place(b);
      await sleep(250 / speed);
    } else if (e.from === e.to) {
      // A contract calling itself (callback): a small loop above its card.
      const up = { x: a.x, y: a.y - 46 };
      await token.animate([{ transform: place(a), opacity: 0 }, { transform: place(up), opacity: 1 }, { transform: place(a), opacity: 0.9 }], { duration: 900 / speed, easing: "ease-in-out", fill: "forwards" }).finished;
    } else if (!e.ok) {
      // Failed: stops halfway, shakes, fades.
      const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
      await token.animate([{ transform: place(a) }, { transform: place(mid) }], { duration: 600 / speed, easing: "ease-out", fill: "forwards" }).finished;
      await token.animate(
        [0, -7, 7, -5, 5, 0].map((dx) => ({ transform: `${place(mid)} translateX(${dx}px)` })),
        { duration: 420 / speed, fill: "forwards" },
      ).finished;
      await sleep(250 / speed);
    } else {
      await token.animate([{ transform: place(a) }, { transform: place(b) }], { duration: (amt > 0 ? 1100 : 800) / speed, easing: "cubic-bezier(.45,.05,.3,1)", fill: "forwards" }).finished;
    }
    if (myRun !== run) return token.remove();
    token.animate?.([{ opacity: 1 }, { opacity: 0 }], { duration: 250 / speed, fill: "forwards" }).finished.then(() => token.remove());
  }

  function logRow(e) {
    const li = el("li", e.ok ? "" : "bad");
    li.append(el("span", "blk", `#${e.block}`), el("code", "", e.from), document.createTextNode(" → "), el("code", "", e.to), document.createTextNode(` ${e.action}`));
    if (amount(e.deposit_near) > 0) li.append(el("span", "amt", ` ${e.deposit_near} NEAR`));
    li.append(e.ok ? document.createTextNode(" ✓") : el("span", "fail", ` ✗ ${e.detail}`));
    for (const old of log.querySelectorAll("li.now")) old.classList.remove("now");
    li.classList.add("now");
    log.append(li);
    while (opts.maxLog && log.children.length > opts.maxLog) log.firstElementChild.remove();
  }

  async function playOne() {
    if (busy || next >= events.length) return;
    busy = true;
    const myRun = run;
    const e = events[next++];
    progress.textContent = `${next} / ${events.length}`;
    logRow(e);
    await travel(e, myRun);
    if (myRun !== run) return;
    const amt = amount(e.deposit_near);
    if (e.ok && amt > 0 && e.from !== e.to) {
      if (nodes.has(e.from)) setBalance(e.from, nodes.get(e.from).value - amt, true);
      if (nodes.has(e.to)) setBalance(e.to, nodes.get(e.to).value + amt, true);
    }
    if (next >= events.length) finish();
    busy = false;
  }

  function finish() {
    // The report's net deltas are authoritative (they also cover anything the
    // event list summarises), so the cards end on exactly those numbers.
    for (const [id, d] of Object.entries(r.token_deltas || {})) if (nodes.has(id)) setBalance(id, amount(d.near.replace(/\s*NEAR$/, "")), true);
    const verdict = { broken: "BROKEN", held: "HELD", inconclusive: "INCONCLUSIVE", not_applicable: "N/A", error: "ERROR" }[r.status] || r.status;
    end.replaceChildren(el("span", `st ${r.status}`, verdict), document.createTextNode(` ${opts.endText ? opts.endText(r) : r.explanation}`));
    end.classList.add("shown");
    playing = false;
    playBtn.textContent = "▶ Play";
    opts.onFinish?.();
  }

  async function loop() {
    const myRun = run;
    while (playing && myRun === run && next < events.length) {
      await playOne();
      await sleep(320 / speed);
    }
  }

  function reset() {
    run++;
    playing = false;
    busy = false;
    next = 0;
    fly.replaceChildren();
    log.replaceChildren();
    end.replaceChildren();
    end.classList.remove("shown");
    for (const id of nodes.keys()) setBalance(id, 0, false);
    progress.textContent = `0 / ${events.length}`;
    playBtn.textContent = "▶ Play";
  }

  playBtn.addEventListener("click", () => {
    if (next >= events.length) reset();
    playing = !playing;
    playBtn.textContent = playing ? "⏸ Pause" : "▶ Play";
    if (playing) loop();
  });
  stepBtn.addEventListener("click", () => {
    playing = false;
    playBtn.textContent = "▶ Play";
    if (next >= events.length) reset();
    playOne();
  });
  speedBtn.addEventListener("click", () => {
    speed = speed === 1 ? 2 : speed === 2 ? 0.5 : 1;
    speedBtn.textContent = `${speed}×`;
  });
  restartBtn.addEventListener("click", () => {
    reset();
    playing = true;
    playBtn.textContent = "⏸ Pause";
    loop();
  });

  /** Start playing (used when the panel opens). */
  root.start = () => {
    reset();
    playing = true;
    playBtn.textContent = "⏸ Pause";
    // Wait a frame so the cards have their positions before tokens fly.
    requestAnimationFrame(() => loop());
  };
  root.stop = () => reset();
  /** Jump to the end without animation (reduced motion, or a static snapshot). */
  root.showFinal = () => {
    reset();
    for (const e of events) logRow(e);
    next = events.length;
    progress.textContent = `${next} / ${events.length}`;
    finish();
  };
  return root;
}
