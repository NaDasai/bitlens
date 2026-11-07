// Landing-page hero: replays a real BitLens run on the built-in
// vulnerable-vault demo, on a loop. The data below is that run's report
// (npm run attack -- vulnerable-vault.bitlens-demo --json), trimmed to the
// two results shown: the drain that broke and the takeover that was refused.
// Nothing runs in the sim here, so the landing page stays static and fast.
import { replayPanel } from "/replay.js";

const RUN = {
  contract: "vulnerable-vault.bitlens-demo",
  accounts: { attacker: "attacker.near", owner: "owner.near", user: "user.near", victim: "victim.near" },
  results: [
    {
      id: "unauth:admin_drain",
      name: "Unauthorised call to admin_drain",
      status: "broken",
      explanation: "A non-owner call to `admin_drain` succeeded and moved +67.8015 NEAR into attacker.near's account (the contract's balance changed by -67.8015 NEAR). Anyone can call it.",
      event_sequence: [
        { block: 10, from: "attacker.near", to: "vulnerable-vault.bitlens-demo", action: "call admin_drain", deposit_near: "0.0000", ok: true, detail: "ok" },
        { block: 11, from: "vulnerable-vault.bitlens-demo", to: "attacker.near", action: "Transfer", deposit_near: "67.8015", ok: true, detail: "ok" },
      ],
      token_deltas: {
        "attacker.near": { near: "+67.8015 NEAR" },
        "vulnerable-vault.bitlens-demo": { near: "-67.8015 NEAR" },
      },
    },
    {
      id: "unauth:set_owner",
      name: "Unauthorised call to set_owner",
      status: "held",
      explanation: "A non-owner call to `set_owner` was rejected: panicked: only the owner can call this",
      event_sequence: [
        { block: 10, from: "attacker.near", to: "vulnerable-vault.bitlens-demo", action: "call set_owner", deposit_near: "0.0000", ok: false, detail: "FAILED: panicked: only the owner can call this" },
      ],
      token_deltas: {},
    },
  ],
};

/** One short line for the end of each replay, taken from the run itself. */
function endText(r) {
  const method = r.event_sequence[0]?.action.replace(/^call /, "") ?? "";
  if (r.status === "broken") return `anyone can call ${method}: the attacker walked away with ${r.token_deltas["attacker.near"]?.near ?? "NEAR"}.`;
  const why = r.event_sequence.find((e) => !e.ok)?.detail.replace(/^FAILED:\s*(panicked:\s*)?/, "") ?? "rejected";
  return `${method} by a stranger was rejected: "${why}".`;
}

const box = document.getElementById("hero-replay");
const title = document.getElementById("hero-attack-name");
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
const PAUSE_MS = 2600;

let index = 0;
let visible = true;
let waiting = false; // a replay finished while the hero was off screen

function show(i, final = false) {
  const r = RUN.results[i];
  title.textContent = r.name;
  const panel = replayPanel(r, RUN.accounts, RUN.contract, {
    controls: false,
    maxLog: 2,
    endText,
    onFinish: final ? undefined : () => setTimeout(advance, PAUSE_MS),
  });
  box.replaceChildren(panel);
  if (final) panel.showFinal();
  else panel.start();
}

function advance() {
  if (!visible || document.hidden) {
    waiting = true;
    return;
  }
  waiting = false;
  index = (index + 1) % RUN.results.length;
  show(index);
}

function resume() {
  if (waiting && visible && !document.hidden) advance();
}

if (box && title) {
  if (REDUCED) {
    // No motion: the drain's end state, without a loop.
    show(0, true);
  } else {
    show(0);
    new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      resume();
    }).observe(box);
    document.addEventListener("visibilitychange", resume);
  }
}
