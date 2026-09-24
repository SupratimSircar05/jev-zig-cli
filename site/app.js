"use strict";

const DEFAULT_BRIDGE_PORT = 4768;
const BRIDGE_SERVICE = "jevx-local-bridge";
const BRIDGE_SCOPE = "typed-decisions-only";
const BRIDGE_VERSION = "1.0.0";
const HEALTH_TIMEOUT_MS = 1800;
const DECISION_TIMEOUT_MS = 125000;
const MAX_RESPONSE_BYTES = 65536;

const state = {
  bridgeLive: false,
  checking: false,
  deciding: false,
  bridgePort: DEFAULT_BRIDGE_PORT,
  pairingToken: "",
};

const elements = {
  badge: document.querySelector("#connection-badge"),
  connection: document.querySelector(".connection-state"),
  output: document.querySelector("#decision-output"),
  outputMode: document.querySelector("#output-mode"),
  prompt: document.querySelector("#decision-prompt"),
  policy: document.querySelector("#policy-select"),
  pairing: document.querySelector("#pairing-token"),
  run: document.querySelector("#run-decision"),
  recheck: document.querySelector("#recheck-bridge"),
  toast: document.querySelector("#copy-toast"),
  header: document.querySelector("[data-header]"),
};

function setText(element, value) {
  if (element) element.textContent = value;
}

function bridgeOrigin() {
  return `http://127.0.0.1:${state.bridgePort}`;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = HEALTH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    });
  } finally {
    window.clearTimeout(timeout);
  }
}

function setBridgeState(live) {
  state.bridgeLive = live;
  elements.connection?.classList.toggle("is-live", live);
  elements.outputMode?.classList.toggle("is-live", live);
  setText(elements.badge, live ? "LIVE LOCAL · JEVX CONNECTED" : "BROWSER DEMO · BRIDGE OFFLINE");
  setText(elements.outputMode, live ? "LIVE LOCAL · JEVX BRIDGE" : "DETERMINISTIC BROWSER DEMO · NOT REAL JEV");
}

async function checkBridge() {
  if (state.checking) return;
  state.checking = true;
  elements.recheck.disabled = true;
  setText(elements.badge, "CHECKING LOCAL BRIDGE");

  const enteredToken = elements.pairing?.value.trim() || state.pairingToken;
  if (!/^[a-f0-9]{32}$/u.test(enteredToken)) {
    state.checking = false;
    state.bridgeLive = false;
    elements.connection?.classList.remove("is-live");
    elements.outputMode?.classList.remove("is-live");
    setText(elements.badge, "ENTER THE JEVX PAIRING TOKEN");
    setText(elements.outputMode, "DETERMINISTIC BROWSER DEMO · NOT REAL JEV");
    elements.recheck.disabled = false;
    return;
  }

  try {
    const response = await fetchWithTimeout(`${bridgeOrigin()}/health`, {
      method: "GET",
      headers: {
        Accept: "application/json",
        "X-Jevx-Pairing-Token": enteredToken,
      },
    });
    if (!response.ok) throw new Error("Local bridge health check failed.");
    const health = await parseBoundedJson(response);
    if (
      !health ||
      typeof health !== "object" ||
      Array.isArray(health) ||
      health.ok !== true ||
      health.service !== BRIDGE_SERVICE ||
      health.scope !== BRIDGE_SCOPE ||
      health.version !== BRIDGE_VERSION ||
      health.port !== state.bridgePort
    ) throw new Error(`Port ${state.bridgePort} did not identify the expected jevx bridge.`);
    state.pairingToken = enteredToken;
    if (elements.pairing) {
      elements.pairing.value = "";
      elements.pairing.placeholder = "Paired for this tab";
    }
    setBridgeState(true);
  } catch {
    state.pairingToken = "";
    setBridgeState(false);
  } finally {
    state.checking = false;
    elements.recheck.disabled = false;
  }
}

function containsAny(text, words) {
  return words.some((word) => text.includes(word));
}

function deterministicDemo(prompt, policy) {
  const text = prompt.toLowerCase();
  const destructive = containsAny(text, ["delete", "erase", "wipe", "destroy", "drop database", "rm -rf", "purge"]);
  const credentials = containsAny(text, ["credential", "password", "api key", "token", "secret", "keychain"]);
  const external = containsAny(text, ["push", "publish", "release", "deploy", "send", "message", "purchase"]);
  const outsideWorkspace = containsAny(text, ["outside the workspace", "home directory", "/etc/", "system file"]);
  const write = containsAny(text, ["edit", "write", "fix", "implement", "create", "install", "format", "commit"]);
  const read = containsAny(text, ["read", "inspect", "explain", "review", "summarize", "find", "list"]);
  const underspecified = prompt.trim().split(/\s+/u).length < 6 || containsAny(text, ["do it", "fix it", "make better", "handle this"]);

  let action = "analyze";
  if (destructive) action = "destructive_operation";
  else if (external) action = "external_side_effect";
  else if (write) action = "workspace_write";
  else if (read) action = "read_only";

  const hazards = {
    destructive: destructive ? 0.97 : 0.04,
    credential_sensitive: credentials ? 0.94 : 0.03,
    external_side_effect: external ? 0.96 : 0.03,
    outside_workspace: outsideWorkspace ? 0.95 : 0.02,
    underspecified: underspecified ? 0.78 : 0.12,
  };
  const highHazard = Object.values(hazards).some((value) => value >= 0.2);
  const impact = destructive ? 1.95 : external ? 1.85 : outsideWorkspace ? 1.7 : write ? 0.9 : 0.2;

  let policyResult = "allow";
  if (destructive || credentials || external || outsideWorkspace) policyResult = "ask";
  if (containsAny(text, ["exfiltrate", "bypass sandbox", "disable policy", "steal token"])) policyResult = "deny";
  if (underspecified && policyResult === "allow") policyResult = "ask";
  if (policy === "conservative" && (write || highHazard)) policyResult = "ask";

  return {
    source: "deterministic_browser_demo_not_real_jev",
    executes_actions: false,
    action_choice: { value: action, confidence: 0.82 },
    hazard_nouls: hazards,
    impact_score: { value: impact, confidence: 0.76, scale: "0_to_2" },
    policy: { profile: policy, result: policyResult },
    note: "Illustrative fixed keyword rules only. Start `jevx web` for a live local Jev-backed decision.",
  };
}

function redactString(value) {
  return value
    .replace(/\b(sk-or-v1-|sk-)[A-Za-z0-9_-]{12,}\b/gu, "[REDACTED_CREDENTIAL]")
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+\/-]{12,}\b/giu, "$1[REDACTED]")
    .replace(/\b(?=[A-Za-z0-9_-]{32,}\b)(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[a-z])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]+\b/gu, "[REDACTED_LONG_TOKEN]");
}

function sanitizeValue(value, depth = 0) {
  if (depth > 8) return "[MAX_DEPTH]";
  if (typeof value === "string") return redactString(value).slice(0, 4000);
  if (typeof value === "number") return Number.isFinite(value) ? value : "[NON_FINITE]";
  if (typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => sanitizeValue(item, depth + 1));
  if (typeof value !== "object") return "[UNSUPPORTED_VALUE]";

  const output = {};
  const entries = Object.entries(value).slice(0, 100);
  for (const [key, item] of entries) {
    if (/^(authorization|credentials?|password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|cookie)$/iu.test(key)) {
      output[key] = "[REDACTED]";
    } else {
      output[key] = sanitizeValue(item, depth + 1);
    }
  }
  return output;
}

async function parseBoundedJson(response) {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
    throw new Error("Local bridge response exceeded 64 KiB.");
  }
  const body = await response.text();
  if (new TextEncoder().encode(body).byteLength > MAX_RESPONSE_BYTES) {
    throw new Error("Local bridge response exceeded 64 KiB.");
  }
  try {
    return JSON.parse(body);
  } catch {
    throw new Error("Local bridge returned invalid JSON.");
  }
}

function renderResult(result) {
  const safe = sanitizeValue(result);
  setText(elements.output, JSON.stringify(safe, null, 2));
}

async function runDecision() {
  if (state.deciding) return;
  const prompt = elements.prompt.value.trim();
  const policy = elements.policy.value;
  if (!prompt) {
    setText(elements.output, "Enter a prompt to evaluate.");
    elements.prompt.focus();
    return;
  }

  state.deciding = true;
  elements.run.disabled = true;
  setText(elements.run, "Evaluating…");
  setText(elements.output, state.bridgeLive ? "Waiting for the local jevx bridge…" : "Running the deterministic browser demo…");

  try {
    if (state.bridgeLive) {
      const response = await fetchWithTimeout(`${bridgeOrigin()}/v1/decide`, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-Jevx-Pairing-Token": state.pairingToken,
        },
        body: JSON.stringify({ prompt, policy }),
      }, DECISION_TIMEOUT_MS);
      if (!response.ok) throw new Error(`Local bridge returned HTTP ${response.status}.`);
      renderResult(await parseBoundedJson(response));
    } else {
      renderResult(deterministicDemo(prompt, policy));
    }
  } catch (error) {
    if (state.bridgeLive) {
      setBridgeState(false);
      renderResult({
        source: "deterministic_browser_demo_not_real_jev",
        bridge_error: error instanceof Error ? redactString(error.message) : "Local bridge request failed.",
        fallback: deterministicDemo(prompt, policy),
      });
    } else {
      renderResult({ error: error instanceof Error ? redactString(error.message) : "Decision failed." });
    }
  } finally {
    state.deciding = false;
    elements.run.disabled = false;
    setText(elements.run, "Evaluate");
  }
}

let toastTimeout = 0;
async function copyText(targetId) {
  const target = document.getElementById(targetId);
  if (!target) return;

  try {
    await navigator.clipboard.writeText(target.textContent || "");
    setText(elements.toast, "Copied to clipboard");
  } catch {
    const range = document.createRange();
    range.selectNodeContents(target);
    const selection = window.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
    setText(elements.toast, "Command selected — press Ctrl/Cmd+C");
  }

  window.clearTimeout(toastTimeout);
  elements.toast?.classList.add("is-visible");
  toastTimeout = window.setTimeout(() => elements.toast?.classList.remove("is-visible"), 2400);
}

document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", () => copyText(button.dataset.copyTarget));
});

elements.run?.addEventListener("click", runDecision);
elements.recheck?.addEventListener("click", checkBridge);
elements.pairing?.addEventListener("input", () => {
  state.pairingToken = "";
  setBridgeState(false);
});
elements.prompt?.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") runDecision();
});

window.addEventListener("scroll", () => {
  elements.header?.classList.toggle("is-scrolled", window.scrollY > 12);
}, { passive: true });

function consumePairingFragment() {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  if (!fragment.has("pairing")) return false;
  const fragmentToken = fragment.get("pairing") || "";
  const fragmentPort = Number(fragment.get("port") || DEFAULT_BRIDGE_PORT);
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  if (
    !/^[a-f0-9]{32}$/u.test(fragmentToken) ||
    !Number.isInteger(fragmentPort) ||
    fragmentPort < 1 ||
    fragmentPort > 65535 ||
    !elements.pairing
  ) return false;
  state.pairingToken = "";
  state.bridgePort = fragmentPort;
  elements.pairing.value = fragmentToken;
  return true;
}

window.addEventListener("hashchange", () => {
  if (consumePairingFragment()) checkBridge();
});

window.addEventListener("pagehide", () => {
  state.pairingToken = "";
  if (elements.pairing) elements.pairing.value = "";
});

renderResult(deterministicDemo(elements.prompt.value, elements.policy.value));
consumePairingFragment();
checkBridge();
