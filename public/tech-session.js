// Shared by the technician pages under /tools: the h() builder, the /api fetch helper and the
// access-code gate. Same pattern as plan.js: the code is sent once to /api/session, which sets an
// HttpOnly cookie; nothing secret is kept in the page or in browser storage. All remote text goes
// in through textContent (h() never uses innerHTML).

export const $ = (id) => document.getElementById(id);

/** Tiny element builder: h("p", { class: "x" }, "text", child, ...) */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

let onExpired = () => {};

export async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== "/api/session") onExpired();
  return { res, body: json };
}

export function showError(id, msg) {
  $(id).textContent = msg || "";
  $(id).hidden = !msg;
}

/**
 * Header chrome for the signed-in state (markup in scripts/site-chrome.js): the tools nav (#tech-nav,
 * which holds #lock-btn) shows only while signed in; "Back to home" (#gate-home) only on the gate.
 */
export function showSignedInChrome(on) {
  for (const [id, show] of [["tech-nav", on], ["gate-home", !on]]) {
    const el = $(id);
    if (el) el.hidden = !show;
  }
  applyFeatures();
}

// Feature switches (lib/features.js) as reported by GET/POST /api/session for a signed-in technician.
// Unknown or missing means off: gated tools stay "Coming soon" and their pages say "not available yet".
let features = {};

/** Keep the switches from a /api/session answer (booleans only). */
export function rememberFeatures(value) {
  features = value && typeof value === "object" ? Object.fromEntries(Object.entries(value).map(([k, v]) => [k, v === true])) : {};
}

/** True only when the server said this switch is on. The server enforces it either way. */
export function featureEnabled(name) {
  return features[name] === true;
}

/** In the Tools menu, swap "Coming soon" for the link on tools whose switch is on (markup in scripts/site-chrome.js). */
export function applyFeatures(doc = typeof document === "undefined" ? null : document) {
  if (!doc || typeof doc.querySelectorAll !== "function") return;
  for (const item of doc.querySelectorAll("[data-feature]")) {
    const on = featureEnabled(item.dataset.feature);
    const link = item.querySelector("a");
    const soon = item.querySelector(".tools-menu-soon");
    if (link) link.hidden = !on;
    if (soon) soon.hidden = on;
  }
}

/**
 * The header's Tools menu (a <details>, markup in scripts/site-chrome.js) opens and closes without
 * JS. With JS: Escape closes it and puts focus back on "Tools"; a click or focus outside closes it.
 */
export function initToolsMenu(doc = document) {
  const menu = typeof doc.querySelector === "function" ? doc.querySelector("details.tools-menu") : null;
  if (!menu) return;
  const close = () => {
    menu.open = false;
  };
  doc.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || !menu.open) return;
    close();
    menu.querySelector("summary").focus();
  });
  doc.addEventListener("click", (e) => menu.open && !menu.contains(e.target) && close());
  doc.addEventListener("focusin", (e) => menu.open && !menu.contains(e.target) && close());
}

if (typeof document !== "undefined") initToolsMenu(document);

/** How long to wait for GET /api/session before showing the sign-in form anyway. */
export const SESSION_CHECK_TIMEOUT_MS = 8000;

/**
 * Technician pages load in a neutral "checking your sign-in" state: #session-check is shown, and
 * the sign-in form, the page content, the nav and "Back to home" all start hidden. This asks
 * GET /api/session once, hides #session-check and calls show(true) (signed in) or show(false)
 * (show the sign-in form), so a signed-in technician never sees the form flash on the way to a tool.
 * If the server doesn't answer within timeoutMs the form is shown with a note; a "signed in"
 * answer that arrives later still unlocks the page.
 */
export function checkSession({ show, onError = () => {}, apiFn = api, timeoutMs = SESSION_CHECK_TIMEOUT_MS }) {
  let settled = false;
  const settle = (on, error) => {
    if (settled) {
      if (on) show(true);
      return;
    }
    settled = true;
    const panel = $("session-check");
    if (panel) panel.hidden = true;
    show(on);
    if (error) onError(error);
  };
  const timer = setTimeout(() => settle(false, "Checking your sign-in is taking a while. Sign in below, or reload the page."), timeoutMs);
  return Promise.resolve()
    .then(() => apiFn("/api/session"))
    .then(({ res, body }) => {
      if (body?.authenticated) rememberFeatures(body.features);
      settle(Boolean(body?.authenticated), !body?.authenticated && !res.ok && body?.error ? body.error : "");
    })
    .catch(() => settle(false, "Couldn't reach the server."))
    .finally(() => clearTimeout(timer));
}

/**
 * Wire up the sign-in gate. The page provides #gate, #gate-form, #access-code, #gate-error,
 * #lock-btn and a content element (`contentId`) that is shown only while signed in.
 * `onSignedIn` runs every time the content is unlocked.
 */
export function initGate({ contentId, onSignedIn = () => {}, onSignedOut = () => {} }) {
  const unlock = (on) => {
    $("gate").hidden = on;
    $(contentId).hidden = !on;
    $("lock-btn").hidden = !on;
    showSignedInChrome(on);
    if (on) onSignedIn();
    else onSignedOut();
  };
  onExpired = () => {
    unlock(false);
    showError("gate-error", "Your session has ended. Sign in again.");
  };

  $("gate-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const code = $("access-code").value;
    $("access-code").value = "";
    showError("gate-error", "");
    try {
      const { res, body } = await api("/api/session", { method: "POST", body: { code } });
      if (!res.ok) return showError("gate-error", body.error || "Couldn't sign in.");
      rememberFeatures(body.features);
    } catch {
      return showError("gate-error", "Couldn't reach the server.");
    }
    unlock(true);
  });

  $("lock-btn").addEventListener("click", async () => {
    await api("/api/session", { method: "DELETE" }).catch(() => {});
    unlock(false);
  });

  return checkSession({ show: unlock, onError: (msg) => showError("gate-error", msg) });
}
