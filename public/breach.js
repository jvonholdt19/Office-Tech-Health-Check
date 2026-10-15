// Breach Check (/tools/breach): technician only, and off until the server's BREACH_CHECK_ENABLED
// switch is on (the page then shows "not available yet"; /api/breach answers 404 either way).
// Results come from XposedOrNot and Have I Been Pwned and are inserted with textContent only.
// Passwords: hashed with SHA-1 in this browser; only the first 5 hex characters of the hash are
// sent (k-anonymity). The password and the full hash never leave the page.
import { $, h, api, showError, initGate, featureEnabled } from "./tech-session.js";

/** SHA-1 of `text` as 40 uppercase hex characters (Web Crypto). */
export async function sha1Hex(text, subtle = globalThis.crypto.subtle) {
  const digest = await subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

/** k-anonymity split: the 5-character prefix that is sent, and the 35-character suffix that never is. */
export function splitHash(hash) {
  return { prefix: hash.slice(0, 5), suffix: hash.slice(5) };
}

/** How many times `suffix` appears in a range answer ("<SUFFIX>:<count>" lines). Padding lines count 0. */
export function countFor(suffixes, suffix) {
  for (const line of suffixes || []) {
    const [s, n] = String(line).split(":");
    if (s === suffix) return Number(n) || 0;
  }
  return 0;
}

/**
 * Check a password: hash it here, send only the prefix to /api/breach?range=, look the suffix up
 * locally. Returns { count } or { error }.
 */
export async function checkPassword(password, { apiFn = api, subtle } = {}) {
  const { prefix, suffix } = splitHash(await sha1Hex(password, subtle));
  const { res, body } = await apiFn(`/api/breach?range=${prefix}`);
  if (!res.ok) return { error: body.error || "The password check failed. Try again." };
  return { count: countFor(body.suffixes, suffix) };
}

const WHAT_TO_DO = (breachNames) => [
  "Reset the password for this account, and anywhere else the same password was used.",
  "Turn on 2-step sign-in (multi-factor authentication) for this account.",
  `Watch for phishing: be wary of emails that mention ${breachNames} or ask to "verify" the account or a payment.`,
];

function unverifiedNotice(domain, reason) {
  return h("div", { class: "verify-first", role: "note" },
    h("h3", {}, "Verify this domain in XposedOrNot first"),
    reason === "not-verified"
      ? h("p", {}, `XposedOrNot didn't return ${domain} for the API key on file: the domain isn't verified on that account yet, or the key was reset.`)
      : h("p", {}, `There's no XposedOrNot API key on file for ${domain} yet.`),
    h("ol", { class: "steps" },
      h("li", {}, "Sign in at xposedornot.com and open the CxO Dashboard."),
      h("li", {}, `Add ${domain} and complete the domain verification it asks for.`),
      h("li", {}, `Open API Key Management, copy the key, and send it to whoever manages the Vercel settings to add to XON_DOMAIN_KEYS as "${domain}".`),
      h("li", {}, "Then check the domain again here."),
    ),
  );
}

function breachLine(b) {
  const types = b.dataTypes?.length ? `: ${b.dataTypes.join(", ")}` : "";
  return h("li", {}, h("strong", {}, b.name), b.year ? ` (${b.year})` : "", types);
}

function addressCard(a) {
  const names = a.breaches.map((b) => b.name).join(", ");
  return h("article", { class: "check breach-address", "data-status": "fail" },
    h("div", { class: "check-head" },
      h("span", { class: "status", "data-status": "fail" }, `${a.breaches.length} breach${a.breaches.length === 1 ? "" : "es"}`),
      h("h4", { class: "check-title" }, a.email),
    ),
    h("ul", { class: "breach-list" }, a.breaches.map(breachLine)),
    h("p", { class: "breach-todo-title" }, h("strong", {}, "What to do")),
    h("ol", { class: "steps" }, WHAT_TO_DO(names).map((step) => h("li", {}, step))),
  );
}

/** The domain result, built with h() (textContent only). */
export function renderDomainResult(r) {
  if (r.status === "unverified") return [unverifiedNotice(r.domain, r.reason)];
  const when = new Date(r.checkedAt).toLocaleString();
  if (!r.count) {
    return [
      h("p", { class: "breach-summary", "data-status": "pass" }, h("span", { class: "pill", "data-status": "pass" }, "Good"), ` No addresses on ${r.domain} appear in known breaches.`),
      h("p", { class: "report-foot" }, `Checked ${when}. Results aren't saved.`),
    ];
  }
  return [
    h("p", { class: "breach-summary" }, h("span", { class: "pill", "data-status": "fail" }, "At risk"), ` ${r.count} address${r.count === 1 ? "" : "es"} on ${r.domain} appear${r.count === 1 ? "s" : ""} in ${r.breachCount} known breach${r.breachCount === 1 ? "" : "es"}.`),
    h("div", { class: "check-grid" }, r.addresses.map(addressCard)),
    h("p", { class: "report-foot" }, `Checked ${when}. Results aren't saved; passwords and breach records are never shown.`),
  ];
}

async function runDomainCheck(value) {
  showError("breach-error", "");
  $("breach-report").hidden = true;
  $("breach-loading").hidden = false;
  $("breach-btn").disabled = true;
  try {
    const { res, body } = await api(`/api/breach?domain=${encodeURIComponent(value)}`);
    if (res.status === 401) return; // the gate is shown again by api()
    if (!res.ok) return showError("breach-error", body.error || "The breach check failed. Try again.");
    $("breach-report").replaceChildren(...renderDomainResult(body));
    $("breach-report").hidden = false;
  } catch {
    showError("breach-error", "Couldn't reach the server.");
  } finally {
    $("breach-loading").hidden = true;
    $("breach-btn").disabled = false;
  }
}

async function runPasswordCheck() {
  const input = $("password-input");
  const password = input.value;
  input.value = ""; // don't keep it in the page
  showError("password-error", "");
  $("password-result").hidden = true;
  if (!password) return;
  $("password-btn").disabled = true;
  try {
    const r = await checkPassword(password);
    if (r.error) return showError("password-error", r.error);
    const out = $("password-result");
    out.dataset.status = r.count ? "fail" : "pass";
    out.textContent = r.count
      ? `Seen ${r.count.toLocaleString()} time${r.count === 1 ? "" : "s"} in breaches. Don't use this password anywhere; change it wherever it's used.`
      : "Not found in known breaches. That's good, but it's no guarantee: use a long, unique password for every account.";
    out.hidden = false;
  } catch {
    showError("password-error", "The password check failed. Try again.");
  } finally {
    $("password-btn").disabled = false;
  }
}

if (typeof document !== "undefined" && $("breach-form")) {
  $("breach-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("breach-domain").value.trim();
    if (v) runDomainCheck(v);
  });
  $("password-form").addEventListener("submit", (e) => {
    e.preventDefault();
    runPasswordCheck();
  });
  initGate({
    contentId: "tool",
    onSignedIn: () => {
      const on = featureEnabled("breachCheck");
      $("breach-off").hidden = on;
      $("breach-on").hidden = !on;
      if (on) $("breach-domain").focus();
    },
    onSignedOut: () => {
      $("breach-report").hidden = true;
      $("password-result").hidden = true;
    },
  });
}
