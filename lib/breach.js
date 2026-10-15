// Breach Check (technician tool, off unless BREACH_CHECK_ENABLED=true; see lib/features.js).
//
// 1. Domain breaches from XposedOrNot's free domain monitoring. The domain must be verified in the
//    XposedOrNot dashboard; its API key lives server-side in XON_DOMAIN_KEYS (a JSON map of domain →
//    key) and is only ever sent to api.xposedornot.com in the x-api-key header. One key covers every
//    domain verified on that XposedOrNot account, so the answer is filtered to the domain asked for.
//    Only the address, breach name, year and the kinds of data exposed are passed on: never
//    passwords, descriptions or anything else from the response.
// 2. Pwned Passwords (Have I Been Pwned) k-anonymity range lookups: the browser hashes the password
//    with SHA-1 and sends only the first 5 hex characters here; this proxies that prefix to
//    api.pwnedpasswords.com and returns the list of matching suffixes for the browser to search.
//
// Nothing is stored. Outbound calls go through fetchApi (https, exact host allowlist, vetted IP,
// TLS verified, no redirects).
import { fetchApi } from "./net.js";

export const XON_HOST = "api.xposedornot.com";
export const HIBP_HOST = "api.pwnedpasswords.com";
export const ALLOWED_HOSTS = [XON_HOST, HIBP_HOST];
export const XON_DOMAIN_BREACHES_URL = `https://${XON_HOST}/v1/domain-breaches/`;
export const HIBP_RANGE_URL = `https://${HIBP_HOST}/range/`;

let testDeps = {};
/** Tests (and only tests) replace the network layer here, like setStoreForTests. */
export function setBreachDepsForTests(deps) {
  testDeps = deps || {};
}
const deps = () => ({ fetchApi, ...testDeps });

/**
 * The XposedOrNot API key for `domain` from XON_DOMAIN_KEYS ({"example.com": "key", ...}), or null.
 * A missing or malformed variable means "not configured"; the value is never logged.
 */
export function domainKey(domain, env = process.env) {
  const raw = env.XON_DOMAIN_KEYS;
  if (!raw) return null;
  let map;
  try {
    map = JSON.parse(raw);
  } catch {
    console.warn("[breach] XON_DOMAIN_KEYS isn't valid JSON; treating every domain as not configured.");
    return null;
  }
  if (!map || typeof map !== "object" || Array.isArray(map)) return null;
  for (const [d, key] of Object.entries(map)) {
    if (String(d).trim().toLowerCase() === domain && typeof key === "string" && key.trim()) return key.trim();
  }
  return null;
}

const text = (v, max = 200) => String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);

/** "Email addresses;Passwords" or ["Email addresses", "Passwords"] → a clean, de-duplicated list. */
function dataTypes(xposed) {
  const list = Array.isArray(xposed) ? xposed : String(xposed ?? "").split(";");
  return [...new Set(list.map((t) => text(t, 60)).filter(Boolean))].slice(0, 20);
}

function breachYear(date) {
  const m = String(date ?? "").match(/\b(19|20)\d{2}\b/);
  return m ? Number(m[0]) : null;
}

/**
 * Reduce XposedOrNot's domain-breaches answer to what the report shows, for `domain` only:
 * { verified, addresses: [{ email, breaches: [{ name, year, dataTypes }] }], count, breachCount }.
 * `verified` is false when the key's account doesn't include this domain.
 */
export function summarizeDomainBreaches(json, domain) {
  const metrics = json?.metrics || {};
  const verifiedDomains = Object.keys(metrics.Domain_Summary || {}).map((d) => d.toLowerCase());
  if (!verifiedDomains.includes(domain)) return { verified: false, addresses: [], count: 0, breachCount: 0 };
  const info = metrics.Detailed_Breach_Info || {};
  const byEmail = new Map();
  for (const row of Array.isArray(metrics.Breaches_Details) ? metrics.Breaches_Details : []) {
    const email = text(row?.email, 254).toLowerCase();
    if (text(row?.domain).toLowerCase() !== domain || !email.endsWith(`@${domain}`)) continue;
    const name = text(row?.breach, 120);
    if (!name) continue;
    const detail = info[row.breach] || {};
    const breaches = byEmail.get(email) || new Map();
    breaches.set(name, { name, year: breachYear(detail.breached_date), dataTypes: dataTypes(detail.xposed_data) });
    byEmail.set(email, breaches);
  }
  const addresses = [...byEmail]
    .map(([email, breaches]) => ({ email, breaches: [...breaches.values()].sort((a, b) => (b.year || 0) - (a.year || 0) || a.name.localeCompare(b.name)) }))
    .sort((a, b) => b.breaches.length - a.breaches.length || a.email.localeCompare(b.email));
  const breachCount = new Set(addresses.flatMap((a) => a.breaches.map((b) => b.name))).size;
  return { verified: true, addresses, count: addresses.length, breachCount };
}

/**
 * Domain breach check. Returns one of:
 * { status: "unverified", reason: "not-configured" | "not-verified" }  (no key, or XposedOrNot doesn't know the domain for that key)
 * { status: "ok", addresses, count, breachCount }
 * { status: "error", error, retryAfter? }
 */
export async function checkDomainBreaches(domain, { env = process.env } = {}) {
  const key = domainKey(domain, env);
  if (!key) return { status: "unverified", reason: "not-configured" };
  const r = await deps().fetchApi(XON_DOMAIN_BREACHES_URL, {
    allowedHosts: ALLOWED_HOSTS,
    method: "POST",
    headers: { "x-api-key": key, "Content-Length": "0", Accept: "application/json" },
    timeoutMs: 10_000,
    maxBytes: 5_000_000,
  });
  if (!r.ok) return { status: "error", error: "Couldn't reach XposedOrNot. Try again in a few minutes." };
  if (r.status === 401 || r.status === 403) return { status: "unverified", reason: "not-verified" };
  if (r.status === 429) return { status: "error", error: "XposedOrNot's free limit was reached (25 checks an hour, 50 a day). Try again later.", retryAfter: Number(r.headers?.["retry-after"]) || null };
  if (r.status !== 200 || r.truncated) return { status: "error", error: "XposedOrNot didn't return a usable answer. Try again later." };
  let json;
  try {
    json = JSON.parse(r.body);
  } catch {
    return { status: "error", error: "XposedOrNot didn't return a usable answer. Try again later." };
  }
  const summary = summarizeDomainBreaches(json, domain);
  if (!summary.verified) return { status: "unverified", reason: "not-verified" };
  return { status: "ok", addresses: summary.addresses, count: summary.count, breachCount: summary.breachCount };
}

export const PREFIX_RE = /^[0-9A-F]{5}$/;

/**
 * Pwned Passwords range lookup for a 5-character SHA-1 prefix (k-anonymity). Returns
 * { ok: true, prefix, suffixes: ["<35 hex>:<count>", ...] } or { ok: false, error }.
 * Padding is requested so the response size doesn't hint at the prefix.
 */
export async function passwordRange(prefixInput) {
  const prefix = String(prefixInput ?? "").toUpperCase();
  if (!PREFIX_RE.test(prefix)) return { ok: false, error: "Send exactly the first 5 characters of the SHA-1 hash." };
  const r = await deps().fetchApi(HIBP_RANGE_URL + prefix, {
    allowedHosts: ALLOWED_HOSTS,
    headers: { "Add-Padding": "true", Accept: "text/plain" },
    timeoutMs: 8000,
    maxBytes: 1_000_000,
  });
  if (!r.ok || r.status !== 200 || r.truncated) return { ok: false, error: "Couldn't reach Have I Been Pwned. Try again in a few minutes." };
  const suffixes = r.body
    .split(/\r?\n/)
    .map((l) => l.trim().toUpperCase())
    .filter((l) => /^[0-9A-F]{35}:\d+$/.test(l));
  return { ok: true, prefix, suffixes };
}
