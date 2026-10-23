// Public endpoint for the lander: GET /api/preview?domain=example.com → { domain, grade, items }.
// No sign-in, so it is protected by durable limits in the shared store (Supabase rate_limit_hit),
// never an in-memory fallback: if the store is unavailable the endpoint fails closed with 503.
//   per client:  5 per 10 minutes and 20 per day (IPv4 address, or the IPv6 /64 prefix)
//   per domain:  3 per 10 minutes (across all visitors)
//   global:      300 per hour (bounds cost)
// The per-client limits are checked first, on their own. Only a request they allow touches the
// per-domain and global counters, so one client over its own limit can't use up the global cap or
// lock a domain for everyone else.
// Audit: a preview_scan event is written at most once per client per hour ({ ip, domain, grade } only),
// so audit_log volume stays bounded. No CORS headers are set; GET only; no cookies are read.
import { consentGiven, CONSENT_REQUIRED } from "../lib/consent.js";
import { isIP } from "node:net";
import { normalizeDomain } from "../lib/domain.js";
import { runPreview } from "../lib/preview.js";
import { getStore } from "../lib/store.js";
import { audit, requestContext } from "../lib/audit.js";
import { send, retryAfter } from "../lib/private-api.js";

/** The 8 hextets of an IPv6 address (handles "::" and a dotted IPv4 tail), or null. */
function ipv6Hextets(address) {
  let a = String(address).split("%")[0].toLowerCase();
  const tail = [];
  const v4 = a.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [b0, b1, b2, b3] = v4.slice(1).map(Number);
    tail.push((b0 << 8) | b1, (b2 << 8) | b3);
    a = a.slice(0, -v4[0].length);
    if (a.endsWith(":") && !a.endsWith("::")) a = a.slice(0, -1);
  }
  const [headPart, restPart] = a.includes("::") ? a.split("::") : [a, null];
  const head = headPart ? headPart.split(":").filter(Boolean).map((x) => parseInt(x, 16)) : [];
  const rest = restPart ? restPart.split(":").filter(Boolean).map((x) => parseInt(x, 16)) : [];
  const fill = 8 - head.length - rest.length - tail.length;
  if (fill < 0 || (restPart === null && fill !== 0)) return null;
  return [...head, ...new Array(restPart === null ? 0 : fill).fill(0), ...rest, ...tail];
}

/**
 * Rate-limit key for a client address: IPv4 as is; IPv6 by its /64 prefix (one customer network
 * usually gets a whole /64, so per-address limits would be trivial to dodge). IPv4-mapped IPv6
 * (::ffff:192.0.2.1) is treated as the IPv4 address.
 */
export function clientKey(ip) {
  const family = isIP(String(ip).split("%")[0]);
  if (family === 4) return String(ip);
  if (family !== 6) return String(ip);
  const h = ipv6Hextets(ip);
  if (!h) return String(ip);
  if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff) return `${h[6] >> 8}.${h[6] & 255}.${h[7] >> 8}.${h[7] & 255}`;
  return `${h.slice(0, 4).map((x) => x.toString(16)).join(":")}::/64`;
}

// Stage 1: per client. Stage 2 (only for requests stage 1 allows): per domain and global.
export const CLIENT_LIMITS = [
  { key: (c) => `preview-ip:${c.client}`, windowSeconds: 600, max: 5, message: "Too many checks from your connection. Please wait a few minutes." },
  { key: (c) => `preview-ip-day:${c.client}`, windowSeconds: 86_400, max: 20, message: "Daily limit reached for your connection. Please try again tomorrow." },
];
export const SHARED_LIMITS = [
  { key: (c) => `preview-domain:${c.domain}`, windowSeconds: 600, max: 3, message: "That domain was checked several times in the last few minutes. Please wait a little." },
  { key: () => "preview-global", windowSeconds: 3600, max: 300, message: "The preview is busy right now. Please try again later." },
];
export const PREVIEW_LIMITS = [...CLIENT_LIMITS, ...SHARED_LIMITS];

/** Count one hit against each limit; returns the 429 to send, or null when every limit allows it. */
async function checkLimits(store, limits, ctx) {
  const hits = await Promise.all(limits.map((l) => store.hit(l.key(ctx), l.windowSeconds)));
  const over = limits.map((l, i) => ({ l, h: hits[i] })).filter(({ l, h }) => h.count > l.max);
  if (!over.length) return null;
  return { message: over[0].l.message, resetAt: Math.max(...over.map(({ h }) => h.resetAt)) };
}

let runOverride = null;
/** Tests replace the scan (no network) here, like setStoreForTests. */
export function setPreviewRunnerForTests(fn) {
  runOverride = fn;
}

export default async function handler(req, res) {
  if (req.method !== "GET") return send(res, 405, { error: "Use GET /api/preview?domain=example.com" }, { Allow: "GET" });
  const url = new URL(req.url, "http://localhost");
  const parsed = normalizeDomain(url.searchParams.get("domain") || "");
  if (parsed.error) return send(res, 400, { error: parsed.error });
  if (!consentGiven(url)) return send(res, 400, { error: CONSENT_REQUIRED });
  const store = getStore();
  if (!store) return send(res, 503, { error: "The preview is unavailable right now. Please try again later." });

  const { ip } = requestContext(req);
  const ctx = { ip, client: clientKey(ip), domain: parsed.domain };
  let limited;
  try {
    limited = (await checkLimits(store, CLIENT_LIMITS, ctx)) || (await checkLimits(store, SHARED_LIMITS, ctx));
  } catch (err) {
    console.warn(`[rate-limit] store unavailable: ${err.message}`);
    return send(res, 503, { error: "The preview is unavailable right now. Please try again later." });
  }
  if (limited) return send(res, 429, { error: limited.message }, { "Retry-After": retryAfter(limited.resetAt) });

  try {
    const result = await (runOverride || runPreview)(parsed.domain);
    try {
      const gate = await store.hit(`preview-audit:${ctx.client}`, 3600);
      if (gate.count === 1) await audit("preview_scan", { ip, domain: parsed.domain, data: { grade: result.grade, consent: true } }, store);
    } catch (err) {
      console.warn(`[audit] preview gate unavailable: ${err.message}`);
    }
    return send(res, 200, { domain: result.domain, grade: result.grade, items: result.items.map(({ id, title, status }) => ({ id, title, status })) });
  } catch (err) {
    console.error("preview failed", parsed.domain, err);
    return send(res, 500, { error: "The check failed unexpectedly. Please try again." });
  }
}
