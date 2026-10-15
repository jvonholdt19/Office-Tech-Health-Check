// Public endpoint for the lander: GET /api/preview?domain=acme.com → { domain, grade, items }.
// No sign-in, so it is protected by durable limits in the shared store (Supabase rate_limit_hit),
// never an in-memory fallback: if the store is unavailable the endpoint fails closed with 503.
//   per IP:      5 per 10 minutes and 20 per day
//   per domain:  3 per 10 minutes (across all visitors)
//   global:      300 per hour (bounds cost)
// Audit: a preview_scan event is written at most once per IP per hour ({ ip, domain, grade } only),
// so audit_log volume stays bounded. No CORS headers are set; GET only; no cookies are read.
import { normalizeDomain } from "../lib/domain.js";
import { runPreview } from "../lib/preview.js";
import { getStore } from "../lib/store.js";
import { audit, requestContext } from "../lib/audit.js";
import { send, retryAfter } from "../lib/private-api.js";

export const PREVIEW_LIMITS = [
  { key: (c) => `preview-ip:${c.ip}`, windowSeconds: 600, max: 5, message: "Too many checks from your connection. Please wait a few minutes." },
  { key: (c) => `preview-ip-day:${c.ip}`, windowSeconds: 86_400, max: 20, message: "Daily limit reached for your connection. Please try again tomorrow." },
  { key: (c) => `preview-domain:${c.domain}`, windowSeconds: 600, max: 3, message: "That domain was checked several times in the last few minutes. Please wait a little." },
  { key: () => "preview-global", windowSeconds: 3600, max: 300, message: "The preview is busy right now. Please try again later." },
];

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
  const store = getStore();
  if (!store) return send(res, 503, { error: "The preview is unavailable right now. Please try again later." });

  const { ip } = requestContext(req);
  const ctx = { ip, domain: parsed.domain };
  let hits;
  try {
    hits = await Promise.all(PREVIEW_LIMITS.map((l) => store.hit(l.key(ctx), l.windowSeconds)));
  } catch (err) {
    console.warn(`[rate-limit] store unavailable: ${err.message}`);
    return send(res, 503, { error: "The preview is unavailable right now. Please try again later." });
  }
  const over = PREVIEW_LIMITS.map((l, i) => ({ l, h: hits[i] })).filter(({ l, h }) => h.count > l.max);
  if (over.length) {
    const resetAt = Math.max(...over.map(({ h }) => h.resetAt));
    return send(res, 429, { error: over[0].l.message }, { "Retry-After": retryAfter(resetAt) });
  }

  try {
    const result = await (runOverride || runPreview)(parsed.domain);
    try {
      const gate = await store.hit(`preview-audit:${ip}`, 3600);
      if (gate.count === 1) await audit("preview_scan", { ip, domain: parsed.domain, data: { grade: result.grade } }, store);
    } catch (err) {
      console.warn(`[audit] preview gate unavailable: ${err.message}`);
    }
    return send(res, 200, { domain: result.domain, grade: result.grade, items: result.items.map(({ id, title, status }) => ({ id, title, status })) });
  } catch (err) {
    console.error("preview failed", parsed.domain, err);
    return send(res, 500, { error: "The check failed unexpectedly. Please try again." });
  }
}
