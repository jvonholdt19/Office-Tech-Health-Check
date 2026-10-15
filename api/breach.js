import { normalizeDomain } from "../lib/domain.js";
import { authorize, send, retryAfter } from "../lib/private-api.js";
import { audit } from "../lib/audit.js";
import { breachCheckEnabled } from "../lib/features.js";
import { checkDomainBreaches, passwordRange } from "../lib/breach.js";

// Private endpoint (technician session), only while BREACH_CHECK_ENABLED is exactly "true":
//   GET /api/breach?domain=example.com → breached addresses for a domain verified in XposedOrNot
//   GET /api/breach?range=ABCDE        → Pwned Passwords suffixes for a 5-character SHA-1 prefix
// Switched off it answers 404 to everyone, before the session check and before any outside call.
// Nothing is stored; the audit log gets the tool, the domain, the number of breached addresses and
// the time (breach_check), and nothing at all for password checks.

// XposedOrNot's free tier allows 25 domain-breach calls an hour and 50 a day (per IP); stay under it.
export const BREACH_LIMITS = [
  { key: (d) => `breach-domain:${d}`, max: 3, windowSeconds: 60, message: (d) => `${d} was checked several times in the last minute. Wait a minute and try again.` },
  { key: () => "breach-xon-hour", max: 20, windowSeconds: 3600, message: () => "The hourly limit for breach checks was reached. Try again later." },
  { key: () => "breach-xon-day", max: 45, windowSeconds: 86_400, message: () => "The daily limit for breach checks was reached. Try again tomorrow." },
];

export default async function handler(req, res) {
  if (!breachCheckEnabled()) return send(res, 404, { error: "Not found." });
  if (req.method !== "GET") return send(res, 405, { error: "Use GET /api/breach?domain=example.com" }, { Allow: "GET" });
  const ctx = await authorize(req, res);
  if (!ctx) return;
  const url = new URL(req.url, "http://localhost");

  if (url.searchParams.has("range")) {
    const r = await passwordRange(url.searchParams.get("range"));
    if (!r.ok) return send(res, /exactly the first 5/.test(r.error) ? 400 : 502, { error: r.error });
    return send(res, 200, r);
  }

  const parsed = normalizeDomain(url.searchParams.get("domain") || "");
  if (parsed.error) return send(res, 400, { error: parsed.error });
  const domain = parsed.domain;

  for (const limit of BREACH_LIMITS) {
    let hit;
    try {
      hit = await ctx.store.hit(limit.key(domain), limit.windowSeconds);
    } catch (err) {
      console.warn(`[rate-limit] store unavailable: ${err.message}`);
      return send(res, 503, { error: "Couldn't reach the rate-limit store. Try again in a minute." });
    }
    if (hit.count > limit.max) return send(res, 429, { error: limit.message(domain) }, { "Retry-After": retryAfter(hit.resetAt) });
  }

  try {
    const result = await checkDomainBreaches(domain);
    if (result.status === "error") return send(res, 502, { error: result.error }, result.retryAfter ? { "Retry-After": String(result.retryAfter) } : {});
    if (result.status === "unverified") return send(res, 200, { domain, status: "unverified", reason: result.reason });
    await audit("breach_check", { domain, data: { count: result.count } }, ctx.store);
    return send(res, 200, { domain, status: "ok", checkedAt: new Date().toISOString(), count: result.count, breachCount: result.breachCount, addresses: result.addresses });
  } catch (err) {
    console.error("breach check failed", domain, err?.message);
    return send(res, 500, { error: "The breach check failed unexpectedly. Please try again." });
  }
}
