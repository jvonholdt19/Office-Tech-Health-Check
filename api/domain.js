import { normalizeDomain } from "../lib/domain.js";
import { runDomainScan } from "../lib/domain-scan.js";
import { authorize, send, retryAfter } from "../lib/private-api.js";
import { audit } from "../lib/audit.js";

// Private endpoint: GET /api/domain?domain=example.com → Domain Health report (passive DNS + RDAP).
// Technician session + per-session limit from authorize(); any one domain at most 3 times a minute.
export const DOMAIN_LIMIT = { max: 3, windowSeconds: 60 };

export default async function handler(req, res) {
  if (req.method !== "GET") return send(res, 405, { error: "Use GET /api/domain?domain=example.com" }, { Allow: "GET" });
  const ctx = await authorize(req, res);
  if (!ctx) return;
  const url = new URL(req.url, "http://localhost");
  const parsed = normalizeDomain(url.searchParams.get("domain") || "");
  if (parsed.error) return send(res, 400, { error: parsed.error });
  const domain = parsed.domain;

  let hit;
  try {
    hit = await ctx.store.hit(`domain-target:${domain}`, DOMAIN_LIMIT.windowSeconds);
  } catch (err) {
    console.warn(`[rate-limit] store unavailable: ${err.message}`);
    return send(res, 503, { error: "Couldn't reach the rate-limit store. Try again in a minute." });
  }
  if (hit.count > DOMAIN_LIMIT.max) {
    return send(res, 429, { error: `${domain} was checked several times in the last minute. Wait a minute and try again.` }, { "Retry-After": retryAfter(hit.resetAt) });
  }

  try {
    const report = await runDomainScan(domain);
    if (report.error) return send(res, 400, { error: report.error });
    await audit("domain_scan", { sid: ctx.sid, ip: ctx.ip, ua: ctx.ua, domain, data: { score: report.score, grade: report.grade, counts: report.counts, durationMs: report.durationMs } }, ctx.store);
    return send(res, 200, report);
  } catch (err) {
    console.error("domain scan failed", domain, err);
    return send(res, 500, { error: "The domain check failed unexpectedly. Please try again." });
  }
}
