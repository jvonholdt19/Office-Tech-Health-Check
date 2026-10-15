import { parseWebsiteTarget, runWebsiteScan } from "../lib/website-scan.js";
import { authorize, send, retryAfter } from "../lib/private-api.js";
import { audit } from "../lib/audit.js";

// Private endpoint: GET /api/website?target=example.com → passive Website Security Check report.
// Technician session + per-session rate limit come from authorize(); on top of that, any one site can
// be checked at most 3 times a minute (across all sessions), so the tool can't be used to hammer it.
export const TARGET_LIMIT = { max: 3, windowSeconds: 60 };

export default async function handler(req, res) {
  if (req.method !== "GET") return send(res, 405, { error: "Use GET /api/website?target=example.com" }, { Allow: "GET" });
  const ctx = await authorize(req, res);
  if (!ctx) return;
  const url = new URL(req.url, "http://localhost");
  const parsed = parseWebsiteTarget(url.searchParams.get("target") || "");
  if (parsed.error) return send(res, 400, { error: parsed.error });
  const host = parsed.host;

  let hit;
  try {
    hit = await ctx.store.hit(`website-target:${host}`, TARGET_LIMIT.windowSeconds);
  } catch (err) {
    console.warn(`[rate-limit] store unavailable: ${err.message}`);
    return send(res, 503, { error: "Couldn't reach the rate-limit store. Try again in a minute." });
  }
  if (hit.count > TARGET_LIMIT.max) {
    return send(res, 429, { error: `${host} was checked several times in the last minute. Wait a minute and try again.` }, { "Retry-After": retryAfter(hit.resetAt) });
  }

  try {
    const report = await runWebsiteScan(host);
    if (report.error) return send(res, 400, { error: report.error });
    // Summary only: never the page HTML or response headers in bulk.
    await audit("website_scan", { sid: ctx.sid, ip: ctx.ip, ua: ctx.ua, domain: host, data: { score: report.score, grade: report.grade, counts: report.counts, durationMs: report.durationMs } }, ctx.store);
    return send(res, 200, report);
  } catch (err) {
    console.error("website scan failed", host, err);
    return send(res, 500, { error: "The website check failed unexpectedly. Please try again." });
  }
}
