import { normalizeDomain } from "../lib/domain.js";
import { runScan } from "../lib/scan.js";
import { authorize, send } from "../lib/private-api.js";
import { audit } from "../lib/audit.js";

// Private endpoint (technician session): GET /api/scan?domain=acme.com → the full email & domain report.
// The public lander uses /api/preview instead. Rate limiting is the durable per-session limit in
// authorize(); the old in-memory per-IP limiter is gone.
export default async function handler(req, res) {
  if (req.method !== "GET") return send(res, 405, { error: "Use GET /api/scan?domain=example.com" }, { Allow: "GET" });
  const auth = await authorize(req, res);
  if (!auth) return;
  const url = new URL(req.url, "http://localhost");
  const parsed = normalizeDomain(url.searchParams.get("domain") || "");
  if (parsed.error) return send(res, 400, { error: parsed.error });
  try {
    const report = await runScan(parsed.domain, scanDeps);
    await audit("scan", { sid: auth.sid, ip: auth.ip, ua: auth.ua, domain: parsed.domain, data: { score: report.score, grade: report.grade, counts: report.counts, durationMs: report.durationMs } }, auth.store);
    return send(res, 200, report);
  } catch (err) {
    console.error("scan failed", parsed.domain, err);
    return send(res, 500, { error: "The scan failed unexpectedly. Please try again." });
  }
}

let scanDeps = {};
/** Tests replace the network layer here. */
export function setScanDepsForTests(deps) {
  scanDeps = deps || {};
}
