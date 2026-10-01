import { normalizeDomain } from "../lib/domain.js";
import { runScan } from "../lib/scan.js";

// Best-effort, per-instance rate limit. Good enough to stop casual abuse.
// Move to a shared store (e.g. Supabase or Upstash) if the tool gets popular.
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 10;
const hits = new Map();

function rateLimited(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) hits.clear();
  return recent.length > MAX_PER_WINDOW;
}

function send(res, status, body, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return send(res, 405, { error: "Use GET /api/scan?domain=example.com" }, { Allow: "GET" });
  }
  const url = new URL(req.url, "http://localhost");
  const parsed = normalizeDomain(url.searchParams.get("domain") || "");
  if (parsed.error) return send(res, 400, { error: parsed.error });

  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  if (rateLimited(ip)) {
    return send(res, 429, { error: "Too many scans in a short time. Please wait a minute and try again." }, { "Retry-After": "60" });
  }

  try {
    const report = await runScan(parsed.domain);
    return send(res, 200, report, { "Cache-Control": "public, s-maxage=300, stale-while-revalidate=600" });
  } catch (err) {
    console.error("scan failed", parsed.domain, err);
    return send(res, 500, { error: "The scan failed unexpectedly. Please try again." });
  }
}
