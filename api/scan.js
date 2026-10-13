import { normalizeDomain } from "../lib/domain.js";
import { runScan } from "../lib/scan.js";

// Best-effort, per-instance rate limit for the public scan. Good enough to stop casual abuse.
// (The technician endpoints use the durable Supabase limiter in lib/private-api.js.)
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 10;
const hits = new Map();

function rateLimited(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  hits.set(ip, recent);
  // Drop only expired entries; clearing everything would let a flood of IPs reset every limit.
  if (hits.size > 5000) for (const [k, ts] of hits) if (!ts.some((t) => now - t < WINDOW_MS)) hits.delete(k);
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

  // x-real-ip is set by Vercel; the leftmost x-forwarded-for can be chosen by the client.
  const ip = String(req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown").trim();
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
