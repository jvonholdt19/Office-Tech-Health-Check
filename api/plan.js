import { timingSafeEqual, createHash } from "node:crypto";
import { normalizeDomain } from "../lib/domain.js";
import { runScan } from "../lib/scan.js";
import { buildPlan } from "../lib/plan.js";

// Private endpoint: GET /api/plan?domain=acme.com with header "x-plan-passcode".
// The passcode comes from the PLAN_PASSCODE environment variable in Vercel.
// If it isn't set, the endpoint stays locked.

const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 10;
const MAX_BAD_PASSCODES = 5;
const hits = new Map();
const failures = new Map();

function tooMany(map, ip, limit) {
  const now = Date.now();
  const recent = (map.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  map.set(ip, recent);
  if (map.size > 5000) map.clear();
  return recent.length >= limit;
}
const record = (map, ip) => map.set(ip, [...(map.get(ip) || []), Date.now()]);

/** Constant-time comparison so the passcode can't be guessed character by character. */
export function passcodeMatches(given, expected) {
  if (!given || !expected) return false;
  const a = createHash("sha256").update(String(given)).digest();
  const b = createHash("sha256").update(String(expected)).digest();
  return timingSafeEqual(a, b);
}

function send(res, status, body, extra = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Robots-Tag", "noindex");
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

export default async function handler(req, res) {
  if (req.method !== "GET") return send(res, 405, { error: "Use GET" }, { Allow: "GET" });

  const expected = process.env.PLAN_PASSCODE;
  if (!expected || expected.length < 8) {
    return send(res, 503, { error: "Fix plans are locked. Set a PLAN_PASSCODE (8+ characters) in Vercel → Project → Settings → Environment Variables, then redeploy." });
  }

  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  if (tooMany(failures, ip, MAX_BAD_PASSCODES)) {
    return send(res, 429, { error: "Too many wrong passcodes. Wait a minute and try again." }, { "Retry-After": "60" });
  }
  if (!passcodeMatches(req.headers["x-plan-passcode"], expected)) {
    record(failures, ip);
    return send(res, 401, { error: "Wrong passcode." });
  }
  if (tooMany(hits, ip, MAX_PER_WINDOW)) {
    return send(res, 429, { error: "Too many plans in a short time. Wait a minute." }, { "Retry-After": "60" });
  }
  record(hits, ip);

  const url = new URL(req.url, "http://localhost");
  const parsed = normalizeDomain(url.searchParams.get("domain") || "");
  if (parsed.error) return send(res, 400, { error: parsed.error });

  try {
    const report = await runScan(parsed.domain);
    const plan = buildPlan(report);
    return send(res, 200, { report, plan });
  } catch (err) {
    console.error("plan failed", parsed.domain, err);
    return send(res, 500, { error: "Couldn't build the plan. Please try again." });
  }
}
