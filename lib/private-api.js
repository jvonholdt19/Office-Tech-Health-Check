// Shared plumbing for the private (passcode-protected) endpoints: /api/plan and /api/verify.
import { timingSafeEqual, createHash } from "node:crypto";

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

export function send(res, status, body, extra = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Robots-Tag", "noindex");
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

/** Checks the passcode and rate limits. Sends the error response and returns false when the request must stop. */
export function authorize(req, res, { limit = MAX_PER_WINDOW } = {}) {
  const expected = process.env.PLAN_PASSCODE;
  if (!expected || expected.length < 8) {
    send(res, 503, { error: "Fix plans are locked. Set a PLAN_PASSCODE (8+ characters) in Vercel → Project → Settings → Environment Variables, then redeploy." });
    return false;
  }
  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  if (tooMany(failures, ip, MAX_BAD_PASSCODES)) {
    send(res, 429, { error: "Too many wrong passcodes. Wait a minute and try again." }, { "Retry-After": "60" });
    return false;
  }
  if (!passcodeMatches(req.headers["x-plan-passcode"], expected)) {
    record(failures, ip);
    send(res, 401, { error: "Wrong passcode." });
    return false;
  }
  if (tooMany(hits, ip, limit)) {
    send(res, 429, { error: "Too many requests in a short time. Wait a minute." }, { "Retry-After": "60" });
    return false;
  }
  record(hits, ip);
  return true;
}

/** Read a JSON body (Vercel may have parsed it already). Zone files can be large, so allow up to ~2.5 MB. */
export async function readJson(req, maxBytes = 2_500_000) {
  if (req.body !== undefined && req.body !== null && req.body !== "") {
    if (typeof req.body === "object" && !Buffer.isBuffer(req.body)) return req.body;
    const s = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : String(req.body);
    if (s.length > maxBytes) throw Object.assign(new Error("The upload is too large."), { status: 413 });
    return JSON.parse(s);
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error("The upload is too large."), { status: 413 });
    chunks.push(chunk);
  }
  const s = Buffer.concat(chunks).toString("utf8");
  return s ? JSON.parse(s) : {};
}

/** Wrap the live network functions so the dry run reuses the website/registry results instead of repeating them. */
export function cachedDeps(deps) {
  const memo = (fn) => {
    const cache = new Map();
    return (...args) => {
      const k = JSON.stringify(args);
      if (!cache.has(k)) cache.set(k, fn(...args));
      return cache.get(k);
    };
  };
  return { ...deps, inspectTls: memo(deps.inspectTls), probeHttp: memo(deps.probeHttp), fetchRdap: memo(deps.fetchRdap) };
}
