// Shared plumbing for the private technician endpoints: /api/session, /api/plan, /api/plan/confirm, /api/verify.
// Access is a signed HttpOnly session cookie (lib/session.js); rate limits and the audit log are
// durable in Supabase (lib/store.js). Without SESSION_SECRET or Supabase the endpoints fail closed.
import { getStore } from "./store.js";
import { requestContext } from "./audit.js";
import { sessionSecret, sessionFromRequest, originAllowed, codeMatches } from "./session.js";

// Plan builds, confirmations and verifications: 30 per session per 10 minutes.
export const SESSION_LIMIT = { max: 30, windowSeconds: 600 };

/** Kept for callers that compared passcodes directly; the comparison is constant-time. */
export const passcodeMatches = codeMatches;

export function send(res, status, body, extra = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Robots-Tag", "noindex");
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

const retryAfter = (resetAt) => String(Math.max(1, Math.ceil((resetAt - Date.now()) / 1000)));

/**
 * Checks the configuration, CSRF origin, session cookie and per-session rate limit. Sends the error
 * response and returns null when the request must stop; otherwise returns { sid, ip, ua, store }.
 */
export async function authorize(req, res) {
  const secret = sessionSecret();
  if (!secret) {
    send(res, 503, { error: "Technician tools are locked: SESSION_SECRET (32+ characters) isn't set. Add it in Vercel → Project → Settings → Environment Variables, then redeploy." });
    return null;
  }
  const store = getStore();
  if (!store) {
    send(res, 503, { error: "Technician tools are locked: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY aren't set, so rate limits and the audit log can't be kept." });
    return null;
  }
  if (req.method !== "GET" && req.method !== "HEAD" && !originAllowed(req)) {
    send(res, 403, { error: "Request origin not allowed." });
    return null;
  }
  const session = sessionFromRequest(req, secret);
  if (!session) {
    send(res, 401, { error: "Sign in again: your technician session is missing or has expired." });
    return null;
  }
  let hit;
  try {
    hit = await store.hit(`session:${session.sid}`, SESSION_LIMIT.windowSeconds);
  } catch (err) {
    console.warn(`[rate-limit] store unavailable: ${err.message}`);
    send(res, 503, { error: "Couldn't reach the rate-limit store. Try again in a minute." });
    return null;
  }
  if (hit.count > SESSION_LIMIT.max) {
    send(res, 429, { error: "Too many requests in a short time. Wait a few minutes." }, { "Retry-After": retryAfter(hit.resetAt) });
    return null;
  }
  return { sid: session.sid, ...requestContext(req), store };
}

export { retryAfter };

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
