// Technician sign-in.
//   GET    /api/session          → { authenticated, expiresAt, features? } (features only when signed in)
//   POST   /api/session { code } → sets the ohc_tech session cookie (8 hours)
//   DELETE /api/session          → signs out
// The code is compared on the server only, against TECH_ACCESS_CODE (or PLAN_PASSCODE during migration).
import { send, readJson, retryAfter } from "../lib/private-api.js";
import { getStore } from "../lib/store.js";
import { audit, requestContext } from "../lib/audit.js";
import { features } from "../lib/features.js";
import { sessionSecret, accessCode, codeMatches, newSession, encodeSession, setCookieHeader, clearCookieHeader, sessionFromRequest, originAllowed } from "../lib/session.js";

// Failed sign-ins: 5 per IP per 15 minutes, and 20 across all IPs per hour.
export const LOGIN_LIMITS = { perIp: { max: 5, windowSeconds: 900 }, global: { max: 20, windowSeconds: 3600 } };

export default async function handler(req, res) {
  if (!["GET", "POST", "DELETE"].includes(req.method)) return send(res, 405, { error: "Use GET, POST or DELETE" }, { Allow: "GET, POST, DELETE" });
  const secret = sessionSecret();
  if (!secret) return send(res, 503, { error: "Technician tools are locked: SESSION_SECRET (32+ characters) isn't set." });

  if (req.method === "GET") {
    const s = sessionFromRequest(req, secret);
    return send(res, 200, { authenticated: Boolean(s), expiresAt: s ? new Date(s.exp * 1000).toISOString() : null, ...(s ? { features: features() } : {}) });
  }

  const store = getStore();
  if (!store) return send(res, 503, { error: "Technician tools are locked: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY aren't set." });
  if (!originAllowed(req)) return send(res, 403, { error: "Request origin not allowed." });
  const ctx = requestContext(req);

  if (req.method === "DELETE") {
    const s = sessionFromRequest(req, secret);
    await audit("logout", { sid: s?.sid || null, ip: ctx.ip, ua: ctx.ua }, store);
    return send(res, 200, { ok: true }, { "Set-Cookie": clearCookieHeader() });
  }

  const expected = accessCode();
  if (!expected) return send(res, 503, { error: "Technician tools are locked: TECH_ACCESS_CODE (8+ characters) isn't set." });

  const ipKey = `login-fail-ip:${ctx.ip}`;
  const globalKey = "login-fail-global";
  let ipHits;
  let globalHits;
  try {
    [ipHits, globalHits] = await Promise.all([store.hit(ipKey, LOGIN_LIMITS.perIp.windowSeconds, 0), store.hit(globalKey, LOGIN_LIMITS.global.windowSeconds, 0)]);
  } catch (err) {
    console.warn(`[rate-limit] store unavailable: ${err.message}`);
    return send(res, 503, { error: "Couldn't reach the rate-limit store. Try again in a minute." });
  }
  if (ipHits.count >= LOGIN_LIMITS.perIp.max || globalHits.count >= LOGIN_LIMITS.global.max) {
    const reset = ipHits.count >= LOGIN_LIMITS.perIp.max ? ipHits.resetAt : globalHits.resetAt;
    await audit("login_failure", { sid: null, ip: ctx.ip, ua: ctx.ua, reason: "rate-limited" }, store);
    return send(res, 429, { error: "Too many wrong codes. Wait and try again later." }, { "Retry-After": retryAfter(reset) });
  }

  let body;
  try {
    body = await readJson(req, 10_000);
  } catch {
    return send(res, 400, { error: "Couldn't read the request." });
  }
  if (!codeMatches(typeof body?.code === "string" ? body.code : "", expected)) {
    try {
      await Promise.all([store.hit(ipKey, LOGIN_LIMITS.perIp.windowSeconds), store.hit(globalKey, LOGIN_LIMITS.global.windowSeconds)]);
    } catch (err) {
      console.warn(`[rate-limit] couldn't record a failed sign-in: ${err.message}`);
    }
    await audit("login_failure", { sid: null, ip: ctx.ip, ua: ctx.ua, reason: "wrong-code" }, store);
    return send(res, 401, { error: "Wrong access code." });
  }

  const session = newSession();
  await audit("login_success", { sid: session.sid, ip: ctx.ip, ua: ctx.ua }, store);
  return send(res, 200, { authenticated: true, expiresAt: new Date(session.exp * 1000).toISOString(), features: features() }, { "Set-Cookie": setCookieHeader(encodeSession(session, secret)) });
}
