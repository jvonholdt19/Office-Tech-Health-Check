// Technician sessions: a signed, HttpOnly cookie instead of a passcode kept in the browser.
//   ohc_tech=<base64url(JSON {sid, iat, exp})>.<base64url(HMAC-SHA256(payload, SESSION_SECRET))>
// The access code (TECH_ACCESS_CODE, or PLAN_PASSCODE during migration) is only ever compared
// on the server; it is never sent back to, or stored in, the browser.

import { createHmac, randomBytes, timingSafeEqual, createHash } from "node:crypto";

export const COOKIE_NAME = "ohc_tech";
export const SESSION_SECONDS = 8 * 60 * 60;
const MIN_SECRET = 32;
const MIN_CODE = 8;

/** SESSION_SECRET, or null when it's missing or shorter than 32 characters (fail closed). */
export function sessionSecret() {
  const s = process.env.SESSION_SECRET;
  return s && s.length >= MIN_SECRET ? s : null;
}

/** TECH_ACCESS_CODE, falling back to PLAN_PASSCODE while deployments migrate. Null if unset or too short. */
export function accessCode() {
  const c = process.env.TECH_ACCESS_CODE || process.env.PLAN_PASSCODE;
  return c && c.length >= MIN_CODE ? c : null;
}

/** Constant-time comparison (hashing first so lengths don't leak). */
export function codeMatches(given, expected) {
  if (!given || !expected) return false;
  const a = createHash("sha256").update(String(given)).digest();
  const b = createHash("sha256").update(String(expected)).digest();
  return timingSafeEqual(a, b);
}

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const sign = (payload, secret) => createHmac("sha256", secret).update(payload).digest("base64url");

export function newSession(now = Date.now()) {
  const iat = Math.floor(now / 1000);
  return { sid: randomBytes(16).toString("hex"), iat, exp: iat + SESSION_SECONDS };
}

export function encodeSession(session, secret) {
  const payload = b64url(JSON.stringify(session));
  return `${payload}.${sign(payload, secret)}`;
}

/** Verify a cookie value's signature and expiry. Returns the session or null. */
export function decodeSession(value, secret, now = Date.now()) {
  if (!value || !secret) return null;
  const [payload, sig, extra] = String(value).split(".");
  if (!payload || !sig || extra !== undefined) return null;
  const expected = Buffer.from(sign(payload, secret));
  const given = Buffer.from(sig);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  let s;
  try {
    s = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  const t = Math.floor(now / 1000);
  if (!s || typeof s.sid !== "string" || !Number.isInteger(s.exp) || !Number.isInteger(s.iat)) return null;
  if (s.exp <= t || s.iat > t + 60 || s.exp - s.iat > SESSION_SECONDS) return null;
  return s;
}

export function readCookie(req, name = COOKIE_NAME) {
  for (const part of String(req.headers?.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

export function sessionFromRequest(req, secret = sessionSecret(), now = Date.now()) {
  return decodeSession(readCookie(req), secret, now);
}

export function setCookieHeader(value) {
  return `${COOKIE_NAME}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=${SESSION_SECONDS}`;
}

export function clearCookieHeader() {
  return `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=0`;
}

/**
 * CSRF guard for state-changing requests: the Origin header must be present and match the host
 * the request was sent to. (SameSite=Strict on the cookie is the first line of defence.)
 */
export function originAllowed(req) {
  const origin = req.headers?.origin;
  const host = req.headers?.host || req.headers?.["x-forwarded-host"];
  if (!origin || !host) return false;
  try {
    return new URL(origin).host.toLowerCase() === String(host).split(",")[0].trim().toLowerCase();
  } catch {
    return false;
  }
}
