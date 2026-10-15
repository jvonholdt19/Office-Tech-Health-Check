// Audit log for the technician tools. Every event is written as one structured JSON line to the
// function logs and, when Supabase is configured, appended to the audit_log table (newest 5000 kept).
// Events: login_success, login_failure, logout, plan_build, plan_confirm, verify, website_scan.
// website_scan logs only the target host and a summary (score, grade, counts, durationMs), never page HTML or headers.
// Never log access codes or uploaded zone contents (uploads are logged by SHA-256 and size only).

import { getStore } from "./store.js";

const listeners = new Set();

/** Tests subscribe here to see events as they're emitted. Returns an unsubscribe function. */
export function onAudit(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** IP and user agent for the audit trail. x-real-ip is set by Vercel; the leftmost x-forwarded-for is client-controlled. */
export function requestContext(req) {
  const ip = String(req.headers?.["x-real-ip"] || req.socket?.remoteAddress || "unknown").trim().slice(0, 64);
  const ua = String(req.headers?.["user-agent"] || "").slice(0, 512);
  return { ip, ua };
}

export async function audit(event, fields = {}, store = getStore()) {
  const entry = { audit: true, ts: new Date().toISOString(), event, ...fields };
  console.log(JSON.stringify(entry));
  for (const fn of listeners) fn(entry);
  if (store) {
    try {
      await store.audit(entry);
    } catch (err) {
      console.warn(`[audit] couldn't store ${event}: ${err.message}`);
    }
  }
  return entry;
}
