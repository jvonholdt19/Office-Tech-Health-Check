// Durable storage for the technician tools: rate limits and the audit log, in Supabase.
// Used only by the serverless functions, through Supabase's REST API (PostgREST) with the
// service-role key. Both env vars are server-only: never NEXT_PUBLIC_*, never shipped to public/.
//
//   SUPABASE_URL               https://<project>.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY  service-role (or sb_secret_...) key
//
// Tables and functions: supabase/migrations/20261013000000_dns_scanner.sql
// When either env var is missing, getStore() returns null and the technician endpoints fail closed.

import { withTimeout } from "./net.js";

let override; // tests inject a store (or null) here
let warned = false;

export function setStoreForTests(store) {
  override = store;
}

export function getStore() {
  if (override !== undefined) return override;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    if (!warned) {
      warned = true;
      console.warn("[store] SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are not set: technician endpoints are locked (503) until they are.");
    }
    return null;
  }
  return supabaseStore(url, key);
}

/** Store backed by the Supabase REST API. `fetchImpl` is injectable for tests. */
export function supabaseStore(url, key, fetchImpl = globalThis.fetch) {
  const base = String(url).replace(/\/+$/, "");
  const headers = { apikey: key, "Content-Type": "application/json", Accept: "application/json" };
  // Legacy service-role keys are JWTs and go in Authorization too; new sb_secret_ keys only in apikey.
  if (/^eyJ/.test(key)) headers.Authorization = `Bearer ${key}`;

  async function rpc(fn, body) {
    const res = await withTimeout(fetchImpl(`${base}/rest/v1/rpc/${fn}`, { method: "POST", headers, body: JSON.stringify(body) }), 4000, `Supabase ${fn}`);
    if (!res.ok) throw new Error(`Supabase ${fn} HTTP ${res.status}`);
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }

  return {
    kind: "supabase",
    /** Add `increment` hits to `key`'s current window; returns { count, resetAt (ms) }. */
    async hit(key_, windowSeconds, increment = 1) {
      const rows = await rpc("rate_limit_hit", { p_key: key_, p_window_seconds: windowSeconds, p_increment: increment });
      const row = Array.isArray(rows) ? rows[0] : rows;
      return { count: Number(row?.hits ?? 0), resetAt: new Date(row?.reset_at ?? Date.now()).getTime() };
    },
    async audit(event) {
      await rpc("audit_append", { p_event: event });
    },
  };
}

/** In-memory store with the same interface (tests, and the local dev server when asked to). */
export function memoryStore() {
  const windows = new Map();
  const events = [];
  return {
    kind: "memory",
    events,
    async hit(key, windowSeconds, increment = 1) {
      const now = Date.now();
      let w = windows.get(key);
      if (!w || w.resetAt <= now) w = { count: 0, resetAt: now + windowSeconds * 1000 };
      w.count += increment;
      windows.set(key, w);
      return { count: w.count, resetAt: w.resetAt };
    },
    async audit(event) {
      events.push(event);
      if (events.length > 5000) events.splice(0, events.length - 5000);
    },
  };
}
