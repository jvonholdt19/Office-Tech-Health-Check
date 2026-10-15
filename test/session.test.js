// Technician sessions: server-side code check, signed HttpOnly cookie, durable rate limits, audit events.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import sessionHandler from "../api/session.js";
import planHandler from "../api/plan.js";
import { setStoreForTests, memoryStore, supabaseStore } from "../lib/store.js";
import { onAudit } from "../lib/audit.js";
import { encodeSession, newSession, decodeSession, SESSION_SECONDS } from "../lib/session.js";

const SECRET = "test-session-secret-0123456789-abcdefgh";
const CODE = "tech-code-for-tests-7f3a";
const HOST = "officetech.nwimpm.com";
let saved;
let store;
let events;
let stopAudit;

beforeEach(() => {
  saved = { ...process.env };
  process.env.SESSION_SECRET = SECRET;
  process.env.TECH_ACCESS_CODE = CODE;
  delete process.env.PLAN_PASSCODE;
  store = memoryStore();
  setStoreForTests(store);
  events = [];
  stopAudit = onAudit((e) => events.push(e));
});
afterEach(() => {
  stopAudit();
  setStoreForTests(undefined);
  for (const k of ["SESSION_SECRET", "TECH_ACCESS_CODE", "PLAN_PASSCODE"]) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

function fakeRes() {
  return {
    statusCode: 0, headers: {}, body: "",
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    end(b) { this.body = b; },
  };
}
const req = (method, { body, headers = {}, url = "/api/session" } = {}) => ({
  method, url, body, socket: {},
  headers: { host: HOST, origin: `https://${HOST}`, "x-real-ip": "203.0.113.7", "user-agent": "test-agent", ...headers },
});
async function call(handler, r) {
  const res = fakeRes();
  await handler(r, res);
  return { status: res.statusCode, headers: res.headers, json: res.body ? JSON.parse(res.body) : null };
}
const login = (code, headers) => call(sessionHandler, req("POST", { body: { code }, headers }));

test("wrong code → 401 and an audit failure event without the code", async () => {
  const r = await login("not-the-code");
  assert.equal(r.status, 401);
  assert.equal(r.headers["set-cookie"], undefined);
  const fail = events.find((e) => e.event === "login_failure");
  assert.ok(fail);
  assert.equal(fail.ip, "203.0.113.7");
  assert.equal(fail.ua, "test-agent");
  assert.ok(fail.ts);
  assert.ok(!JSON.stringify(events).includes("not-the-code"), "the code is never logged");
  assert.ok(store.events.some((e) => e.event === "login_failure"), "stored durably");
});

test("the 6th failure from one IP → 429 with Retry-After", async () => {
  for (let i = 0; i < 5; i++) assert.equal((await login(`wrong-${i}`)).status, 401);
  const sixth = await login(CODE);
  assert.equal(sixth.status, 429, "even the right code is refused while locked out");
  assert.ok(Number(sixth.headers["retry-after"]) > 0);
  assert.equal((await login(CODE, { "x-real-ip": "198.51.100.1" })).status, 200, "another IP is unaffected");
});

test("x-forwarded-for can't be used to dodge the per-IP limit", async () => {
  for (let i = 0; i < 5; i++) await login("wrong", { "x-forwarded-for": `10.0.0.${i}` });
  assert.equal((await login("wrong", { "x-forwarded-for": "10.9.9.9" })).status, 429);
});

test("success sets an HttpOnly, Secure, SameSite=Strict cookie scoped to /api for 8 hours", async () => {
  const r = await login(CODE);
  assert.equal(r.status, 200);
  const cookie = r.headers["set-cookie"];
  assert.match(cookie, /^ohc_tech=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+;/);
  for (const attr of ["HttpOnly", "Secure", "SameSite=Strict", "Path=/api", `Max-Age=${SESSION_SECONDS}`]) assert.ok(cookie.includes(attr), attr);
  assert.ok(events.some((e) => e.event === "login_success" && e.sid));
  const value = cookie.split(";")[0].slice("ohc_tech=".length);
  const who = await call(sessionHandler, req("GET", { headers: { cookie: `ohc_tech=${value}` } }));
  assert.equal(who.json.authenticated, true);
});

test("PLAN_PASSCODE still works as a fallback during migration", async () => {
  delete process.env.TECH_ACCESS_CODE;
  process.env.PLAN_PASSCODE = "legacy-passcode-123";
  assert.equal((await login("legacy-passcode-123")).status, 200);
});

test("tampered, expired or missing cookies → 401; the header passcode no longer works", async () => {
  const planReq = (cookie, extra = {}) => req("GET", { url: "/api/plan?domain=localhost", headers: { ...(cookie ? { cookie: `ohc_tech=${cookie}` } : {}), ...extra } });
  const good = encodeSession(newSession(), SECRET);
  assert.equal((await call(planHandler, planReq(good))).status, 400, "valid session reaches validation (bad domain)");

  const [payload, sig] = good.split(".");
  const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(payload, "base64url")), sid: "attacker" })).toString("base64url");
  assert.equal((await call(planHandler, planReq(`${forged}.${sig}`))).status, 401);
  assert.equal((await call(planHandler, planReq(encodeSession(newSession(), "a-different-secret-that-is-long-enough")))).status, 401);

  const old = encodeSession(newSession(Date.now() - (SESSION_SECONDS + 60) * 1000), SECRET);
  assert.equal(decodeSession(old, SECRET), null);
  assert.equal((await call(planHandler, planReq(old))).status, 401);

  assert.equal((await call(planHandler, planReq(null, { "x-plan-passcode": CODE }))).status, 401);
});

test("logout clears the cookie and is audited", async () => {
  const r = await call(sessionHandler, req("DELETE", { headers: { cookie: `ohc_tech=${encodeSession(newSession(), SECRET)}` } }));
  assert.equal(r.status, 200);
  assert.match(r.headers["set-cookie"], /Max-Age=0/);
  assert.ok(events.some((e) => e.event === "logout" && e.sid));
});

test("POST from another origin is refused (CSRF)", async () => {
  assert.equal((await login(CODE, { origin: "https://evil.example" })).status, 403);
  assert.equal((await login(CODE, { origin: undefined })).status, 403);
});

test("fails closed: short SESSION_SECRET, missing Supabase, missing code", async () => {
  process.env.SESSION_SECRET = "too-short";
  assert.equal((await login(CODE)).status, 503);
  process.env.SESSION_SECRET = SECRET;
  setStoreForTests(null);
  assert.equal((await login(CODE)).status, 503);
  assert.equal((await call(planHandler, req("GET", { url: "/api/plan?domain=example.com", headers: { cookie: `ohc_tech=${encodeSession(newSession(), SECRET)}` } }))).status, 503);
  setStoreForTests(store);
  delete process.env.TECH_ACCESS_CODE;
  assert.equal((await login(CODE)).status, 503);
});

test("plan requests are limited to 30 per session per 10 minutes", async () => {
  const cookie = `ohc_tech=${encodeSession(newSession(), SECRET)}`;
  for (let i = 0; i < 30; i++) assert.equal((await call(planHandler, req("GET", { url: "/api/plan?domain=localhost", headers: { cookie } }))).status, 400);
  const r = await call(planHandler, req("GET", { url: "/api/plan?domain=localhost", headers: { cookie } }));
  assert.equal(r.status, 429);
  assert.ok(r.headers["retry-after"]);
});

test("the Supabase store calls the rate-limit and audit RPCs with server-side credentials", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith("/rate_limit_hit")) return { ok: true, status: 200, text: async () => JSON.stringify([{ hits: 3, reset_at: "2030-01-01T00:00:00Z" }]) };
    return { ok: true, status: 204, text: async () => "" };
  };
  const s = supabaseStore("https://proj.supabase.co/", "sb_secret_abc", fetchImpl);
  assert.deepEqual(await s.hit("k", 60), { count: 3, resetAt: Date.parse("2030-01-01T00:00:00Z") });
  await s.audit({ event: "verify" });
  assert.equal(calls[0].url, "https://proj.supabase.co/rest/v1/rpc/rate_limit_hit");
  assert.deepEqual(JSON.parse(calls[0].init.body), { p_key: "k", p_window_seconds: 60, p_increment: 1 });
  assert.equal(calls[0].init.headers.apikey, "sb_secret_abc");
  assert.equal(calls[1].url, "https://proj.supabase.co/rest/v1/rpc/audit_append");
  const failing = supabaseStore("https://proj.supabase.co", "eyJ.x.y", async () => ({ ok: false, status: 500, text: async () => "" }));
  await assert.rejects(failing.hit("k", 60), /HTTP 500/);
});

test("no secret or server-only env name is shipped in public/", () => {
  const root = fileURLToPath(new URL("../public/", import.meta.url));
  const files = [];
  const walk = (dir) => {
    for (const f of readdirSync(dir)) {
      const p = join(dir, f);
      if (statSync(p).isDirectory()) walk(p);
      else files.push(p);
    }
  };
  walk(root);
  const secrets = [SECRET, CODE, process.env.SUPABASE_SERVICE_ROLE_KEY, saved.TECH_ACCESS_CODE, saved.PLAN_PASSCODE, saved.SESSION_SECRET].filter((v) => v && v.length >= 8);
  const names = ["TECH_ACCESS_CODE", "PLAN_PASSCODE", "SESSION_SECRET", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_URL", "NEXT_PUBLIC_", "x-plan-passcode", "sessionStorage"];
  for (const f of files) {
    const text = readFileSync(f, "utf8");
    for (const v of secrets) assert.ok(!text.includes(v), `${f} contains a secret value`);
    for (const n of names) assert.ok(!text.includes(n), `${f} mentions ${n}`);
  }
  assert.ok(files.length >= 4);
});
