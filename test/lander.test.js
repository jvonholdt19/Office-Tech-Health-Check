// Public lander + preview API, the now-private /api/scan, the scanner's move to /tools/email,
// and the non-compete wording guard. Offline.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import previewHandler, { setPreviewRunnerForTests, PREVIEW_LIMITS } from "../api/preview.js";
import scanHandler, { setScanDepsForTests } from "../api/scan.js";
import { runPreview } from "../lib/preview.js";
import { inspectTls } from "../lib/net.js";
import { setStoreForTests, memoryStore } from "../lib/store.js";
import { onAudit } from "../lib/audit.js";
import { encodeSession, newSession } from "../lib/session.js";
import { fakeDeps, fakeResolver, goodTls, DKIM_RECORD } from "./fakes.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (p) => readFileSync(join(root, p), "utf8");
const SECRET = "test-session-secret-0123456789-abcdefgh";
let store;
let events;
let stop;
let saved;

beforeEach(() => {
  saved = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = SECRET;
  store = memoryStore();
  setStoreForTests(store);
  events = [];
  stop = onAudit((e) => events.push(e));
  // A full-looking result with extra fields, to prove the endpoint strips everything but the essentials.
  setPreviewRunnerForTests(async (domain) => ({
    domain,
    grade: "C",
    items: [
      { id: "spf", title: "SPF", status: "pass", detail: "v=spf1 include:_spf.google.com ~all", fix: "x", data: { record: "secret" } },
      { id: "dmarc", title: "DMARC", status: "fail", detail: "No DMARC record", fix: "add one" },
      { id: "ssl", title: "HTTPS", status: "pass", detail: "valid" },
    ],
    checks: [{ detail: "should never leak" }],
  }));
});
afterEach(() => {
  stop();
  setStoreForTests(undefined);
  setPreviewRunnerForTests(null);
  setScanDepsForTests(null);
  if (saved === undefined) delete process.env.SESSION_SECRET;
  else process.env.SESSION_SECRET = saved;
});

function fakeRes() {
  return { statusCode: 0, headers: {}, body: "", setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(b) { this.body = b; } };
}
async function call(handler, url, { ip = "203.0.113.5", headers = {}, method = "GET" } = {}) {
  const res = fakeRes();
  await handler({ method, url, headers: { host: "officetech.nwimpm.com", "x-real-ip": ip, "user-agent": "t", ...headers }, socket: {} }, res);
  return { status: res.statusCode, headers: res.headers, json: res.body ? JSON.parse(res.body) : null };
}
const preview = (domain, opts) => call(previewHandler, `/api/preview?domain=${encodeURIComponent(domain)}`, opts);

/* ------------------------------ preview ------------------------------ */

test("preview returns only domain, grade and id/title/status per item", async () => {
  const r = await preview("acmedental.com");
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys(r.json).sort(), ["domain", "grade", "items"]);
  for (const item of r.json.items) assert.deepEqual(Object.keys(item).sort(), ["id", "status", "title"]);
  assert.ok(!JSON.stringify(r.json).includes("spf1") && !JSON.stringify(r.json).includes("never leak"));
  assert.equal(r.headers["cache-control"], "no-store");
  assert.equal(r.headers["access-control-allow-origin"], undefined, "no CORS headers");
});

test("runPreview grades SPF, DMARC and HTTPS only, and returns nothing else", async () => {
  const deps = fakeDeps({
    mx: { "acmedental.com": [{ exchange: "aspmx.l.google.com", priority: 1 }] },
    txt: { "acmedental.com": ["v=spf1 include:_spf.google.com ~all"], "_dmarc.acmedental.com": ["v=DMARC1; p=reject; rua=mailto:d@acmedental.com"], "google._domainkey.acmedental.com": [DKIM_RECORD] },
    tls: { "acmedental.com": goodTls, "www.acmedental.com": goodTls },
  });
  const r = await runPreview("acmedental.com", deps);
  assert.deepEqual(Object.keys(r).sort(), ["domain", "grade", "items"]);
  assert.deepEqual(r.items.map((i) => i.id), ["spf", "dmarc", "ssl"]);
  assert.deepEqual(r.items.map((i) => i.status), ["pass", "pass", "pass"]);
  assert.equal(r.grade, "A");
});

test("preview SSRF: internal names and IPs are refused, and a domain resolving to a private IP is never connected to", async () => {
  for (const d of ["localhost", "10.0.0.1", "169.254.169.254", "127.0.0.1", "intranet.local"]) assert.equal((await preview(d)).status, 400, d);
  const resolver = fakeResolver({ a: { "evil-dental.com": ["10.0.0.5"], "www.evil-dental.com": ["169.254.169.254"] } });
  const neverConnect = () => assert.fail("must not connect to a private address");
  const r = await runPreview("evil-dental.com", { ...fakeDeps(), resolver, inspectTls: (h) => inspectTls(h, { resolver, connect: neverConnect }) });
  assert.equal(r.items.find((i) => i.id === "ssl").status, "info", "HTTPS not checked: no public address");
});

test("preview per-IP limit: 5 per 10 minutes, then 429 with Retry-After", async () => {
  for (let i = 0; i < 5; i++) assert.equal((await preview(`site${i}.com`)).status, 200);
  const r = await preview("site9.com");
  assert.equal(r.status, 429);
  assert.ok(Number(r.headers["retry-after"]) > 0);
  assert.equal((await preview("site9.com", { ip: "198.51.100.7" })).status, 200, "another visitor is unaffected");
  assert.equal((await preview("site8.com", { ip: "203.0.113.5", headers: { "x-forwarded-for": "1.2.3.4" } })).status, 429, "x-forwarded-for can't dodge it");
});

test("preview per-IP daily limit: 20 per day", async () => {
  for (let i = 0; i < 20; i++) await store.hit("preview-ip-day:203.0.113.5", 86_400);
  const r = await preview("acmedental.com");
  assert.equal(r.status, 429);
  assert.match(r.json.error, /Daily limit/);
});

test("preview per-domain limit: 3 per 10 minutes across all visitors", async () => {
  for (let i = 0; i < 3; i++) assert.equal((await preview("acmedental.com", { ip: `198.51.100.${i}` })).status, 200);
  const r = await preview("acmedental.com", { ip: "198.51.100.50" });
  assert.equal(r.status, 429);
  assert.match(r.json.error, /checked several times/);
});

test("preview global cap: 300 per hour", async () => {
  for (let i = 0; i < 300; i++) await store.hit("preview-global", 3600);
  assert.equal((await preview("acmedental.com")).status, 429);
  assert.deepEqual(PREVIEW_LIMITS.map((l) => [l.max, l.windowSeconds]), [[5, 600], [20, 86_400], [3, 600], [300, 3600]]);
});

test("preview fails closed (503) without the store, or when it errors", async () => {
  setStoreForTests(null);
  assert.equal((await preview("acmedental.com")).status, 503);
  setStoreForTests({ hit: async () => { throw new Error("down"); }, audit: async () => {} });
  assert.equal((await preview("acmedental.com")).status, 503);
});

test("preview audit: at most one preview_scan per IP per hour, with ip, domain and grade only", async () => {
  await preview("one-dental.com");
  await preview("two-dental.com");
  await preview("three-dental.com", { ip: "198.51.100.9" });
  const audits = events.filter((e) => e.event === "preview_scan");
  assert.equal(audits.length, 2);
  assert.deepEqual(audits.map((e) => e.domain), ["one-dental.com", "three-dental.com"]);
  assert.deepEqual(audits[0].data, { grade: "C" });
  assert.equal(audits[0].ip, "203.0.113.5");
  assert.equal(audits[0].sid, undefined);
  assert.equal(audits[0].ua, undefined);
});

test("preview is GET only", async () => {
  assert.equal((await preview("acmedental.com", { method: "POST" })).status, 405);
});

/* ------------------------------ /api/scan ------------------------------ */

test("/api/scan is private now: 401 without a session; works and is audited with one", async () => {
  assert.equal((await call(scanHandler, "/api/scan?domain=acmedental.com")).status, 401);
  setScanDepsForTests(fakeDeps({ mx: { "acmedental.com": [{ exchange: "aspmx.l.google.com", priority: 1 }] } }));
  const cookie = `ohc_tech=${encodeSession(newSession(), SECRET)}`;
  const r = await call(scanHandler, "/api/scan?domain=acmedental.com", { headers: { cookie } });
  assert.equal(r.status, 200);
  for (const k of ["domain", "score", "grade", "coverage", "checks", "fixes", "provider"]) assert.ok(k in r.json, k);
  const e = events.find((x) => x.event === "scan");
  assert.ok(e && e.sid && e.domain === "acmedental.com");
  assert.deepEqual(Object.keys(e.data).sort(), ["counts", "durationMs", "grade", "score"]);
});

/* ---------------------- pages, routes and redirects ---------------------- */

test("the lander has the preview, the tech sign-in link and the contact details, and never calls /api/scan", () => {
  const html = read("public/index.html");
  const js = read("public/lander.js");
  assert.match(html, /<title>Office Tech Health Check<\/title>/);
  assert.match(html, /Powered by NWIM Project Management/);
  assert.match(html, /<a class="[^"]*signin-btn[^"]*" href="\/tools">Tech sign in<\/a>/);
  assert.match(html, /Quick email security check \(preview\)/);
  assert.match(html, /<a href="tel:\+15073604479">507-360-4479<\/a>/);
  assert.match(html, /<a href="mailto:info@nwimpm\.com">info@nwimpm\.com<\/a>/);
  assert.match(html, /Want the full check and a fix plan\? Call NWIM Project Management at/);
  assert.match(html, /<meta name="robots" content="noindex, nofollow">/);
  assert.match(html, /<script src="\/lander\.js" type="module"><\/script>/);
  assert.ok(!/api\/scan/.test(js) && /api\/preview/.test(js));
  assert.ok(!/TODO/.test(html), "no leftover TODOs");
});

test("the scanner moved to /tools/email behind the gate; dashboard and redirects point there", () => {
  const html = read("public/tools/email.html");
  assert.match(html, /<script src="\/email\.js" type="module"><\/script>/);
  assert.match(html, /id="gate-form"/);
  const js = read("public/email.js");
  assert.match(js, /initGate\(/);
  assert.match(js, /api\(`\/api\/scan\?domain=/, "fetched with the session cookie via api()");
  const registry = read("public/tools.js");
  assert.match(registry, /name: "Email Security Check".*href: "\/tools\/email", status: "live"/);
  assert.match(registry, /name: "Domain Health".*href: "\/tools\/domain", status: "live"/);
  assert.ok(!/href: "\/",/.test(registry));
  assert.match(read("public/plan.js"), /\/tools\/email\?d=/);
  assert.ok(!/href: `\/\?d=/.test(read("public/plan.js")));
  const vercel = JSON.parse(read("vercel.json"));
  for (const key of ["d", "domain"]) {
    const r = vercel.redirects.find((x) => x.source === "/" && x.has?.[0]?.key === key);
    assert.ok(r, `redirect for /?${key}=`);
    assert.equal(r.destination, "/tools/email");
    assert.equal(r.permanent, false);
  }
  assert.ok(vercel.headers.some((h) => h.source === "/tools/(.*)" && h.headers.some((x) => x.key === "X-Robots-Tag")), "/tools/email and /tools/domain are noindex");
  assert.ok(vercel.headers.some((h) => h.source === "/" && h.headers.some((x) => /noindex/.test(x.value))));
  assert.ok(vercel.functions["api/preview.js"]);
});

test("non-compete: no marketing, SEO, reviews or Google Business wording in public pages", () => {
  const files = [];
  const walk = (dir) => {
    for (const f of readdirSync(dir)) {
      const p = join(dir, f);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(html|js)$/.test(f)) files.push(p);
    }
  };
  walk(join(root, "public"));
  // "review" as a verb (a technician reviewing DNS changes) is fine; customer/online reviews are not.
  const deny = /\bSEO\b|search engine|Google Business|\b(customer|online|google|yelp|star|5-star) reviews?\b|\breviews? (site|platform|management)\b|\brankings?\b|grow your business|more customers|marketing/i;
  for (const f of files) {
    const text = readFileSync(f, "utf8");
    const m = text.match(deny);
    assert.ok(!m, `${f} contains "${m && m[0]}"`);
  }
  assert.ok(files.length >= 10);
});

test("old production hostname is gone", () => {
  for (const f of ["CLAUDE.md", "README.md", "lib/net.js", "test/session.test.js"]) assert.ok(!read(f).includes("office-tech-health-check.vercel.app"), f);
  assert.match(read("lib/net.js"), /"User-Agent": WEBSITE_UA/);
});
