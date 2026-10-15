// Breach Check: the off-switch, sign-in, the XposedOrNot key never reaching the browser, the
// whitelist-only domain summary, k-anonymity for passwords (only 5 hash characters ever sent),
// the outbound host allowlist, rate limits and the audit entry. Every outside call is mocked.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import breachHandler from "../api/breach.js";
import sessionHandler from "../api/session.js";
import { setBreachDepsForTests, summarizeDomainBreaches, domainKey, XON_DOMAIN_BREACHES_URL, HIBP_RANGE_URL, ALLOWED_HOSTS } from "../lib/breach.js";
import { breachCheckEnabled, features } from "../lib/features.js";
import { fetchApi } from "../lib/net.js";
import { setStoreForTests, memoryStore } from "../lib/store.js";
import { onAudit } from "../lib/audit.js";
import { encodeSession, newSession } from "../lib/session.js";
import { fakeResolver } from "./fakes.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (p) => readFileSync(join(root, p), "utf8");
const SECRET = "test-session-secret-0123456789-abcdefgh";
const KEY = "xon-test-key-6f1c2a9e";
const ENV = ["SESSION_SECRET", "BREACH_CHECK_ENABLED", "XON_DOMAIN_KEYS", "TECH_ACCESS_CODE"];
let saved;
let events;
let stop;
let calls;
let store;

// XposedOrNot's real response shape (POST /v1/domain-breaches/): two verified domains on one account.
const XON_BODY = {
  status: "success",
  metrics: {
    Yearly_Metrics: { 2019: 3 },
    Domain_Summary: { "example.com": 3, "example.org": 1 },
    Breach_Summary: { Canva: 2, LinkedIn: 1, Adobe: 1 },
    Breaches_Details: [
      { email: "jane@example.com", domain: "example.com", breach: "Canva" },
      { email: "jane@example.com", domain: "example.com", breach: "LinkedIn" },
      { email: "office@example.com", domain: "example.com", breach: "Canva" },
      { email: "bob@example.org", domain: "example.org", breach: "Adobe" },
    ],
    Top10_Breaches: { Canva: 2 },
    Detailed_Breach_Info: {
      Canva: { breached_date: "2019-05-24T00:00:00+00:00", logo: "x.png", password_risk: "hardtocrack", searchable: true, xposed_data: "Email addresses;Names;Passwords;Usernames", xposed_records: 137272116, xposure_desc: "In May 2019 the graphic design tool…" },
      LinkedIn: { breached_date: "2012-05-05T00:00:00+00:00", logo: "y.png", password_risk: "easytocrack", searchable: true, xposed_data: ["Email addresses", "Passwords"], xposed_records: 164611595, xposure_desc: "In May 2016…" },
      Adobe: { breached_date: "2013-10-04T00:00:00+00:00", logo: "z.png", password_risk: "hardtocrack", searchable: true, xposed_data: "Email addresses;Password hints", xposed_records: 152445165, xposure_desc: "…" },
    },
  },
};

const reply = (status, body, headers = {}) => ({ ok: true, url: "", status, headers, body: typeof body === "string" ? body : JSON.stringify(body), truncated: false });
function mockOutside(answer = () => reply(200, XON_BODY)) {
  setBreachDepsForTests({
    fetchApi: async (url, opts) => {
      calls.push({ url, ...opts });
      return answer(url, opts);
    },
  });
}

beforeEach(() => {
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  for (const k of ENV) delete process.env[k];
  process.env.SESSION_SECRET = SECRET;
  store = memoryStore();
  setStoreForTests(store);
  events = [];
  stop = onAudit((e) => events.push(e));
  calls = [];
  mockOutside();
});
afterEach(() => {
  stop();
  setStoreForTests(undefined);
  setBreachDepsForTests(null);
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

function fakeRes() {
  return { statusCode: 0, headers: {}, body: "", setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(b) { this.body = b ?? ""; } };
}
const cookie = () => `ohc_tech=${encodeSession(newSession(), SECRET)}`;
async function call(handler, url, { signedIn = true, method = "GET", body, headers = {} } = {}) {
  const res = fakeRes();
  const req = {
    method,
    url,
    headers: { host: "officetech.nwimpm.com", origin: "https://officetech.nwimpm.com", "x-real-ip": "203.0.113.9", "user-agent": "t", ...(signedIn ? { cookie: cookie() } : {}), ...headers },
    socket: {},
  };
  if (body !== undefined) {
    const buf = Buffer.from(JSON.stringify(body));
    req[Symbol.asyncIterator] = async function* () {
      yield buf;
    };
    req.on = () => req;
  }
  await handler(req, res);
  return { status: res.statusCode, headers: res.headers, raw: res.body, json: res.body ? JSON.parse(res.body) : null };
}
const enable = () => {
  process.env.BREACH_CHECK_ENABLED = "true";
  process.env.XON_DOMAIN_KEYS = JSON.stringify({ "Example.com": KEY });
};

/* ------------------------------ the off-switch ------------------------------ */

test("off by default: only the exact string \"true\" turns Breach Check on", () => {
  assert.equal(breachCheckEnabled({}), false);
  for (const v of ["", "1", "yes", "TRUE", "True", " true", "true ", "on", "false"]) assert.equal(breachCheckEnabled({ BREACH_CHECK_ENABLED: v }), false, JSON.stringify(v));
  assert.equal(breachCheckEnabled({ BREACH_CHECK_ENABLED: "true" }), true);
  assert.deepEqual(features({}), { breachCheck: false });
});

test("switched off: /api/breach is 404 for everyone (signed in or not, any method) and nothing outside is called", async () => {
  process.env.XON_DOMAIN_KEYS = JSON.stringify({ "example.com": KEY }); // configured, but still off
  for (const url of ["/api/breach?domain=example.com", "/api/breach?range=5BAA6", "/api/breach"]) {
    for (const signedIn of [true, false]) {
      for (const method of ["GET", "POST"]) {
        const r = await call(breachHandler, url, { signedIn, method });
        assert.equal(r.status, 404, `${method} ${url} signedIn=${signedIn}`);
        assert.deepEqual(r.json, { error: "Not found." });
      }
    }
  }
  assert.deepEqual(calls, [], "no outside call");
  assert.deepEqual(events.filter((e) => e.event === "breach_check"), [], "nothing audited");
  assert.equal(await store.hit("breach-xon-hour", 3600, 0).then((h) => h.count), 0, "no rate-limit counters touched");
});

test("the session tells signed-in pages whether the switch is on (booleans only); signed-out visitors get nothing", async () => {
  let r = await call(sessionHandler, "/api/session");
  assert.deepEqual(r.json.features, { breachCheck: false });
  process.env.BREACH_CHECK_ENABLED = "true";
  r = await call(sessionHandler, "/api/session");
  assert.deepEqual(r.json.features, { breachCheck: true });
  r = await call(sessionHandler, "/api/session", { signedIn: false });
  assert.equal(r.json.authenticated, false);
  assert.ok(!("features" in r.json), "no features before sign-in");

  process.env.TECH_ACCESS_CODE = "correct-horse-battery";
  r = await call(sessionHandler, "/api/session", { signedIn: false, method: "POST", body: { code: "correct-horse-battery" } });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.features, { breachCheck: true }, "sign-in answer carries the switches too");
});

/* --------------------------------- sign-in --------------------------------- */

test("switched on: technicians only (401 without a session, before any outside call)", async () => {
  enable();
  for (const url of ["/api/breach?domain=example.com", "/api/breach?range=5BAA6"]) {
    const r = await call(breachHandler, url, { signedIn: false });
    assert.equal(r.status, 401, url);
  }
  assert.equal((await call(breachHandler, "/api/breach?domain=example.com", { method: "POST" })).status, 405);
  assert.deepEqual(calls, []);
});

/* ------------------------------ domain check ------------------------------ */

test("domain check: one POST to XposedOrNot with the key in x-api-key; only this domain's addresses, names, years and data types come back", async () => {
  enable();
  const r = await call(breachHandler, "/api/breach?domain=example.com");
  assert.equal(r.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, XON_DOMAIN_BREACHES_URL);
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].headers["x-api-key"], KEY);
  assert.deepEqual(calls[0].allowedHosts, ALLOWED_HOSTS);
  assert.equal(r.json.status, "ok");
  assert.equal(r.json.count, 2);
  assert.equal(r.json.breachCount, 2);
  assert.deepEqual(r.json.addresses, [
    {
      email: "jane@example.com",
      breaches: [
        { name: "Canva", year: 2019, dataTypes: ["Email addresses", "Names", "Passwords", "Usernames"] },
        { name: "LinkedIn", year: 2012, dataTypes: ["Email addresses", "Passwords"] },
      ],
    },
    { email: "office@example.com", breaches: [{ name: "Canva", year: 2019, dataTypes: ["Email addresses", "Names", "Passwords", "Usernames"] }] },
  ]);
  assert.ok(!r.raw.includes("example.org") && !r.raw.includes("Adobe"), "other domains on the same XposedOrNot account are never shown");
  for (const leak of ["xposure_desc", "password_risk", "logo", "xposed_records", "In May 2019"]) assert.ok(!r.raw.includes(leak), leak);
  assert.equal(r.headers["cache-control"], "no-store");
});

test("the XposedOrNot key never reaches the browser", async () => {
  enable();
  const answers = [
    () => reply(200, XON_BODY),
    () => reply(401, { detail: "Invalid or missing API key" }),
    () => reply(429, { detail: "rate limited" }, { "retry-after": "30" }),
    () => reply(500, "oops"),
    () => ({ ok: false, error: `boom ${KEY}` }),
  ];
  for (const [i, answer] of answers.entries()) {
    mockOutside(answer);
    const r = await call(breachHandler, `/api/breach?domain=example.com&n=${i}`);
    assert.ok(!r.raw.includes(KEY), `answer ${i} (${r.status}) doesn't echo the key`);
    await store.hit("breach-domain:example.com", 60, -1); // keep under the per-domain limit
  }
  for (const r of [await call(sessionHandler, "/api/session"), await call(breachHandler, "/api/breach?range=5BAA6")]) assert.ok(!r.raw.includes(KEY));
  // Nothing in public/ knows about the key, its variable or the header it travels in.
  const walk = (dir, out = []) => {
    for (const f of readdirSync(dir)) {
      const p = join(dir, f);
      if (statSync(p).isDirectory()) walk(p, out);
      else out.push(p);
    }
    return out;
  };
  for (const f of walk(join(root, "public"))) {
    const text = readFileSync(f, "utf8");
    for (const needle of ["XON_DOMAIN_KEYS\"", "x-api-key", KEY, "api.xposedornot.com"]) assert.ok(!text.includes(needle), `${f}: ${needle}`);
  }
  // The audit entry has the tool, domain, count and time only: no key, session, IP or addresses.
  const audit = events.filter((e) => e.event === "breach_check");
  assert.equal(audit.length, 1);
  assert.deepEqual(Object.keys(audit[0]).sort(), ["audit", "data", "domain", "event", "ts"]);
  assert.deepEqual(audit[0].data, { count: 2 });
  assert.equal(audit[0].domain, "example.com");
});

test("unverified: no key on file (no outside call), XposedOrNot says 401, or the account doesn't cover the domain", async () => {
  process.env.BREACH_CHECK_ENABLED = "true";
  let r = await call(breachHandler, "/api/breach?domain=example.com");
  assert.deepEqual(r.json, { domain: "example.com", status: "unverified", reason: "not-configured" });
  assert.deepEqual(calls, [], "no key, no call");

  process.env.XON_DOMAIN_KEYS = "{not json";
  r = await call(breachHandler, "/api/breach?domain=example.com");
  assert.equal(r.json.reason, "not-configured", "a malformed variable means not configured");

  process.env.XON_DOMAIN_KEYS = JSON.stringify({ "example.com": KEY, "example.net": KEY });
  mockOutside(() => reply(401, { detail: "Invalid or missing API key" }));
  r = await call(breachHandler, "/api/breach?domain=example.com");
  assert.deepEqual([r.status, r.json.status, r.json.reason], [200, "unverified", "not-verified"]);
  mockOutside(() => reply(200, XON_BODY));
  r = await call(breachHandler, "/api/breach?domain=example.net");
  assert.deepEqual([r.json.status, r.json.reason], ["unverified", "not-verified"], "key's account doesn't include example.net");
  assert.deepEqual(events.filter((e) => e.event === "breach_check"), [], "only real results are audited");
});

test("domain check: XposedOrNot errors become plain messages; no breaches is a clean result", async () => {
  enable();
  mockOutside(() => reply(429, {}, { "retry-after": "120" }));
  let r = await call(breachHandler, "/api/breach?domain=example.com");
  assert.equal(r.status, 502);
  assert.match(r.json.error, /free limit/);
  assert.equal(r.headers["retry-after"], "120");
  mockOutside(() => reply(200, "<html>not json"));
  r = await call(breachHandler, "/api/breach?domain=example.com");
  assert.equal(r.status, 502);
  mockOutside(() => reply(200, { status: "success", metrics: { Domain_Summary: { "example.com": 0 }, Breaches_Details: [], Detailed_Breach_Info: {} } }));
  r = await call(breachHandler, "/api/breach?domain=example.com");
  assert.deepEqual([r.json.status, r.json.count, r.json.addresses], ["ok", 0, []]);
  assert.equal((await call(breachHandler, "/api/breach?domain=localhost")).status, 400);
});

test("domain check: at most 3 checks of a domain a minute, and an hourly budget under XposedOrNot's free limit", async () => {
  enable();
  for (let i = 0; i < 3; i++) assert.equal((await call(breachHandler, "/api/breach?domain=example.com")).status, 200);
  const r = await call(breachHandler, "/api/breach?domain=example.com");
  assert.equal(r.status, 429);
  assert.equal(calls.length, 3, "the 4th never reaches XposedOrNot");
  for (let i = 0; i < 20; i++) await store.hit("breach-xon-hour", 3600);
  process.env.XON_DOMAIN_KEYS = JSON.stringify({ "example.net": KEY });
  assert.equal((await call(breachHandler, "/api/breach?domain=example.net")).status, 429);
});

test("summarizeDomainBreaches ignores rows for other domains or with mismatched addresses", () => {
  const s = summarizeDomainBreaches({ metrics: { Domain_Summary: { "example.com": 1 }, Breaches_Details: [{ email: "x@evil.example.net", domain: "example.com", breach: "Canva" }, { email: "a@example.com", domain: "example.com", breach: "" }], Detailed_Breach_Info: {} } }, "example.com");
  assert.deepEqual(s, { verified: true, addresses: [], count: 0, breachCount: 0 });
  assert.equal(domainKey("example.com", { XON_DOMAIN_KEYS: JSON.stringify({ "example.com": "  " }) }), null);
  assert.equal(domainKey("example.com", { XON_DOMAIN_KEYS: JSON.stringify(["example.com"]) }), null);
});

/* --------------------------- passwords: k-anonymity --------------------------- */

test("k-anonymity in the browser: only the first 5 hash characters are sent; the password and the rest of the hash never are", async () => {
  const { checkPassword, sha1Hex, splitHash, countFor } = await import("../public/breach.js");
  const password = "correct horse battery staple";
  const full = createHash("sha1").update(password).digest("hex").toUpperCase();
  assert.equal(await sha1Hex(password), full);
  const { prefix, suffix } = splitHash(full);
  assert.equal(prefix.length, 5);
  assert.equal(suffix.length, 35);
  const sent = [];
  const apiFn = async (path, opts) => {
    sent.push({ path, opts });
    return { res: { ok: true }, body: { suffixes: ["0000000000000000000000000000000000A:0", `${suffix}:2391`, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:4"] } };
  };
  assert.deepEqual(await checkPassword(password, { apiFn }), { count: 2391 });
  assert.equal(sent.length, 1, "one request");
  assert.equal(sent[0].path, `/api/breach?range=${prefix}`);
  assert.equal(sent[0].opts, undefined, "a GET with no body");
  const wire = JSON.stringify(sent);
  assert.ok(!wire.includes(password) && !wire.includes(encodeURIComponent(password)), "the password isn't sent");
  assert.ok(!wire.includes(suffix) && !wire.includes(full), "nor the full hash or its suffix");
  assert.equal(countFor(["ABC:0"], "ABC"), 0, "padding entries mean not found");
  assert.equal((await checkPassword("not in the list", { apiFn: async () => ({ res: { ok: true }, body: { suffixes: [] } }) })).count, 0);
  // The page never builds a request from the password input any other way.
  const page = read("public/breach.js");
  assert.ok(!/innerHTML/.test(page));
  assert.match(page, /input\.value = ""; \/\/ don't keep it in the page/);
  assert.ok(!/<input[^>]*id="password-input"[^>]*\bname=/.test(read("public/tools/breach.html")), "the password field has no name, so it can't be submitted as a form field");
});

test("k-anonymity on the server: exactly 5 hex characters are forwarded to api.pwnedpasswords.com, with padding; anything else is refused unsent", async () => {
  enable();
  mockOutside((url) => reply(200, `${"1".repeat(35)}:3\r\n${"2".repeat(35)}:0\r\nnot a line\r\n`));
  for (const bad of ["5BAA", "5BAA61", "5BAG6", "", "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", "../x1", "5baa6%0A"]) {
    const r = await call(breachHandler, `/api/breach?range=${bad}`);
    assert.equal(r.status, 400, bad);
  }
  assert.deepEqual(calls, [], "nothing sent for a bad prefix");
  const r = await call(breachHandler, "/api/breach?range=5baa6");
  assert.equal(r.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${HIBP_RANGE_URL}5BAA6`);
  assert.equal(calls[0].url, "https://api.pwnedpasswords.com/range/5BAA6");
  assert.equal(calls[0].headers["Add-Padding"], "true");
  assert.equal(calls[0].method, undefined, "GET");
  assert.deepEqual(r.json, { ok: true, prefix: "5BAA6", suffixes: [`${"1".repeat(35)}:3`, `${"2".repeat(35)}:0`] });
  assert.deepEqual(events.filter((e) => e.event === "breach_check"), [], "password checks aren't audited");
  mockOutside(() => ({ ok: false, error: "ECONNRESET" }));
  assert.equal((await call(breachHandler, "/api/breach?range=5BAA6")).status, 502);
});

/* ------------------------------- outbound guard ------------------------------- */

test("fetchApi: https only, exact allowlisted hosts only, vetted public address, TLS verified", async () => {
  const never = () => assert.fail("must not connect");
  for (const url of ["http://api.pwnedpasswords.com/range/5BAA6", "https://evil.example.net/x", "https://api.pwnedpasswords.com.evil.example.net/", "https://api.pwnedpasswords.com:8443/range/5BAA6", "https://user:pw@api.pwnedpasswords.com/", "https://127.0.0.1/", "not a url"]) {
    const r = await fetchApi(url, { allowedHosts: ALLOWED_HOSTS, request: never, resolver: fakeResolver({ a: { "api.pwnedpasswords.com": ["104.16.1.1"] } }) });
    assert.equal(r.ok, false, url);
  }
  const rebound = await fetchApi("https://api.xposedornot.com/v1/domain-breaches/", { allowedHosts: ALLOWED_HOSTS, request: never, resolver: fakeResolver({ a: { "api.xposedornot.com": ["10.0.0.7"] } }) });
  assert.deepEqual([rebound.ok, rebound.error], [false, "non-public address"], "a private answer is never connected to");
  let opts;
  const capture = (o) => {
    opts = o;
    return { on() { return this; }, end() {}, destroy() {} };
  };
  fetchApi("https://api.pwnedpasswords.com/range/5BAA6", { allowedHosts: ALLOWED_HOSTS, request: capture, headers: { "Add-Padding": "true" }, timeoutMs: 50, resolver: fakeResolver({ a: { "api.pwnedpasswords.com": ["104.16.1.1"] } }) });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(opts.host, "104.16.1.1", "connects to the vetted IP");
  assert.equal(opts.servername, "api.pwnedpasswords.com");
  assert.equal(opts.rejectUnauthorized, true, "certificate verified");
  assert.equal(opts.headers["Add-Padding"], "true");
  assert.deepEqual(ALLOWED_HOSTS, ["api.xposedornot.com", "api.pwnedpasswords.com"]);
});

/* ---------------------------------- pages ---------------------------------- */

test("/tools/breach: consent notice, attribution, and 'not available yet' unless the session says the switch is on", () => {
  const html = read("public/tools/breach.html");
  assert.ok(html.includes("Only check domains you manage for a client who has given written permission. Never use results to contact or sell to breach victims."));
  assert.match(html, /Breach data from <a href="https:\/\/xposedornot\.com\/"[^>]*>XposedOrNot<\/a>/);
  assert.match(html, /Password data from <a href="https:\/\/haveibeenpwned\.com\/Passwords"[^>]*>Have I Been Pwned<\/a>/);
  assert.match(html, /<div class="breach-off" id="breach-off">\s*<p class="lede">Not available yet\./, "the off notice is the default");
  assert.match(html, /<div id="breach-on" hidden>/, "the tool itself starts hidden");
  assert.match(html, /<input id="password-input" type="password" autocomplete="off"/);
  assert.match(html, /<script src="\/breach\.js" type="module"><\/script>/);
  const js = read("public/breach.js");
  assert.match(js, /const on = featureEnabled\("breachCheck"\);\n\s+\$\("breach-off"\)\.hidden = on;\n\s+\$\("breach-on"\)\.hidden = !on;/);
  // The registry, the dashboard and the menu: "Coming soon" until the switch is on.
  assert.match(read("public/tools.js"), /id: "breach-check", category: "Email".*href: "\/tools\/breach", status: "live", feature: "breachCheck"/);
  assert.match(read("public/dashboard.js"), /\(!tool\.feature \|\| featureEnabled\(tool\.feature\)\)/);
  for (const f of ["public/tools/email.html", "public/tools/website.html", "public/tools/domain.html", "public/plan.html"]) {
    assert.match(read(f), /<li data-feature="breachCheck"><a href="\/tools\/breach" hidden>Breach Check<\/a><span class="tools-menu-soon">Breach Check <span class="soon-tag">Coming soon<\/span><\/span><\/li>/, f);
  }
  assert.ok(read("vercel.json").includes('"api/breach.js"'));
  assert.match(read("scripts/dev-server.js"), /pathname === "\/api\/breach"/);
});

test("the Tools menu swaps 'Coming soon' for the link only when the session reports the switch on", async () => {
  const mk = () => ({ hidden: false });
  const link = mk();
  const soon = mk();
  link.hidden = true;
  const item = { dataset: { feature: "breachCheck" }, querySelector: (sel) => (sel === "a" ? link : soon) };
  const doc = { querySelectorAll: () => [item] };
  globalThis.document = { getElementById: () => null };
  const { rememberFeatures, applyFeatures, featureEnabled } = await import(`../public/tech-session.js?features=${Date.now()}`);
  applyFeatures(doc);
  assert.deepEqual([link.hidden, soon.hidden], [true, false], "unknown = off");
  rememberFeatures({ breachCheck: "true" });
  assert.equal(featureEnabled("breachCheck"), false, "only a real boolean true counts");
  rememberFeatures({ breachCheck: true });
  applyFeatures(doc);
  assert.deepEqual([link.hidden, soon.hidden], [false, true]);
  rememberFeatures(undefined);
  applyFeatures(doc);
  assert.deepEqual([link.hidden, soon.hidden], [true, false]);
});

test("domain results render with textContent only, including the 'verify first' steps", async () => {
  class El {
    constructor(tag) {
      this.tag = tag;
      this.children = [];
      this.attrs = {};
    }
    setAttribute(k, v) {
      this.attrs[k] = v;
    }
    addEventListener() {}
    append(...c) {
      this.children.push(...c);
    }
    get textContent() {
      return this.children.map((c) => (typeof c === "string" ? c : c.textContent)).join("");
    }
  }
  globalThis.Node = El;
  globalThis.document = { getElementById: () => null, createElement: (t) => new El(t), createTextNode: (t) => t };
  const { renderDomainResult } = await import(`../public/breach.js?render=${Date.now()}`);
  const text = (nodes) => nodes.map((n) => n.textContent).join("\n");
  const unverified = text(renderDomainResult({ domain: "example.com", status: "unverified", reason: "not-configured" }));
  assert.match(unverified, /Verify this domain in XposedOrNot first/);
  assert.match(unverified, /XON_DOMAIN_KEYS as "example\.com"/);
  const found = text(renderDomainResult({ domain: "example.com", status: "ok", checkedAt: "2026-10-15T12:00:00Z", count: 1, breachCount: 1, addresses: [{ email: "jane@example.com", breaches: [{ name: "Canva", year: 2019, dataTypes: ["Email addresses", "Passwords"] }] }] }));
  for (const s of ["1 address on example.com appears in 1 known breach", "jane@example.com", "Canva (2019): Email addresses, Passwords", "Reset the password", "Turn on 2-step sign-in", "Watch for phishing", "Results aren't saved"]) assert.ok(found.includes(s), s);
  const none = text(renderDomainResult({ domain: "example.com", status: "ok", checkedAt: "2026-10-15T12:00:00Z", count: 0, breachCount: 0, addresses: [] }));
  assert.match(none, /No addresses on example\.com appear in known breaches/);
});
