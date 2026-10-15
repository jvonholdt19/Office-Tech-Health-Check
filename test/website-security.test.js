// Website Security Check: header grading, cookies, mixed content, version disclosure, WordPress,
// input validation, the full scan and the private /api/website endpoint. No network.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  checkHsts,
  checkCsp,
  checkFraming,
  checkNosniff,
  checkReferrerPolicy,
  checkPermissionsPolicy,
  checkCookies,
  parseSetCookies,
  findMixedContent,
  checkMixedContent,
  checkVersionDisclosure,
  detectWordPress,
  checkWordPress,
  fetchWordPressVersions,
  resetWordPressCache,
  frameAncestors,
} from "../lib/checks/website-security.js";
import { parseWebsiteTarget, runWebsiteScan, setWebsiteDepsForTests } from "../lib/website-scan.js";
import websiteHandler from "../api/website.js";
import { setStoreForTests, memoryStore } from "../lib/store.js";
import { onAudit } from "../lib/audit.js";
import { encodeSession, newSession } from "../lib/session.js";
import { fakeResolver, goodTls, NOW } from "./fakes.js";

const page = (headers = {}, body = "", url = "https://acmedental.com/", status = 200) => ({ ok: true, url, status, headers, body, truncated: false });

/* ---------------------------- headers ---------------------------- */

test("HSTS: missing fails, short warns, max-age=0 fails, six months passes", () => {
  assert.equal(checkHsts(page()).status, "fail");
  assert.equal(checkHsts(page({ "strict-transport-security": "max-age=86400" })).status, "warn");
  assert.equal(checkHsts(page({ "strict-transport-security": "max-age=0" })).status, "fail");
  assert.equal(checkHsts(page({ "strict-transport-security": "max-age=15552000" })).status, "pass");
  assert.equal(checkHsts(page({ "strict-transport-security": "max-age=31536000; includeSubDomains; preload" })).status, "pass");
  assert.equal(checkHsts(null).status, "fail", "no HTTPS means no HSTS");
});

test("CSP: missing or report-only is yellow, never red; header or <meta> passes", () => {
  assert.equal(checkCsp(page()).status, "warn");
  assert.equal(checkCsp(page({ "content-security-policy-report-only": "default-src 'self'" })).status, "warn");
  assert.equal(checkCsp(page({ "content-security-policy": "default-src 'self'" })).status, "pass");
  assert.equal(checkCsp(page({}, `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`)).status, "pass");
  assert.equal(checkCsp(page({ "content-security-policy": "script-src 'self' 'unsafe-inline'" })).data.unsafeInline, true);
});

test("clickjacking: X-Frame-Options or CSP frame-ancestors satisfies it", () => {
  assert.equal(checkFraming(page()).status, "fail");
  assert.equal(checkFraming(page({ "x-frame-options": "SAMEORIGIN" })).status, "pass");
  assert.equal(checkFraming(page({ "x-frame-options": "deny" })).status, "pass");
  assert.equal(checkFraming(page({ "content-security-policy": "default-src 'self'; frame-ancestors 'none'" })).status, "pass");
  assert.equal(checkFraming(page({ "x-frame-options": "ALLOW-FROM https://x.example" })).status, "warn");
  assert.equal(checkFraming(page({ "content-security-policy": "frame-ancestors *" })).status, "warn");
  assert.equal(frameAncestors("default-src 'self'; frame-ancestors 'self' https://a.example"), "'self' https://a.example");
  assert.equal(frameAncestors("default-src 'self'"), null);
});

test("nosniff, Referrer-Policy and Permissions-Policy", () => {
  assert.equal(checkNosniff(page()).status, "fail");
  assert.equal(checkNosniff(page({ "x-content-type-options": "nosniff" })).status, "pass");
  assert.equal(checkReferrerPolicy(page()).status, "warn");
  assert.equal(checkReferrerPolicy(page({ "referrer-policy": "unsafe-url" })).status, "warn");
  assert.equal(checkReferrerPolicy(page({ "referrer-policy": "no-referrer, strict-origin-when-cross-origin" })).status, "pass");
  assert.equal(checkPermissionsPolicy(page()).status, "warn", "missing Permissions-Policy is yellow, not red");
  assert.equal(checkPermissionsPolicy(page({ "permissions-policy": "camera=()" })).status, "pass");
});

test("header checks are left out (info, weight 0) when there's no HTTPS page", () => {
  for (const fn of [checkCsp, checkFraming, checkNosniff, checkReferrerPolicy, checkPermissionsPolicy, checkVersionDisclosure]) {
    const r = fn(null);
    assert.equal(r.status, "info", fn.name);
    assert.equal(r.weight, 0, fn.name);
  }
});

/* ---------------------------- cookies ---------------------------- */

test("Set-Cookie parsing reads flags and never keeps values", () => {
  const lines = [
    "sessionid=SECRET-VALUE-1; Path=/; Secure; HttpOnly; SameSite=Lax",
    "_ga=GA1.2.SECRET-VALUE-2; Path=/; Max-Age=63072000",
    "cart=SECRET-VALUE-3; Path=/; Secure",
  ];
  const parsed = parseSetCookies(lines);
  assert.deepEqual(parsed, [
    { name: "sessionid", secure: true, httpOnly: true, sameSite: "lax" },
    { name: "_ga", secure: false, httpOnly: false, sameSite: null },
    { name: "cart", secure: true, httpOnly: false, sameSite: null },
  ]);
  const chain = { ok: true, responses: [page({ "set-cookie": lines })], final: page({ "set-cookie": lines }) };
  const r = checkCookies({ https: chain, http: { ok: false } });
  assert.equal(r.status, "fail", "a cookie without Secure on an HTTPS site is red");
  const out = JSON.stringify(r);
  assert.ok(!out.includes("SECRET-VALUE"), "cookie values never appear in the result");
  assert.match(r.detail, /_ga: missing Secure, SameSite/);
  assert.match(r.detail, /_ga: no HttpOnly \(normal/, "analytics cookies get an info note for HttpOnly");
  assert.match(r.detail, /cart: missing HttpOnly, SameSite/);
});

test("cookies: all flags set passes; cookies on redirect hops count; none set passes", () => {
  const good = "sid=x; Secure; HttpOnly; SameSite=Strict";
  const hop = page({ "set-cookie": ["lang=en; Secure; SameSite=Lax"], location: "/home" }, "", "https://acmedental.com/", 302);
  const final = page({ "set-cookie": [good] }, "", "https://acmedental.com/home");
  const r = checkCookies({ https: { ok: true, responses: [hop, final], final }, http: null });
  assert.equal(r.status, "pass");
  assert.deepEqual(r.data.cookies.map((c) => c.name), ["lang", "sid"]);
  assert.equal(checkCookies({ https: { ok: true, responses: [page()], final: page() } }).status, "pass");
});

/* ------------------------- mixed content ------------------------- */

test("mixed content: http:// in src, stylesheet links and form actions; only on HTTPS pages", () => {
  const html = `
    <script src="http://cdn.example/a.js"></script>
    <img src='https://ok.example/a.png'><img src=http://img.example/b.png>
    <link rel="stylesheet" href="http://cdn.example/s.css">
    <link rel="canonical" href="http://acmedental.com/">
    <a href="http://elsewhere.example/">plain links are fine</a>
    <form action="http://acmedental.com/contact" method="post"></form>`;
  const found = findMixedContent(html);
  assert.deepEqual(found.map((f) => f.tag), ["script", "img", "link", "form"]);
  const r = checkMixedContent(page({}, html));
  assert.equal(r.status, "warn");
  assert.equal(r.data.forms, 1);
  assert.equal(checkMixedContent(page({}, "<img src=/x.png>")).status, "pass");
  assert.equal(checkMixedContent(page({}, html, "http://acmedental.com/")).status, "info", "not checked on plain-HTTP pages");
});

/* ----------------------- version disclosure ---------------------- */

test("Server / X-Powered-By with version numbers is yellow; product names alone pass", () => {
  assert.equal(checkVersionDisclosure(page({ server: "Apache/2.4.41 (Ubuntu)" })).status, "warn");
  assert.equal(checkVersionDisclosure(page({ "x-powered-by": "PHP/7.4.3" })).status, "warn");
  assert.equal(checkVersionDisclosure(page({ server: "nginx/1.18.0" })).status, "warn");
  assert.equal(checkVersionDisclosure(page({ server: "nginx", "x-powered-by": "PHP" })).status, "pass");
  assert.equal(checkVersionDisclosure(page({ server: "cloudflare" })).status, "pass");
  assert.equal(checkVersionDisclosure(page()).status, "pass");
});

/* ---------------------------- WordPress -------------------------- */

const wpPage = (v) => page({}, `<html><head><meta name="generator" content="WordPress ${v}" /><link rel="stylesheet" href="/wp-content/themes/x/style.css"></head></html>`);
const versionsOk = async () => ({ ok: true, latest: "6.8.3", versions: ["6.8.3", "6.7.4"] });

test("WordPress generator parsing", () => {
  assert.deepEqual(detectWordPress(`<meta name="generator" content="WordPress 6.4.2">`), { detected: true, version: "6.4.2" });
  assert.deepEqual(detectWordPress(`<meta content="WordPress 5.9" name="generator">`), { detected: true, version: "5.9" });
  assert.deepEqual(detectWordPress(`<script src="/wp-includes/js/jquery.js"></script>`), { detected: true, version: null });
  assert.deepEqual(detectWordPress(`<meta name="generator" content="Wix.com Website Builder">`), { detected: false, version: null });
});

test("WordPress: latest passes, one branch behind warns, more than one major branch behind fails", async () => {
  assert.equal((await checkWordPress(wpPage("6.8.3"), { wordpressVersions: versionsOk })).status, "pass");
  assert.equal((await checkWordPress(wpPage("6.8.1"), { wordpressVersions: versionsOk })).status, "warn");
  assert.equal((await checkWordPress(wpPage("6.7.2"), { wordpressVersions: versionsOk })).status, "warn");
  const old = await checkWordPress(wpPage("6.4.2"), { wordpressVersions: versionsOk });
  assert.equal(old.status, "fail");
  assert.equal(old.data.branchesBehind, 4);
  assert.equal((await checkWordPress(wpPage("5.9"), { wordpressVersions: versionsOk })).status, "fail");
});

test("WordPress: version check failure falls back to 'reported, couldn't compare'; no WP is info", async () => {
  const r = await checkWordPress(wpPage("6.4.2"), { wordpressVersions: async () => ({ ok: false, error: "timed out" }) });
  assert.equal(r.status, "unknown");
  assert.match(r.summary, /reports WordPress 6\.4\.2/);
  assert.equal((await checkWordPress(page({}, "<html></html>"), { wordpressVersions: versionsOk })).status, "info");
  const hidden = await checkWordPress(page({}, `<link href="/wp-content/x.css">`), { wordpressVersions: () => assert.fail("not needed") });
  assert.equal(hidden.status, "info");
});

test("fetchWordPressVersions reads the public API, caches it, and fails soft", async () => {
  resetWordPressCache();
  let calls = 0;
  const body = { offers: [{ response: "upgrade", current: "6.8.3", version: "6.8.3" }, { response: "autoupdate", current: "6.7.4", version: "6.7.4" }] };
  const fetchImpl = async (url) => {
    calls++;
    assert.equal(url, "https://api.wordpress.org/core/version-check/1.7/");
    return { ok: true, status: 200, json: async () => body };
  };
  const r = await fetchWordPressVersions({ fetchImpl });
  assert.equal(r.latest, "6.8.3");
  await fetchWordPressVersions({ fetchImpl });
  assert.equal(calls, 1, "cached");
  resetWordPressCache();
  assert.deepEqual(await fetchWordPressVersions({ fetchImpl: async () => { throw Object.assign(new Error("x"), { code: "ENOTFOUND" }); } }), { ok: false, error: "ENOTFOUND" });
  assert.equal((await fetchWordPressVersions({ fetchImpl: async () => ({ ok: false, status: 503 }) })).error, "HTTP 503");
  assert.equal((await fetchWordPressVersions({ fetchImpl: () => new Promise(() => {}), timeoutMs: 20 })).ok, false, "times out");
  resetWordPressCache();
});

/* ------------------------- input validation ---------------------- */

test("target validation: schemes, IP literals, ports and userinfo", () => {
  assert.deepEqual(parseWebsiteTarget("acme.com"), { host: "acme.com" });
  assert.deepEqual(parseWebsiteTarget("https://www.Acme.com/contact?x=1#top"), { host: "acme.com" }, "path, query and www dropped");
  assert.deepEqual(parseWebsiteTarget("http://acme.com"), { host: "acme.com" });
  assert.deepEqual(parseWebsiteTarget("acme.com:443"), { host: "acme.com" });
  for (const bad of ["", "ftp://acme.com", "file:///etc/passwd", "javascript:alert(1)", "https://user:pw@acme.com", "user@acme.com", "acme.com:8080", "https://acme.com:8443/",
    "127.0.0.1", "10.0.0.1", "http://169.254.169.254/", "http://[::1]/", "http://2130706433/", "localhost", "http://localhost/", "printer.local"]) {
    assert.ok(parseWebsiteTarget(bad).error, `${bad} must be refused`);
  }
});

/* --------------------------- full scan --------------------------- */

const acmeDns = { a: { "acmedental.com": ["93.184.216.34"], "www.acmedental.com": ["93.184.216.34"] } };
function fakeFetchPage(routes, log = []) {
  return async (url) => {
    log.push(url);
    const r = routes[url];
    if (!r) return { ok: false, error: "ECONNREFUSED" };
    return { ok: true, url, status: r.status, headers: r.headers || {}, body: r.body || "", truncated: false, tlsAuthorized: true };
  };
}
const strongHeaders = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=()",
  "set-cookie": ["sid=v; Secure; HttpOnly; SameSite=Lax"],
};

test("a well-configured site gets an A; every check has a status and a weight", async () => {
  const fetchPage = fakeFetchPage({
    "http://acmedental.com/": { status: 301, headers: { location: "https://acmedental.com/" } },
    "https://acmedental.com/": { status: 301, headers: { location: "https://www.acmedental.com/", ...strongHeaders } },
    "https://www.acmedental.com/": { status: 200, headers: strongHeaders, body: "<html><img src=/a.png></html>" },
  });
  const r = await runWebsiteScan("https://acmedental.com/some/path", {
    resolver: fakeResolver(acmeDns),
    fetchPage,
    inspectTls: async () => goodTls,
    wordpressVersions: () => assert.fail("not WordPress"),
    now: () => NOW,
  });
  assert.equal(r.target, "acmedental.com");
  assert.equal(r.finalUrl, "https://www.acmedental.com/");
  assert.equal(r.grade, "A");
  assert.equal(r.score, 100);
  assert.equal(r.coverage, 100);
  assert.deepEqual(r.redirects.https.map((x) => x.status), [301, 200]);
  for (const c of r.checks) {
    assert.ok(["pass", "warn", "fail", "info", "unknown"].includes(c.status), c.id);
    assert.equal(typeof c.weight, "number", c.id);
  }
  assert.ok(!JSON.stringify(r).includes("<html>"), "no page HTML in the report");
});

test("a bare HTTP site with an old WordPress grades badly and lists fixes", async () => {
  const fetchPage = fakeFetchPage({
    "http://acmedental.com/": { status: 200, headers: { server: "Apache/2.4.29", "set-cookie": ["PHPSESSID=abc; path=/"] }, body: `<meta name="generator" content="WordPress 5.8.1">` },
  });
  const r = await runWebsiteScan("acmedental.com", {
    resolver: fakeResolver(acmeDns),
    fetchPage,
    inspectTls: async () => ({ ok: false, error: "ECONNREFUSED" }),
    wordpressVersions: versionsOk,
    now: () => NOW,
  });
  const by = Object.fromEntries(r.checks.map((c) => [c.id, c]));
  assert.equal(by.https.status, "fail");
  assert.equal(by["https-redirect"].status, "warn");
  assert.equal(by.hsts.status, "fail");
  assert.equal(by.cookies.status, "warn");
  assert.equal(r.grade, "F");
  assert.ok(r.fixes.length >= 3);
});

test("an unreachable site gets no grade", async () => {
  const r = await runWebsiteScan("acmedental.com", { resolver: fakeResolver(), fetchPage: fakeFetchPage({}), inspectTls: async () => ({ ok: false, error: "ENOTFOUND" }), now: () => NOW });
  assert.equal(r.grade, null);
  assert.equal(r.score, null);
});

test("runWebsiteScan refuses bad input without touching the network", async () => {
  const r = await runWebsiteScan("http://127.0.0.1/", { fetchPage: () => assert.fail("no fetch"), inspectTls: () => assert.fail("no TLS") });
  assert.ok(r.error);
});

/* ------------------------- /api/website -------------------------- */

const SECRET = "test-session-secret-0123456789-abcdefgh";
let saved;
let store;
let events;
let stopAudit;
beforeEach(() => {
  saved = { SESSION_SECRET: process.env.SESSION_SECRET, TECH_ACCESS_CODE: process.env.TECH_ACCESS_CODE };
  process.env.SESSION_SECRET = SECRET;
  process.env.TECH_ACCESS_CODE = "tech-code-for-tests-7f3a";
  store = memoryStore();
  setStoreForTests(store);
  events = [];
  stopAudit = onAudit((e) => events.push(e));
  setWebsiteDepsForTests({
    resolver: fakeResolver(acmeDns),
    fetchPage: fakeFetchPage({ "https://acmedental.com/": { status: 200, headers: { "strict-transport-security": "max-age=31536000" }, body: "<html>SECRET-HTML</html>" } }),
    inspectTls: async () => goodTls,
    wordpressVersions: versionsOk,
  });
});
afterEach(() => {
  stopAudit();
  setStoreForTests(undefined);
  setWebsiteDepsForTests(null);
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

function fakeRes() {
  return { statusCode: 0, headers: {}, body: "", setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(b) { this.body = b; } };
}
async function callWebsite(target, cookie, method = "GET") {
  const res = fakeRes();
  const headers = { host: "officetech.nwimpm.com", "x-real-ip": "203.0.113.9", "user-agent": "test-agent", ...(cookie ? { cookie } : {}) };
  await websiteHandler({ method, url: `/api/website?target=${encodeURIComponent(target)}`, headers, socket: {} }, res);
  return { status: res.statusCode, headers: res.headers, json: res.body ? JSON.parse(res.body) : null };
}
const sessionCookie = () => `ohc_tech=${encodeSession(newSession(), SECRET)}`;

test("/api/website: 401 without a session", async () => {
  const r = await callWebsite("acmedental.com", null);
  assert.equal(r.status, 401);
  assert.equal(events.length, 0);
});

test("/api/website: a scan is audited as website_scan with a summary only, and is no-store", async () => {
  const r = await callWebsite("acmedental.com", sessionCookie());
  assert.equal(r.status, 200);
  assert.equal(r.headers["cache-control"], "no-store");
  assert.equal(r.json.target, "acmedental.com");
  const e = events.find((x) => x.event === "website_scan");
  assert.ok(e);
  assert.equal(e.domain, "acmedental.com");
  assert.ok(e.sid && e.ip === "203.0.113.9" && e.ua === "test-agent");
  assert.deepEqual(Object.keys(e.data).sort(), ["counts", "durationMs", "grade", "score"]);
  assert.ok(!JSON.stringify(e).includes("SECRET-HTML"), "no page HTML in the audit log");
  assert.ok(store.events.some((x) => x.event === "website_scan"), "stored durably");
});

test("/api/website: bad targets are 400 and private addresses are refused", async () => {
  const cookie = sessionCookie();
  for (const t of ["localhost", "127.0.0.1", "10.0.0.1", "http://169.254.169.254/", "file:///etc/passwd", "acmedental.com:8080"]) {
    assert.equal((await callWebsite(t, cookie)).status, 400, t);
  }
});

test("/api/website: one site can be checked at most 3 times a minute (429)", async () => {
  const cookie = sessionCookie();
  for (let i = 0; i < 3; i++) assert.equal((await callWebsite("https://www.acmedental.com/x", cookie)).status, 200);
  const r = await callWebsite("acmedental.com", sessionCookie());
  assert.equal(r.status, 429, "the cooldown is per site, across sessions");
  assert.ok(Number(r.headers["retry-after"]) > 0);
  assert.equal((await callWebsite("otherdental.com", cookie)).status, 200, "other sites are unaffected");
});

test("/api/website: only GET", async () => {
  assert.equal((await callWebsite("acmedental.com", sessionCookie(), "POST")).status, 405);
});
