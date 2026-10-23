// Website Security Check: header grading, cookies, mixed content, version disclosure, WordPress,
// input validation, the full scan and the private /api/website endpoint. No network.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  checkHsts,
  hstsDuration,
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
  checkCertificate,
  checkTlsDetails,
  checkCors,
  checkSri,
  findExternalScripts,
} from "../lib/checks/website-security.js";
import { parseWebsiteTarget, runWebsiteScan, setWebsiteDepsForTests, applyGradeCaps } from "../lib/website-scan.js";
import websiteHandler from "../api/website.js";
import { setStoreForTests, memoryStore } from "../lib/store.js";
import { onAudit } from "../lib/audit.js";
import { encodeSession, newSession } from "../lib/session.js";
import { fakeResolver, goodTls, NOW } from "./fakes.js";

const page = (headers = {}, body = "", url = "https://example.com/", status = 200) => ({ ok: true, url, status, headers, body, truncated: false });

/* ---------------------------- headers ---------------------------- */

test("HSTS: a short max-age is described in minutes or hours, never as \"0 days\"", () => {
  const summary = (age) => checkHsts(page({ "strict-transport-security": `max-age=${age}` })).summary;
  assert.equal(summary(300), "HSTS is on, but only for 5 minutes (less than a day). Six months or more is recommended.");
  assert.match(summary(1), /only for 1 second \(less than a day\)/);
  assert.match(summary(600), /only for 10 minutes \(less than a day\)/);
  assert.match(summary(7200), /only for 2 hours \(less than a day\)/);
  assert.match(summary(86400), /only for 1 day\. /);
  assert.match(summary(604800), /only for 7 days\. /);
  for (const age of [1, 59, 60, 300, 3599, 3600, 86399, 86400, 15551999]) {
    assert.ok(!/\b0 (days|hours|minutes|seconds)\b/.test(summary(age)), `max-age=${age}: ${summary(age)}`);
  }
  assert.deepEqual([59, 60, 119, 3600, 86399, 172800].map(hstsDuration), ["59 seconds", "1 minute", "1 minute", "1 hour", "23 hours", "2 days"]);
});

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

test("clickjacking: X-Frame-Options or CSP frame-ancestors satisfies it; missing is a warning (weight 6)", () => {
  const missing = checkFraming(page());
  assert.equal(missing.status, "warn", "small-office fairness: missing is yellow, not red");
  assert.equal(missing.weight, 6);
  assert.equal(checkFraming(page({ "x-frame-options": "SAMEORIGIN" })).status, "pass");
  assert.equal(checkFraming(page({ "x-frame-options": "deny" })).status, "pass");
  assert.equal(checkFraming(page({ "content-security-policy": "default-src 'self'; frame-ancestors 'none'" })).status, "pass");
  assert.equal(checkFraming(page({ "x-frame-options": "ALLOW-FROM https://x.example" })).status, "warn");
  assert.equal(checkFraming(page({ "content-security-policy": "frame-ancestors *" })).status, "warn");
  assert.equal(frameAncestors("default-src 'self'; frame-ancestors 'self' https://a.example"), "'self' https://a.example");
  assert.equal(frameAncestors("default-src 'self'"), null);
});

test("nosniff, Referrer-Policy and Permissions-Policy", () => {
  const nosniff = checkNosniff(page());
  assert.equal(nosniff.status, "warn", "missing nosniff is a warning (Observatory: -5)");
  assert.equal(nosniff.weight, 4);
  assert.equal(checkNosniff(page({ "x-content-type-options": "nosniff" })).status, "pass");
  const ref = checkReferrerPolicy(page());
  assert.equal(ref.status, "pass", "missing Referrer-Policy: browsers default to strict-origin-when-cross-origin");
  assert.equal(ref.weight, 2);
  assert.match(ref.summary, /default/);
  assert.equal(checkReferrerPolicy(page({ "referrer-policy": "unsafe-url" })).status, "warn");
  assert.equal(checkReferrerPolicy(page({ "referrer-policy": "no-referrer, strict-origin-when-cross-origin" })).status, "pass");
  const pp = checkPermissionsPolicy(page());
  assert.equal(pp.status, "info", "Permissions-Policy is not scored");
  assert.equal(pp.weight, 0);
  assert.match(pp.summary, /camera=\(\)/, "the advice is kept");
  assert.equal(checkPermissionsPolicy(page({ "permissions-policy": "camera=()" })).status, "info");
  assert.equal(checkPermissionsPolicy(page({ "permissions-policy": "camera=()" })).weight, 0);
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
  assert.match(r.detail, /_ga: missing Secure/);
  assert.match(r.detail, /_ga: no HttpOnly \(fine/, "non-session cookies get an info note for HttpOnly");
  assert.match(r.detail, /cart: no HttpOnly \(fine/, "cart isn't a session cookie, so no HttpOnly is info only");
  assert.match(r.detail, /cart: no SameSite \(browsers default to Lax\)/);
});

test("cookies: all flags set passes; cookies on redirect hops count; none set passes", () => {
  const good = "sid=x; Secure; HttpOnly; SameSite=Strict";
  const hop = page({ "set-cookie": ["lang=en; Secure; SameSite=Lax"], location: "/home" }, "", "https://example.com/", 302);
  const final = page({ "set-cookie": [good] }, "", "https://example.com/home");
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
    <link rel="canonical" href="http://example.com/">
    <a href="http://elsewhere.example/">plain links are fine</a>
    <form action="http://example.com/contact" method="post"></form>`;
  const found = findMixedContent(html);
  assert.deepEqual(found.map((f) => f.tag), ["script", "img", "link", "form"]);
  assert.deepEqual(found.map((f) => f.active), [true, false, true, true]);
  const r = checkMixedContent(page({}, html));
  assert.equal(r.status, "fail", "active mixed content is red");
  assert.equal(r.weight, 6);
  assert.equal(r.data.forms, 1);
  assert.equal(checkMixedContent(page({}, "<img src=/x.png>")).status, "pass");
  assert.equal(checkMixedContent(page({}, html, "http://example.com/")).status, "info", "not checked on plain-HTTP pages");
});

test("mixed content: active (script, iframe, stylesheet, form) fails; passive (img, audio, video, source) warns", () => {
  for (const html of [`<script src="http://x.example/a.js"></script>`, `<iframe src="http://x.example/"></iframe>`, `<link rel="stylesheet" href="http://x.example/s.css">`, `<form action="http://x.example/post"></form>`]) {
    assert.equal(checkMixedContent(page({}, html)).status, "fail", html);
  }
  for (const html of [`<img src="http://x.example/a.png">`, `<audio src="http://x.example/a.mp3"></audio>`, `<video src="http://x.example/a.mp4"></video>`, `<source src="http://x.example/a.webm">`, `<link rel="icon" href="http://x.example/f.ico">`]) {
    assert.equal(checkMixedContent(page({}, html)).status, "warn", html);
  }
});

/* ------------------------------- HSTS ---------------------------- */

test("HSTS weight 8; includeSubDomains/preload are noted without changing the score; HTTP-only HSTS counts as missing", () => {
  const plain = checkHsts(page({ "strict-transport-security": "max-age=31536000" }));
  const full = checkHsts(page({ "strict-transport-security": "max-age=31536000; includeSubDomains; preload" }));
  assert.equal(plain.weight, 8);
  assert.equal(plain.status, "pass");
  assert.equal(full.status, "pass");
  assert.equal(full.weight, plain.weight, "no score change for the extras");
  assert.deepEqual([full.data.includeSubDomains, full.data.preload], [true, true]);
  assert.match(full.summary, /includeSubDomains/);
  assert.match(plain.summary, /Optional: includeSubDomains/);
  const http = { ok: true, responses: [page({ "strict-transport-security": "max-age=31536000", location: "https://example.com/" }, "", "http://example.com/", 301)] };
  const onlyHttp = checkHsts(page(), { http });
  assert.equal(onlyHttp.status, "fail");
  assert.equal(onlyHttp.data.code, "http-only");
});

/* ------------------------------- CSP ----------------------------- */

test("CSP: unsafe-inline without nonce/hash, *, http: or https: sources warn; nonce/hash and strict lists pass", () => {
  const csp = (v) => checkCsp(page({ "content-security-policy": v }));
  assert.equal(csp("script-src 'self' 'unsafe-inline'").status, "warn");
  assert.equal(csp("default-src 'self' 'unsafe-inline'").status, "warn", "default-src is the fallback");
  assert.equal(csp("script-src *").status, "warn");
  assert.equal(csp("script-src 'self' https:").status, "warn");
  assert.equal(csp("default-src http:").status, "warn");
  assert.equal(csp("script-src 'self' 'unsafe-inline' 'nonce-abc123'").status, "pass", "a nonce neutralises unsafe-inline");
  assert.equal(csp("script-src 'self' 'sha256-abc='").status, "pass");
  assert.equal(csp("default-src 'self'; script-src 'self' https://cdn.example").status, "pass");
  assert.equal(csp("frame-ancestors 'self'").status, "warn", "a CSP that doesn't restrict scripts isn't a pass");
  assert.equal(csp("script-src 'self'").weight, 5);
});

test("CSP: a <meta> CSP passes only when it restricts scripts", () => {
  const meta = (v) => checkCsp(page({}, `<meta http-equiv="Content-Security-Policy" content="${v}">`));
  assert.equal(meta("default-src 'self'").status, "pass");
  assert.equal(meta("upgrade-insecure-requests").status, "warn");
  assert.equal(meta("script-src 'self' 'unsafe-inline'").status, "warn");
});

/* ------------------------------ cookies -------------------------- */

test("cookies: missing SameSite alone is info (pass), not a warning", () => {
  const chain = (lines) => ({ ok: true, responses: [page({ "set-cookie": lines })] });
  const r = checkCookies({ https: chain(["PHPSESSID=x; Secure; HttpOnly"]) });
  assert.equal(r.status, "pass");
  assert.match(r.detail, /no SameSite \(browsers default to Lax\)/);
});

test("cookies: missing HttpOnly warns only for session-looking names", () => {
  const chain = (lines) => ({ ok: true, responses: [page({ "set-cookie": lines })] });
  for (const name of ["PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "laravel_session", "wordpress_logged_in_abc", "auth_token", "sid", "my_session"]) {
    const r = checkCookies({ https: chain([`${name}=v; Secure; SameSite=Lax`]) });
    assert.equal(r.status, "warn", name);
    assert.match(r.detail, /missing HttpOnly/, name);
  }
  for (const name of ["cart", "_ga", "lang", "XSRF-TOKEN", "_hjSessionUser_1"]) {
    assert.equal(checkCookies({ https: chain([`${name}=v; Secure; SameSite=Lax`]) }).status, "pass", name);
  }
  assert.equal(checkCookies({ https: chain(["PHPSESSID=v; HttpOnly; SameSite=Lax"]) }).status, "fail", "missing Secure on HTTPS is still red");
});

/* -------------------------------- SRI ---------------------------- */

test("SRI: third-party scripts without integrity warn only for smaller hosts; major CDNs are info; own scripts ignored", () => {
  const sri = (html) => checkSri(page({}, html), "example.com");
  assert.equal(sri(`<script src="/app.js"></script><script src="https://www.example.com/x.js"></script>`).status, "pass");
  assert.equal(sri(`<script src="https://widgets.example.net/w.js" integrity="sha384-abc" crossorigin="anonymous"></script>`).status, "pass");
  const major = sri(`<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>`);
  assert.equal(major.status, "info");
  assert.equal(major.weight, 0);
  const minor = sri(`<script src="//widgets.example.net/w.js"></script><script src="https://www.googletagmanager.com/gtm.js"></script>`);
  assert.equal(minor.status, "warn");
  assert.equal(minor.weight, 3);
  assert.deepEqual(minor.data.hosts, ["widgets.example.net"]);
  assert.deepEqual(findExternalScripts(`<script src="https://a.example/x.js" integrity="sha256-x"></script>`, "example.com").map((s) => s.integrity), [true]);
});

/* -------------------------------- CORS --------------------------- */

test("CORS: wildcard is info; credentials for another origin warn; none is info", () => {
  assert.equal(checkCors(page(), "example.com").status, "info");
  const star = checkCors(page({ "access-control-allow-origin": "*" }), "example.com");
  assert.equal(star.status, "info");
  assert.equal(star.weight, 0);
  const creds = checkCors(page({ "access-control-allow-origin": "https://evil.example", "access-control-allow-credentials": "true" }), "example.com");
  assert.equal(creds.status, "warn");
  assert.equal(creds.weight, 3);
  assert.equal(checkCors(page({ "access-control-allow-origin": "null", "access-control-allow-credentials": "true" }), "example.com").status, "warn");
  assert.equal(checkCors(page({ "access-control-allow-origin": "https://shop.example.com", "access-control-allow-credentials": "true" }), "example.com").status, "info", "own subdomain is fine");
});

/* --------------------------- certificate ------------------------- */

const tlsFor = (days, extra = {}) => ({ ok: true, authorized: true, validTo: new Date(NOW.getTime() + days * 86400000 + 3600000).toISOString(), issuer: "Let's Encrypt", protocol: "TLSv1.3", ...extra });
const cert = (apex, www, usesWww = false) => checkCertificate({ host: "example.com", tls: [{ host: "example.com", ...apex }, { host: "www.example.com", ...www }], usesWww }, { now: () => NOW });

test("certificate (website tool): 20 days warns, 6 days fails, 30 days passes", () => {
  assert.equal(cert(tlsFor(30), tlsFor(30)).status, "pass");
  const twenty = cert(tlsFor(20), tlsFor(90));
  assert.equal(twenty.status, "warn");
  assert.equal(twenty.data.days, 20);
  const six = cert(tlsFor(90), tlsFor(6));
  assert.equal(six.status, "fail");
  assert.equal(six.data.code, "expiring-urgent");
  assert.equal(six.data.host, "www.example.com");
});

test("certificate: invalid on www only warns when the site never uses www; otherwise fails", () => {
  const badWww = { ok: true, authorized: false, authorizationError: "ERR_TLS_CERT_ALTNAME_INVALID", validTo: tlsFor(90).validTo };
  const wwwOnly = cert(tlsFor(90), badWww, false);
  assert.equal(wwwOnly.status, "warn");
  assert.equal(wwwOnly.data.code, "www-invalid");
  assert.equal(wwwOnly.data.host, "www.example.com");
  assert.equal(cert(tlsFor(90), badWww, true).status, "fail", "the site redirects to www, so visitors see the warning");
  assert.equal(cert({ ok: true, authorized: false, authorizationError: "CERT_HAS_EXPIRED" }, tlsFor(90)).data.code, "invalid", "an invalid apex always fails");
});

test("TLS details: info with protocol and key; TLS 1.0/1.1 fails (weight 0)", () => {
  const ok = checkTlsDetails({ host: "example.com", tls: [{ host: "example.com", ...tlsFor(90, { keyType: "EC", keyBits: 256 }) }] });
  assert.equal(ok.status, "info");
  assert.equal(ok.weight, 0);
  assert.match(ok.summary, /TLSv1\.3 with an EC 256-bit key/);
  const old = checkTlsDetails({ host: "example.com", tls: [{ host: "example.com", ...tlsFor(90, { protocol: "TLSv1.1" }) }] });
  assert.equal(old.status, "fail");
  assert.equal(old.weight, 0);
  assert.equal(checkTlsDetails({ host: "example.com", tls: [{ host: "example.com", ...tlsFor(90, { keyType: "RSA", keyBits: 1024 }) }] }).data.code, "weak-key");
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

test("a failed WordPress.org lookup is not cached: the next scan tries again", async () => {
  resetWordPressCache();
  let calls = 0;
  let up = false;
  const fetchImpl = async () => {
    calls++;
    if (!up) return { ok: false, status: 503 };
    return { ok: true, status: 200, json: async () => ({ offers: [{ current: "6.8.3", version: "6.8.3" }] }) };
  };
  assert.equal((await fetchWordPressVersions({ fetchImpl })).ok, false);
  assert.equal((await fetchWordPressVersions({ fetchImpl })).ok, false);
  assert.equal(calls, 2, "a failure is retried on the next call, not served from cache");
  up = true;
  assert.equal((await fetchWordPressVersions({ fetchImpl })).latest, "6.8.3", "recovers as soon as WordPress.org answers");
  assert.equal(calls, 3);
  up = false;
  assert.equal((await fetchWordPressVersions({ fetchImpl })).latest, "6.8.3", "a success is cached");
  assert.equal(calls, 3);
  assert.equal((await fetchWordPressVersions({ fetchImpl, nowMs: Date.now() + 13 * 60 * 60 * 1000 })).ok, false, "and expires after 12 hours");
  resetWordPressCache();
});

test("a scan reports an off-site redirect instead of following it", async () => {
  const log = [];
  const fetchPage = fakeFetchPage({
    "https://example.com/": { status: 301, headers: { location: "https://example.wixsite.com/home" } },
    "http://example.com/": { status: 301, headers: { location: "https://example.com/" } },
  }, log);
  const r = await runWebsiteScan("example.com", { resolver: fakeResolver(siteDns), fetchPage, inspectTls: async () => goodTls, wordpressVersions: versionsOk, now: () => NOW });
  assert.ok(!log.some((u) => u.includes("wixsite")), "the off-site host was never requested");
  assert.equal(r.redirects.stopped.https.offsite, true);
  assert.equal(r.redirects.stopped.https.location, "https://example.wixsite.com/home");
});

/* ------------------------- input validation ---------------------- */

test("target validation: schemes, IP literals, ports and userinfo", () => {
  assert.deepEqual(parseWebsiteTarget("example.com"), { host: "example.com" });
  assert.deepEqual(parseWebsiteTarget("https://www.Example.com/contact?x=1#top"), { host: "example.com" }, "path, query and www dropped");
  assert.deepEqual(parseWebsiteTarget("http://example.com"), { host: "example.com" });
  assert.deepEqual(parseWebsiteTarget("example.com:443"), { host: "example.com" });
  for (const bad of ["", "ftp://example.com", "file:///etc/passwd", "javascript:alert(1)", "https://user:pw@example.com", "user@example.com", "example.com:8080", "https://example.com:8443/",
    "127.0.0.1", "10.0.0.1", "http://169.254.169.254/", "http://[::1]/", "http://2130706433/", "localhost", "http://localhost/", "printer.local"]) {
    assert.ok(parseWebsiteTarget(bad).error, `${bad} must be refused`);
  }
});

/* --------------------------- full scan --------------------------- */

const siteDns = { a: { "example.com": ["93.184.216.34"], "www.example.com": ["93.184.216.34"] } };
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
    "http://example.com/": { status: 301, headers: { location: "https://example.com/" } },
    "https://example.com/": { status: 301, headers: { location: "https://www.example.com/", ...strongHeaders } },
    "https://www.example.com/": { status: 200, headers: strongHeaders, body: "<html><img src=/a.png></html>" },
  });
  const r = await runWebsiteScan("https://example.com/some/path", {
    resolver: fakeResolver(siteDns),
    fetchPage,
    inspectTls: async () => goodTls,
    wordpressVersions: () => assert.fail("not WordPress"),
    now: () => NOW,
  });
  assert.equal(r.target, "example.com");
  assert.equal(r.finalUrl, "https://www.example.com/");
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
    "http://example.com/": { status: 200, headers: { server: "Apache/2.4.29", "set-cookie": ["PHPSESSID=abc; path=/"] }, body: `<meta name="generator" content="WordPress 5.8.1">` },
  });
  const r = await runWebsiteScan("example.com", {
    resolver: fakeResolver(siteDns),
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
  const r = await runWebsiteScan("example.com", { resolver: fakeResolver(), fetchPage: fakeFetchPage({}), inspectTls: async () => ({ ok: false, error: "ENOTFOUND" }), now: () => NOW });
  assert.equal(r.grade, null);
  assert.equal(r.score, null);
});

test("runWebsiteScan refuses bad input without touching the network", async () => {
  const r = await runWebsiteScan("http://127.0.0.1/", { fetchPage: () => assert.fail("no fetch"), inspectTls: () => assert.fail("no TLS") });
  assert.ok(r.error);
});

/* ----------------------------- grade caps ------------------------ */

const strongPage = (url = "https://example.com/") => ({ status: 200, headers: strongHeaders, body: "<html></html>", url });
async function scanWith(routes, { tls = goodTls, wwwTls } = {}) {
  return runWebsiteScan("example.com", {
    resolver: fakeResolver(siteDns),
    fetchPage: fakeFetchPage(routes),
    inspectTls: async (h) => (h.startsWith("www.") && wwwTls ? wwwTls : tls),
    wordpressVersions: versionsOk,
    now: () => NOW,
  });
}

test("caps: no HTTPS → F even with an otherwise decent score", async () => {
  const r = await scanWith({ "http://example.com/": strongPage("http://example.com/") }, { tls: { ok: false, error: "ECONNREFUSED" } });
  assert.equal(r.grade, "F");
  assert.ok(r.data.cappedBy.some((c) => c.check === "https" && c.maxGrade === "F"));
});

test("caps: invalid / expired certificate → F; the score number is the uncapped weighted value", async () => {
  const routes = { "https://example.com/": strongPage(), "http://example.com/": { status: 301, headers: { location: "https://example.com/" } } };
  const bad = { ...goodTls, authorized: false, authorizationError: "CERT_HAS_EXPIRED" };
  const r = await scanWith(routes, { tls: bad });
  assert.equal(r.grade, "F");
  assert.equal(r.data.cappedBy[0].check, "ssl");
  assert.equal(r.data.uncappedGrade, "B", "weighted score alone would be a B");
  assert.equal(r.score, 82); // 70 of 85 points: only the 15-point certificate check is lost
});

test("caps: an https → http downgrade → F", async () => {
  const r = await scanWith({
    "https://example.com/": { status: 301, headers: { location: "http://www.example.com/" } },
    "http://www.example.com/": { status: 200, headers: {}, body: "" },
    "http://example.com/": { status: 301, headers: { location: "https://example.com/" } },
  });
  assert.equal(r.grade, "F");
  assert.ok(r.data.cappedBy.some((c) => /redirects back to plain HTTP/.test(c.reason)));
});

test("caps: HTTP not redirecting to HTTPS → at most C, with the reason on the report", async () => {
  const r = await scanWith({ "https://example.com/": strongPage(), "http://example.com/": { status: 200, headers: {}, body: "" } });
  assert.equal(r.data.uncappedGrade, "A");
  assert.equal(r.grade, "C");
  assert.deepEqual(r.data.cappedBy.map((c) => c.maxGrade), ["C"]);
  assert.match(r.data.cappedBy[0].reason, /isn't redirected to HTTPS/);
});

test("caps: none on a well-configured site; applyGradeCaps keeps the worse grade and leaves null alone", async () => {
  const r = await scanWith({ "https://example.com/": strongPage(), "http://example.com/": { status: 301, headers: { location: "https://example.com/" } } });
  assert.equal(r.grade, "A");
  assert.equal(r.data.cappedBy, null);
  const redirectWarn = [{ id: "https-redirect", status: "warn", data: { code: "no-redirect" } }];
  assert.equal(applyGradeCaps("D", redirectWarn).grade, "D", "a cap never improves a grade");
  assert.equal(applyGradeCaps(null, redirectWarn).grade, null);
  assert.equal(applyGradeCaps("A", [{ id: "tls-details", status: "fail", data: { code: "old-tls" } }]).grade, "B");
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
    resolver: fakeResolver(siteDns),
    fetchPage: fakeFetchPage({ "https://example.com/": { status: 200, headers: { "strict-transport-security": "max-age=31536000" }, body: "<html>SECRET-HTML</html>" } }),
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
  await websiteHandler({ method, url: `/api/website?target=${encodeURIComponent(target)}&consent=true`, headers, socket: {} }, res);
  return { status: res.statusCode, headers: res.headers, json: res.body ? JSON.parse(res.body) : null };
}
const sessionCookie = () => `ohc_tech=${encodeSession(newSession(), SECRET)}`;

test("/api/website: 401 without a session", async () => {
  const r = await callWebsite("example.com", null);
  assert.equal(r.status, 401);
  assert.equal(events.length, 0);
});

test("/api/website: a scan is audited as website_scan with a summary only, and is no-store", async () => {
  const r = await callWebsite("example.com", sessionCookie());
  assert.equal(r.status, 200);
  assert.equal(r.headers["cache-control"], "no-store");
  assert.equal(r.json.target, "example.com");
  const e = events.find((x) => x.event === "website_scan");
  assert.ok(e);
  assert.equal(e.domain, "example.com");
  assert.ok(e.sid && e.ip === "203.0.113.9" && e.ua === "test-agent");
  assert.deepEqual(Object.keys(e.data).sort(), ["consent", "counts", "durationMs", "grade", "score"]);
  assert.equal(e.data.consent, true);
  assert.ok(!JSON.stringify(e).includes("SECRET-HTML"), "no page HTML in the audit log");
  assert.ok(store.events.some((x) => x.event === "website_scan"), "stored durably");
});

test("/api/website: bad targets are 400 and private addresses are refused", async () => {
  const cookie = sessionCookie();
  for (const t of ["localhost", "127.0.0.1", "10.0.0.1", "http://169.254.169.254/", "file:///etc/passwd", "example.com:8080"]) {
    assert.equal((await callWebsite(t, cookie)).status, 400, t);
  }
});

test("/api/website: one site can be checked at most 3 times a minute (429)", async () => {
  const cookie = sessionCookie();
  for (let i = 0; i < 3; i++) assert.equal((await callWebsite("https://www.example.com/x", cookie)).status, 200);
  const r = await callWebsite("example.com", sessionCookie());
  assert.equal(r.status, 429, "the cooldown is per site, across sessions");
  assert.ok(Number(r.headers["retry-after"]) > 0);
  assert.equal((await callWebsite("example.net", cookie)).status, 200, "other sites are unaffected");
});

test("/api/website: only GET", async () => {
  assert.equal((await callWebsite("example.com", sessionCookie(), "POST")).status, 405);
});
