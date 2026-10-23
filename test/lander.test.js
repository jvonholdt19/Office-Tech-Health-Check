// Public lander + preview API, the now-private /api/scan, the scanner's move to /tools/email,
// and the non-compete wording guard. Offline.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import previewHandler, { setPreviewRunnerForTests, PREVIEW_LIMITS, clientKey } from "../api/preview.js";
import { OLD_LINK_REDIRECTS, oldLinkRedirect } from "../lib/redirects.js";
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
// Every scan form now carries the consent checkbox; the API needs consent=true (see test/legal.test.js).
const preview = (domain, opts) => call(previewHandler, `/api/preview?domain=${encodeURIComponent(domain)}&consent=true`, opts);

/* ------------------------------ preview ------------------------------ */

test("preview returns only domain, grade and id/title/status per item", async () => {
  const r = await preview("example.com");
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys(r.json).sort(), ["domain", "grade", "items"]);
  for (const item of r.json.items) assert.deepEqual(Object.keys(item).sort(), ["id", "status", "title"]);
  assert.ok(!JSON.stringify(r.json).includes("spf1") && !JSON.stringify(r.json).includes("never leak"));
  assert.equal(r.headers["cache-control"], "no-store");
  assert.equal(r.headers["access-control-allow-origin"], undefined, "no CORS headers");
});

test("runPreview grades SPF, DMARC and HTTPS only, and returns nothing else", async () => {
  const deps = fakeDeps({
    mx: { "example.com": [{ exchange: "aspmx.l.google.com", priority: 1 }] },
    txt: { "example.com": ["v=spf1 include:_spf.google.com ~all"], "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"], "google._domainkey.example.com": [DKIM_RECORD] },
    tls: { "example.com": goodTls, "www.example.com": goodTls },
  });
  const r = await runPreview("example.com", deps);
  assert.deepEqual(Object.keys(r).sort(), ["domain", "grade", "items"]);
  assert.deepEqual(r.items.map((i) => i.id), ["spf", "dmarc", "ssl"]);
  assert.deepEqual(r.items.map((i) => i.status), ["pass", "pass", "pass"]);
  assert.equal(r.grade, "A");
});

test("preview SSRF: internal names and IPs are refused, and a domain resolving to a private IP is never connected to", async () => {
  for (const d of ["localhost", "10.0.0.1", "169.254.169.254", "127.0.0.1", "intranet.local"]) assert.equal((await preview(d)).status, 400, d);
  const resolver = fakeResolver({ a: { "evil.example.com": ["10.0.0.5"], "www.evil.example.com": ["169.254.169.254"] } });
  const neverConnect = () => assert.fail("must not connect to a private address");
  const r = await runPreview("evil.example.com", { ...fakeDeps(), resolver, inspectTls: (h) => inspectTls(h, { resolver, connect: neverConnect }) });
  assert.equal(r.items.find((i) => i.id === "ssl").status, "info", "HTTPS not checked: no public address");
});

test("preview per-IP limit: 5 per 10 minutes, then 429 with Retry-After", async () => {
  for (let i = 0; i < 5; i++) assert.equal((await preview(`site${i}.example.com`)).status, 200);
  const r = await preview("site9.example.com");
  assert.equal(r.status, 429);
  assert.ok(Number(r.headers["retry-after"]) > 0);
  assert.equal((await preview("site9.example.com", { ip: "198.51.100.7" })).status, 200, "another visitor is unaffected");
  assert.equal((await preview("site8.example.com", { ip: "203.0.113.5", headers: { "x-forwarded-for": "1.2.3.4" } })).status, 429, "x-forwarded-for can't dodge it");
});

test("preview per-IP daily limit: 20 per day", async () => {
  for (let i = 0; i < 20; i++) await store.hit("preview-ip-day:203.0.113.5", 86_400);
  const r = await preview("example.com");
  assert.equal(r.status, 429);
  assert.match(r.json.error, /Daily limit/);
});

test("preview per-domain limit: 3 per 10 minutes across all visitors", async () => {
  for (let i = 0; i < 3; i++) assert.equal((await preview("example.com", { ip: `198.51.100.${i}` })).status, 200);
  const r = await preview("example.com", { ip: "198.51.100.50" });
  assert.equal(r.status, 429);
  assert.match(r.json.error, /checked several times/);
});

test("preview global cap: 300 per hour", async () => {
  for (let i = 0; i < 300; i++) await store.hit("preview-global", 3600);
  assert.equal((await preview("example.com")).status, 429);
  assert.deepEqual(PREVIEW_LIMITS.map((l) => [l.max, l.windowSeconds]), [[5, 600], [20, 86_400], [3, 600], [300, 3600]]);
});

const count = async (key, windowSeconds) => (await store.hit(key, windowSeconds, 0)).count; // read without counting

test("preview: requests over the per-IP limit don't count against the domain or global counters", async () => {
  for (let i = 0; i < 50; i++) await preview("example.com");
  assert.equal(await count("preview-ip:203.0.113.5", 600), 50, "every request still counts against the client itself");
  assert.equal(await count("preview-domain:example.com", 600), 5, "only the 5 requests the per-IP limit allowed reached the domain counter");
  assert.equal(await count("preview-global", 3600), 5, "and the global counter");
});

test("preview: a client over its own limit can't lock a domain for everyone else", async () => {
  for (let i = 0; i < 5; i++) assert.equal((await preview(`other${i}.example.com`)).status, 200, "uses up its own 5");
  for (let i = 0; i < 40; i++) assert.equal((await preview("victim.example.com")).status, 429);
  assert.equal(await count("preview-domain:victim.example.com", 600), 0);
  assert.equal((await preview("victim.example.com", { ip: "198.51.100.20" })).status, 200, "another visitor can still check that domain");
});

test("preview: a client over its own limit can't exhaust the global cap", async () => {
  for (let i = 0; i < 290; i++) await store.hit("preview-global", 3600);
  for (let i = 0; i < 200; i++) await preview(`flood${i}.example.com`);
  assert.equal(await count("preview-global", 3600), 295, "only the flooder's first 5 requests counted");
  assert.equal((await preview("example.com", { ip: "198.51.100.21" })).status, 200);
});

test("preview: IPv6 clients are limited by /64 prefix; IPv4 (and IPv4-mapped IPv6) by address", async () => {
  assert.equal(clientKey("2001:db8:abcd:12:1:2:3:4"), "2001:db8:abcd:12::/64");
  assert.equal(clientKey("2001:DB8:ABCD:0012::ff"), "2001:db8:abcd:12::/64");
  assert.equal(clientKey("2001:db8::1"), "2001:db8:0:0::/64");
  assert.equal(clientKey("::ffff:198.51.100.7"), "198.51.100.7");
  assert.equal(clientKey("203.0.113.5"), "203.0.113.5");
  for (let i = 1; i <= 5; i++) assert.equal((await preview(`v6-${i}.example.com`, { ip: `2001:db8:1:2::${i}` })).status, 200);
  assert.equal((await preview("v6-6.example.com", { ip: "2001:db8:1:2:aaaa:bbbb:cccc:dddd" })).status, 429, "a different address in the same /64 shares the limit");
  assert.equal((await preview("v6-7.example.com", { ip: "2001:db8:1:3::1" })).status, 200, "the next /64 is a different client");
  for (let i = 0; i < 5; i++) await preview(`v4-${i}.example.com`, { ip: "198.51.100.30" });
  assert.equal((await preview("v4-x.example.com", { ip: "198.51.100.31" })).status, 200, "neighbouring IPv4 addresses are separate");
  assert.equal((await preview("v4-y.example.com", { ip: "::ffff:198.51.100.30" })).status, 429, "IPv4-mapped IPv6 is the same client as the IPv4 address");
});

test("preview fails closed (503) without the store, or when it errors", async () => {
  setStoreForTests(null);
  assert.equal((await preview("example.com")).status, 503);
  setStoreForTests({ hit: async () => { throw new Error("down"); }, audit: async () => {} });
  assert.equal((await preview("example.com")).status, 503);
});

test("preview audit: at most one preview_scan per IP per hour, with ip, domain and grade only", async () => {
  await preview("one.example.com");
  await preview("two.example.com");
  await preview("three.example.com", { ip: "198.51.100.9" });
  const audits = events.filter((e) => e.event === "preview_scan");
  assert.equal(audits.length, 2);
  assert.deepEqual(audits.map((e) => e.domain), ["one.example.com", "three.example.com"]);
  assert.deepEqual(audits[0].data, { grade: "C", consent: true });
  assert.equal(audits[0].ip, "203.0.113.5");
  assert.equal(audits[0].sid, undefined);
  assert.equal(audits[0].ua, undefined);
});

test("preview is GET only", async () => {
  assert.equal((await preview("example.com", { method: "POST" })).status, 405);
});

/* ------------------------------ /api/scan ------------------------------ */

test("/api/scan is private now: 401 without a session; works and is audited with one", async () => {
  assert.equal((await call(scanHandler, "/api/scan?domain=example.com")).status, 401);
  setScanDepsForTests(fakeDeps({ mx: { "example.com": [{ exchange: "aspmx.l.google.com", priority: 1 }] } }));
  const cookie = `ohc_tech=${encodeSession(newSession(), SECRET)}`;
  const r = await call(scanHandler, "/api/scan?domain=example.com&consent=true", { headers: { cookie } });
  assert.equal(r.status, 200);
  for (const k of ["domain", "score", "grade", "coverage", "checks", "fixes", "provider"]) assert.ok(k in r.json, k);
  const e = events.find((x) => x.event === "scan");
  assert.ok(e && e.sid && e.domain === "example.com");
  assert.deepEqual(Object.keys(e.data).sort(), ["consent", "counts", "durationMs", "grade", "score"]);
  assert.equal(e.data.consent, true);
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
    assert.equal(r.destination, `/tools/email?d=:${key}`, "the domain is spelled out in the destination");
    assert.equal(r.permanent, false);
  }
  assert.ok(vercel.headers.some((h) => h.source === "/tools/(.*)" && h.headers.some((x) => x.key === "X-Robots-Tag")), "/tools/email and /tools/domain are noindex");
  assert.ok(vercel.headers.some((h) => h.source === "/" && h.headers.some((x) => /noindex/.test(x.value))));
  assert.ok(vercel.functions["api/preview.js"]);
});

test("old links /?domain=x and /?d=x land on /tools/email with the domain filled in", async () => {
  assert.deepEqual(JSON.parse(read("vercel.json")).redirects, OLD_LINK_REDIRECTS, "vercel.json uses the same rules as the dev server");
  assert.deepEqual(oldLinkRedirect("/?domain=example.com"), { status: 307, location: "/tools/email?d=example.com" });
  assert.deepEqual(oldLinkRedirect("/?d=example.com&utm=x"), { status: 307, location: "/tools/email?d=example.com" });
  assert.equal(oldLinkRedirect("/?d=https://evil.example/"), null, "only domain characters are captured");
  assert.equal(oldLinkRedirect("/"), null);

  // The landing page fills the domain in after sign-in (fake DOM, like test/website-page.test.js).
  const els = {};
  const el = (id) => (els[id] ||= { id, hidden: false, value: "", textContent: "", disabled: false, children: [], listeners: {}, addEventListener(t, f) { this.listeners[t] = f; }, focus() {}, replaceChildren() {}, scrollIntoView() {} });
  for (const search of ["?d=example.com", "?domain=example.com"]) {
    for (const k of Object.keys(els)) delete els[k];
    Object.assign(globalThis, {
      document: { getElementById: el, createElement: () => ({ append() {}, setAttribute() {} }), createTextNode: (t) => t },
      location: { search, href: `http://x/tools/email${search}`, pathname: "/tools/email" },
      history: { replaceState() {} },
      fetch: async () => ({ status: 200, ok: true, json: async () => ({ authenticated: true }) }),
    });
    await import(`../public/email.js?t=${Date.now()}${search}`);
    for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
    assert.equal(els.domain.value, "example.com", `${search} pre-fills the domain`);
    assert.equal(els.tool.hidden, false);
  }
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
  // Only exception: the registered legal name on /terms and /privacy (generated from docs/legal).
  const legalName = "NWIM Project Management, a trade name of Northwest Iowa Marketing LLC, an Iowa limited liability company";
  for (const f of files) {
    const raw = readFileSync(f, "utf8");
    const text = /[\\/](terms|privacy)\.html$/.test(f) ? raw.replaceAll(legalName, "") : raw;
    const m = text.match(deny);
    assert.ok(!m, `${f} contains "${m && m[0]}"`);
  }
  assert.ok(files.length >= 10);
});

test("old production hostname is gone", () => {
  for (const f of ["CLAUDE.md", "README.md", "lib/net.js", "test/session.test.js"]) assert.ok(!read(f).includes("office-tech-health-check.vercel.app"), f);
  assert.match(read("lib/net.js"), /"User-Agent": WEBSITE_UA/);
});

/* --------------------------- lander redesign --------------------------- */

test("lander: CSP-safe markup, required contact details, noindex, and no third-party resources", () => {
  const html = read("public/index.html");
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), "no inline <script>");
  assert.ok(!/<style\b/i.test(html), "no <style>");
  assert.ok(!/\sstyle\s*=/i.test(html), "no style= attributes");
  assert.ok(!/\son[a-z]+\s*=/i.test(html), "no on*= attributes");
  for (const s of ["tel:+15073604479", "mailto:info@nwimpm.com", "Powered by NWIM Project Management", 'href="/tools">Tech sign in</a>', '<meta name="robots" content="noindex, nofollow">', "Know where your office's technology stands."]) {
    assert.ok(html.includes(s), s);
  }
  assert.match(html, /<a class="l-btn l-btn-primary" href="tel:\+15073604479">.*Call 507-360-4479<\/a>/);
  assert.match(html, /<a class="l-btn l-btn-ghost" href="mailto:info@nwimpm\.com">.*Email info@nwimpm\.com<\/a>/);
  // Only same-origin resources: no http(s) URLs in src= / <link href> / <use href> (plain <a href> links would be allowed).
  for (const m of html.matchAll(/<(?!a\b)[a-z]+\b[^>]*\b(?:src|href)\s*=\s*"(https?:)?\/\/[^"]*"/gi)) assert.fail(`external resource: ${m[0]}`);
  // Other phone numbers or email addresses would be invented contact details.
  assert.deepEqual([...new Set(html.match(/[\w.+-]+@[\w-]+\.[\w.]+/g))], ["info@nwimpm.com"]);
  assert.deepEqual([...new Set(html.match(/\b\d{3}-\d{3}-\d{4}\b/g))], ["507-360-4479"]);
  assert.match(html, /<body class="lander">/);
  assert.match(html, /<a class="skip-link" href="#main">/);
});

test("lander: no non-compete wording and no invented claims", () => {
  const text = read("public/index.html") + read("public/lander.js");
  const nonCompete = /\b(seo|search engine|google business|reviews?|ranking|marketing|grow your business|more customers)\b/i;
  const fabricated = /\b(testimonial|trusted by|certified|award|\d+\+? (years|clients|customers))\b/i;
  assert.ok(!nonCompete.test(text), `non-compete: "${(text.match(nonCompete) || [])[0]}"`);
  assert.ok(!fabricated.test(text), `invented claim: "${(text.match(fabricated) || [])[0]}"`);
  assert.ok(!/endorsed|partner/i.test(text), "standards are referenced, never endorsements");
  // Josh: no unbuilt tool names in public; a general line instead.
  for (const planned of ["Breach Check", "Exposed Services", "Backup Checklist", "Account Security Checklist", "Device Inventory", "Phishing Quiz", "Planned", "Coming soon"]) assert.ok(!text.includes(planned), planned);
  assert.ok(text.includes("A growing suite of tools for your business technology."));
});

test("lander: the SVG sprite is script-free and style-free", () => {
  const svg = read("public/assets/icons.svg");
  assert.ok(!/<script/i.test(svg) && !/\sstyle\s*=/i.test(svg) && !/\son[a-z]+\s*=/i.test(svg) && !/href\s*=\s*"https?:/i.test(svg));
  const used = [...read("public/index.html").matchAll(/icons\.svg#([\w-]+)/g)].map((m) => m[1]);
  for (const id of new Set(used)) assert.match(svg, new RegExp(`<symbol id="${id}"`), `symbol ${id}`);
  assert.ok(Buffer.byteLength(read("public/index.html") + read("public/lander.css") + read("public/lander.js") + svg) < 60_000, "page budget");
});

test("lander: the local note starts hidden and is shown only when confirmed; preview IDs are unchanged", async () => {
  const html = read("public/index.html");
  assert.match(html, /<p class="l-local-note is-hidden" id="local-note">Built for Local Business<\/p>/);
  for (const id of ["preview-form", "preview-domain", "preview-btn", "preview-error", "preview-loading", "preview-result", "preview-grade", "preview-for", "preview-items"]) assert.match(html, new RegExp(`id="${id}"`), id);

  const classes = new Set(["l-local-note", "is-hidden"]);
  const note = { classList: { toggle: (c, on) => (on ? classes.add(c) : classes.delete(c)) } };
  const els = { "local-note": note };
  globalThis.document = { getElementById: (id) => (els[id] ||= { addEventListener() {}, classList: { toggle() {} } }) };
  const mod = await import(`../public/lander.js?t=${Date.now()}`);
  assert.equal(mod.LOCAL_NOTE_CONFIRMED, true, "Josh confirmed the wording");
  assert.equal(classes.has("is-hidden"), false, "shown on load when confirmed");
  mod.applyLocalNote(note, false);
  assert.equal(classes.has("is-hidden"), true, "hidden when not confirmed");
  mod.applyLocalNote(note, true);
  assert.equal(classes.has("is-hidden"), false);
  assert.match(read("public/lander.css"), /body\.lander \.is-hidden \{ display: none !important; \}/);
});
