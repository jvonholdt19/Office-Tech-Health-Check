// "How to fix" guides: coverage of every warn/fail path, content rules, snippet sanity, message
// placeholders and report size. Offline.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { FIX_GUIDES, guideFor, renderGuide, fillPlaceholders } from "../lib/fix-guides.js";
import * as W from "../lib/checks/website-security.js";
import { runWebsiteScan } from "../lib/website-scan.js";
import { fakeResolver, NOW } from "./fakes.js";

const PLATFORMS = ["cloudflare", "wordpress", "apache", "nginx", "iis", "builders"];
// Website Security Check guides; Domain Health guides (tool: "domain") use registrar/DNS platforms
// and are covered in test/domain-health.test.js.
const WEBSITE_GUIDES = Object.entries(FIX_GUIDES).filter(([, g]) => g.tool !== "domain");
const page = (headers = {}, body = "", url = "https://example.com/", status = 200) => ({ ok: true, url, status, headers, body, truncated: false });
const chain = (responses, extra = {}) => ({ ok: true, responses, final: responses.at(-1), ...extra });
const tls = (o) => [{ host: "example.com", ok: true, authorized: true, validTo: new Date(NOW.getTime() + 90 * 864e5).toISOString(), protocol: "TLSv1.3", ...o }];
const now = { now: () => NOW };

// Every warn/fail outcome the website checks can produce, built by running the real check functions.
async function flaggedOutcomes() {
  const out = [];
  const add = (r) => (r.status === "warn" || r.status === "fail") && out.push(r);
  add(W.checkHttpsAvailable({ host: "example.com", https: { ok: false, error: "ECONNREFUSED" }, http: chain([page({}, "", "http://example.com/")]) }));
  add(W.checkHttpsAvailable({ host: "example.com", https: chain([page({ location: "http://example.com/" }, "", "https://example.com/", 301), page({}, "", "http://example.com/")], { downgraded: true }), http: null }));
  add(W.checkHttpRedirect({ http: chain([page({}, "", "http://example.com/")]) }));
  for (const t of [tls({ authorized: false, authorizationError: "CERT_HAS_EXPIRED" }), tls({ validTo: new Date(NOW.getTime() + 15 * 864e5).toISOString() }), tls({ validTo: new Date(NOW.getTime() + 3 * 864e5).toISOString() })]) {
    add(W.checkCertificate({ host: "example.com", tls: t, usesWww: false }, now));
  }
  add(W.checkCertificate({ host: "example.com", tls: [...tls({}), { host: "www.example.com", ok: true, authorized: false, authorizationError: "ERR_TLS_CERT_ALTNAME_INVALID" }], usesWww: false }, now));
  add(W.checkTlsDetails({ host: "example.com", tls: tls({ protocol: "TLSv1" }) }));
  add(W.checkTlsDetails({ host: "example.com", tls: tls({ keyType: "RSA", keyBits: 1024 }) }));
  add(W.checkHsts(null));
  add(W.checkHsts(page()));
  add(W.checkHsts(page(), { http: chain([page({ "strict-transport-security": "max-age=600" }, "", "http://example.com/")]) }));
  add(W.checkHsts(page({ "strict-transport-security": "max-age=0" })));
  add(W.checkHsts(page({ "strict-transport-security": "max-age=600" })));
  add(W.checkFraming(page()));
  add(W.checkFraming(page({ "x-frame-options": "ALLOW-FROM https://x.example" })));
  add(W.checkNosniff(page()));
  add(W.checkCsp(page()));
  add(W.checkCsp(page({ "content-security-policy-report-only": "default-src 'self'" })));
  add(W.checkCsp(page({ "content-security-policy": "script-src *" })));
  add(W.checkCsp(page({ "content-security-policy": "frame-ancestors 'self'" })));
  add(W.checkReferrerPolicy(page({ "referrer-policy": "unsafe-url" })));
  add(W.checkCors(page({ "access-control-allow-origin": "https://evil.example", "access-control-allow-credentials": "true" }), "example.com"));
  add(W.checkCookies({ https: chain([page({ "set-cookie": ["PHPSESSID=1; HttpOnly"] })]) }));
  add(W.checkCookies({ https: chain([page({ "set-cookie": ["PHPSESSID=1; Secure"] })]) }));
  add(W.checkMixedContent(page({}, `<script src="http://x.example/a.js"></script>`)));
  add(W.checkMixedContent(page({}, `<img src="http://x.example/a.png">`)));
  add(W.checkSri(page({}, `<script src="https://widgets.example.net/w.js"></script>`), "example.com"));
  add(W.checkVersionDisclosure(page({ server: "Apache/2.4.1" })));
  const versions = async () => ({ ok: true, latest: "6.8.3" });
  add(await W.checkWordPress(page({}, `<meta name="generator" content="WordPress 6.8.1">`), { wordpressVersions: versions }));
  add(await W.checkWordPress(page({}, `<meta name="generator" content="WordPress 6.2">`), { wordpressVersions: versions }));
  return out;
}

test("every warn/fail outcome has a guide, and every data.code it carries resolves (variant or default)", async () => {
  const outcomes = await flaggedOutcomes();
  assert.ok(outcomes.length >= 30, `exercised ${outcomes.length} flagged outcomes`);
  for (const r of outcomes) {
    assert.ok(FIX_GUIDES[r.id], `guide for ${r.id}`);
    const g = guideFor(r.id, r.data?.code);
    assert.ok(g && g.why && g.platforms, `${r.id}/${r.data?.code}`);
    if (FIX_GUIDES[r.id].variants?.[r.data?.code]) assert.equal(g.code, r.data.code);
  }
  // Codes we expect to be distinct guides really are.
  for (const [id, code] of [["https", "downgrade"], ["ssl", "www-invalid"], ["hsts", "short"], ["csp", "report-only"], ["cookies", "httponly-missing"], ["mixed-content", "passive"], ["cms-wordpress", "branches-behind"], ["tls-details", "weak-key"]]) {
    assert.equal(guideFor(id, code).code, code, `${id}/${code}`);
    assert.notEqual(guideFor(id, code).why, guideFor(id, null).why, `${id}/${code} has its own why`);
  }
  assert.equal(guideFor("no-such-check"), null);
});

test("cross-check: every check id in the source that can warn or fail has a guide", () => {
  const src = readFileSync(new URL("../lib/checks/website-security.js", import.meta.url), "utf8");
  // Split the source at each check's base definition and keep ids whose function body can warn/fail.
  const parts = src.split(/const base = \{ id: "/).slice(1);
  const flagged = parts.filter((p) => /status: "(warn|fail)"|status: worst|status: active\.length/.test(p)).map((p) => p.slice(0, p.indexOf('"')));
  assert.ok(flagged.length >= 15, flagged.join(","));
  for (const id of flagged) assert.ok(FIX_GUIDES[id], `guide for ${id}`);
  assert.ok(FIX_GUIDES["permissions-policy"], "optional guide for the info-only Permissions-Policy");
});

test("every guide has the required fields, https sources and all six platforms", () => {
  for (const [id, g] of WEBSITE_GUIDES) {
    for (const k of ["why", "message", "verify"]) assert.ok(typeof g[k] === "string" && g[k].length > 20, `${id}.${k}`);
    assert.ok(typeof g.time === "string" && /\d/.test(g.time), `${id}.time`);
    assert.ok(["easy", "moderate", "advanced"].includes(g.difficulty), `${id}.difficulty`);
    assert.ok(Array.isArray(g.sources) && g.sources.length > 0, `${id}.sources`);
    for (const u of g.sources) assert.match(u, /^https:\/\/[a-z0-9.-]+\//, `${id} source ${u}`);
    assert.deepEqual(g.platforms.map((p) => p.id).sort(), [...PLATFORMS].sort(), `${id} platforms`);
    for (const p of g.platforms) {
      assert.ok(p.label && p.steps.length > 0, `${id}/${p.id} steps`);
      assert.ok([true, false, "partial"].includes(p.possible), `${id}/${p.id} possible`);
    }
    for (const [code, v] of Object.entries(g.variants || {})) {
      if (v.difficulty) assert.ok(["easy", "moderate", "advanced"].includes(v.difficulty), `${id}/${code}`);
    }
  }
});

test("risk warnings are present where a change can break things", () => {
  for (const id of ["hsts", "csp", "clickjacking", "cookies", "tls-details", "cms-wordpress"]) assert.ok(FIX_GUIDES[id].risk?.length > 40, id);
  assert.match(FIX_GUIDES.hsts.risk, /max-age=300/);
  assert.match(FIX_GUIDES.hsts.risk, /includeSubDomains/);
  assert.match(FIX_GUIDES.hsts.risk, /preload/i);
  assert.match(FIX_GUIDES.csp.risk, /Report-Only/);
  assert.match(FIX_GUIDES.csp.risk, /unsafe-inline/);
  assert.match(FIX_GUIDES.clickjacking.risk, /SAMEORIGIN/);
  assert.match(FIX_GUIDES["cms-wordpress"].risk, /backup/i);
});

const allSnippets = () => WEBSITE_GUIDES.flatMap(([id, g]) => g.platforms.filter((p) => p.snippet).map((p) => ({ id, platform: p.id, ...p.snippet })));

test("HSTS snippets never include preload; CSP snippets are Report-Only", () => {
  const hsts = allSnippets().filter((s) => s.id === "hsts");
  assert.ok(hsts.length >= 3);
  for (const s of hsts) assert.ok(!/preload/i.test(s.code), `${s.platform}: no preload`);
  for (const p of FIX_GUIDES.hsts.platforms) for (const step of p.steps) assert.ok(!/\bpreload\b/i.test(step) || /off|don't|not/i.test(step), `hsts/${p.id} step doesn't recommend preload`);
  const csp = allSnippets().filter((s) => /Content-Security-Policy/.test(s.code));
  assert.ok(csp.length >= 3);
  for (const s of csp) assert.match(s.code, /Content-Security-Policy-Report-Only/, `${s.id}/${s.platform}`);
  for (const step of FIX_GUIDES.csp.platforms.find((p) => p.id === "cloudflare").steps) {
    if (/Header name: Content-Security-Policy/.test(step)) assert.match(step, /Report-Only/);
  }
});

test("snippet sanity: nginx add_header lines end with always;, Apache Header lines sit inside <IfModule mod_headers.c>", () => {
  for (const s of allSnippets()) {
    if (s.lang === "nginx") {
      for (const line of s.code.split("\n").filter((l) => /^\s*add_header\b/.test(l))) assert.match(line, /\salways;\s*$/, `${s.id}: ${line}`);
    }
    if (s.lang === "apache") {
      const lines = s.code.split("\n");
      let depth = null;
      lines.forEach((line) => {
        if (/<IfModule mod_headers\.c>/.test(line)) depth = "headers";
        if (/<\/IfModule>/.test(line)) depth = null;
        if (/^\s*Header\s/.test(line)) assert.equal(depth, "headers", `${s.id}: ${line}`);
      });
      const opens = (s.code.match(/<IfModule\b/g) || []).length;
      assert.equal(opens, (s.code.match(/<\/IfModule>/g) || []).length, `${s.id}: balanced IfModule`);
    }
  }
});

/** Minimal XML well-formedness check (no dependencies): balanced tags, quoted attributes, one root. */
function assertWellFormedXml(xml, label) {
  const stack = [];
  let roots = 0;
  const text = xml.replace(/<!--[\s\S]*?-->/g, "");
  for (const m of text.matchAll(/<(\/?)([A-Za-z_][\w:.-]*)((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>/g)) {
    const [, closing, name, , selfClosing] = m;
    if (closing) assert.equal(stack.pop(), name, `${label}: </${name}> closes the open tag`);
    else if (!selfClosing) {
      if (!stack.length) roots++;
      stack.push(name);
    } else if (!stack.length) roots++;
  }
  assert.deepEqual(stack, [], `${label}: all tags closed`);
  assert.equal(roots, 1, `${label}: one root element`);
  // Anything that looks like a tag but didn't match the pattern above is malformed.
  const tags = (text.match(/<[^>]*>/g) || []).filter((t) => !/^<\?xml/.test(t));
  const ok = tags.filter((t) => /^<\/?[A-Za-z_][\w:.-]*((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*\/?>$/.test(t));
  assert.equal(ok.length, tags.length, `${label}: every tag well-formed`);
}

test("IIS snippets are well-formed XML fragments to merge, with <remove> before every <add>", () => {
  const xml = allSnippets().filter((s) => s.platform === "iis");
  assert.ok(xml.length >= 8);
  for (const s of xml) {
    // Fragments are merged into existing web.config sections, so check them inside a synthetic root.
    assertWellFormedXml(`<fragment>${s.code}</fragment>`, `${s.id}/iis`);
    assert.ok(!/<configuration>/.test(s.code), `${s.id}/iis: no whole <configuration> block`);
    assert.match(s.code, /<!-- web\.config: inside <system\.webServer>/, `${s.id}/iis: says which section to merge into`);
    if (/<customHeaders>|<add name=/.test(s.code)) {
      for (const m of s.code.matchAll(/<add name="([^"]+)"/g)) {
        const at = s.code.indexOf(m[0]);
        assert.ok(s.code.lastIndexOf(`<remove name="${m[1]}" />`, at) !== -1, `${s.id}/iis: <remove name="${m[1]}"/> before its <add>`);
      }
    }
  }
  for (const [id, g] of WEBSITE_GUIDES) {
    const iis = g.platforms.find((p) => p.id === "iis");
    if (iis.snippet) assert.ok(iis.steps.some((t) => /Don't paste a second <configuration> block/.test(t)), `${id}/iis steps say merge, don't paste`);
  }
  assert.throws(() => assertWellFormedXml("<configuration><a></configuration>", "bad"));
});

test("Cloudflare: the one-click Managed Transform is offered where it covers the header, with the manual rule kept", () => {
  const cf = (id) => FIX_GUIDES[id].platforms.find((p) => p.id === "cloudflare").steps.join(" ");
  for (const id of ["clickjacking", "nosniff", "referrer-policy"]) {
    assert.match(cf(id), /Rules Settings page, open the Managed Transforms tab and turn on Add security headers/, id);
    assert.match(cf(id), /Response Header Transform Rule/, `${id}: manual option kept`);
    assert.ok(FIX_GUIDES[id].sources.some((u) => /managed-transforms/.test(u)), `${id}: source`);
  }
  assert.match(cf("version-disclosure"), /Remove "X-Powered-By" headers/);
  for (const id of ["hsts", "csp", "permissions-policy"]) assert.match(cf(id), /doesn't include this header/, `${id}: not covered by the managed transform`);
});

test("CSP guide notes that report-only violations show in the console and no reporting endpoint is set up", () => {
  assert.match(FIX_GUIDES.csp.note, /browser console/);
  assert.match(FIX_GUIDES.csp.note, /reporting endpoint/);
  assert.equal(guideFor("csp", "weak").note, FIX_GUIDES.csp.note, "variants keep the note");
});

test("messages: every placeholder is filled and nothing else about who ran the scan", async () => {
  for (const r of await flaggedOutcomes()) {
    const g = renderGuide(r, "example.com");
    assert.ok(!/\{(domain|finding|detail)\}/.test(g.message), `${r.id}: placeholders filled`);
    assert.ok(!/\{[a-z]+\}/i.test(g.message), `${r.id}: no {…} left`);
    assert.ok(!/\{[a-z]+\}/i.test(g.verify), `${r.id}: verify filled`);
    assert.match(g.message, /example\.com/);
    assert.match(g.message, /our IT provider/i);
    assert.ok(!/office tech|nwimpm/i.test(g.message), `${r.id}: doesn't name the scanner`);
  }
  // Remote text is inserted once and never re-expanded.
  assert.equal(fillPlaceholders("{detail}", { domain: "d", finding: "", detail: "{domain}" }), "{domain}");
});

test("snippets keep server-side variables like {HTTPS} and {R:1} but fill {domain}", () => {
  const g = renderGuide({ id: "https-redirect", status: "warn", summary: "x", detail: "y", data: { code: "no-redirect" } }, "example.com");
  const iis = g.platforms.find((p) => p.id === "iis").snippet.code;
  assert.match(iis, /\{HTTPS\}/);
  assert.match(iis, /\{R:1\}/);
  assert.match(g.platforms.find((p) => p.id === "nginx").snippet.code, /server_name example\.com www\.example\.com;/);
});

test("the report carries guides only for warn/fail checks, and stays small in the worst case", async () => {
  const routes = {
    "http://example.com/": page({ server: "Apache/2.4.29", "set-cookie": ["PHPSESSID=1"] }, `<meta name="generator" content="WordPress 5.0">`, "http://example.com/"),
    "https://example.com/": page(
      { server: "Apache/2.4.29", "x-frame-options": "ALLOW-FROM x", "content-security-policy": "script-src *", "referrer-policy": "unsafe-url", "set-cookie": ["PHPSESSID=1", "auth_token=2; Secure"], "access-control-allow-origin": "null", "access-control-allow-credentials": "true" },
      `<meta name="generator" content="WordPress 5.0"><script src="http://static.example.org/a.js"></script><script src="https://widgets.example.net/w.js"></script>` + "<p>filler</p>".repeat(2000),
    ),
  };
  const r = await runWebsiteScan("example.com", {
    resolver: fakeResolver(),
    fetchPage: async (url) => routes[url] || { ok: false, error: "ECONNREFUSED" },
    inspectTls: async () => ({ ok: true, authorized: true, validTo: new Date(NOW.getTime() + 3 * 864e5).toISOString(), protocol: "TLSv1", keyType: "RSA", keyBits: 1024 }),
    wordpressVersions: async () => ({ ok: true, latest: "6.8.3" }),
    now: () => NOW,
  });
  const flagged = r.checks.filter((c) => c.status === "warn" || c.status === "fail");
  assert.ok(flagged.length >= 12, `worst case flags ${flagged.length} checks`);
  for (const c of r.checks) assert.equal(Boolean(c.guide), c.status === "warn" || c.status === "fail", `${c.id} (${c.status})`);
  const size = Buffer.byteLength(JSON.stringify(r));
  assert.ok(size < 150_000, `report is ${size} bytes`);
});
