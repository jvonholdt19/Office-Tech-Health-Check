// Interim legal pages, footer links, the results disclaimer, consent before every scan, breach-data
// attribution and the founding-testimonial disclosure. Offline.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { RESULTS_DISCLAIMER, FIX_PLAN_TERMS, CONSENT_LABEL, CONSENT_NOTE, disclaimerBlock, inlineNodes, wireConsent } from "../public/legal.js";
import { LEGAL_PAGES, legalHtml, withLegalText, START, END } from "../scripts/sync-legal.js";
import { PAGES, footer, FOOTER_RE } from "../scripts/site-chrome.js";
import { consentGiven, CONSENT_REQUIRED } from "../lib/consent.js";
import { breachCheckEnabled } from "../lib/features.js";
import * as CONFIG from "../lib/config.js";
import previewHandler, { setPreviewRunnerForTests } from "../api/preview.js";
import scanHandler, { setScanDepsForTests } from "../api/scan.js";
import websiteHandler from "../api/website.js";
import domainHandler from "../api/domain.js";
import planHandler from "../api/plan.js";
import { setStoreForTests, memoryStore } from "../lib/store.js";
import { onAudit } from "../lib/audit.js";
import { encodeSession, newSession } from "../lib/session.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (p) => readFileSync(join(root, p), "utf8");
const SECRET = "test-session-secret-0123456789-abcdefgh";
const LEGAL = Object.keys(LEGAL_PAGES);
const HTML = (() => {
  const out = [];
  const walk = (dir) => {
    for (const f of readdirSync(dir)) {
      const p = join(dir, f);
      if (statSync(p).isDirectory()) walk(p);
      else if (f.endsWith(".html")) out.push(relative(root, p).split("\\").join("/"));
    }
  };
  walk(join(root, "public"));
  return out;
})();

/** Minimal DOM for the createElement/textContent renderers. */
function fakeDoc() {
  class El {
    constructor(tag) {
      this.tagName = tag.toUpperCase();
      this.children = [];
      this.attrs = {};
      this.className = "";
      this.listeners = {};
    }
    setAttribute(k, v) {
      this.attrs[k] = v;
    }
    addEventListener(t, f) {
      this.listeners[t] = f;
    }
    append(...c) {
      this.children.push(...c);
    }
    replaceChildren(...c) {
      this.children = c;
    }
    set textContent(v) {
      this.children = [String(v)];
    }
    get textContent() {
      return this.children.map((c) => (typeof c === "string" ? c : c.textContent)).join("");
    }
  }
  return { createElement: (t) => new El(t), createTextNode: (t) => t };
}

/* -------------------------------- documents -------------------------------- */

test("docs/legal holds the four source documents, without the word 'Marketing'", () => {
  for (const f of ["terms-of-service.md", "privacy-policy.md", "scan-results-disclaimer.md", "client-service-agreement.md"]) {
    const text = read(`docs/legal/${f}`);
    assert.ok(text.length > 300, f);
    assert.ok(!/marketing/i.test(text), f);
    assert.ok(!/â€|Ã/.test(text), `${f}: no garbled characters`);
  }
});

test("the disclaimer lives in one place (public/legal.js) and matches docs/legal/scan-results-disclaimer.md word for word", () => {
  const quotes = [...read("docs/legal/scan-results-disclaimer.md").matchAll(/^> (.+)$/gm)].map((m) => m[1]);
  assert.deepEqual(quotes, [RESULTS_DISCLAIMER, FIX_PLAN_TERMS]);
  // No page or page script carries its own copy of the wording.
  for (const f of [...HTML, "public/lander.js", "public/email.js", "public/report-view.js", "public/plan.js", "public/website.js", "public/domain.js"]) {
    assert.ok(!read(f).includes("snapshot of public information at the time of the check"), `${f}: uses public/legal.js`);
  }
});

/* ------------------------------- legal pages ------------------------------- */

test("/terms and /privacy: generated from docs/legal between the markers, with one 'Last updated' at the top", () => {
  assert.deepEqual(LEGAL, ["public/terms.html", "public/privacy.html"]);
  for (const [page, source] of Object.entries(LEGAL_PAGES)) {
    const html = read(page);
    assert.equal(withLegalText(html, read(source), source), html, `${page} is out of date: run node scripts/sync-legal.js`);
    assert.equal(html.split(START).length, 2, `${page}: one LEGAL TEXT START`);
    assert.equal(html.split(END).length, 2, `${page}: one LEGAL TEXT END`);
    assert.equal((html.match(/id="last-updated"/g) || []).length, 1, page);
    assert.match(html, /<h1 id="legal-title">[^<]+<\/h1>\n\s+<p><strong>Office Tech Health Check, provided by NWIM Project Management<\/strong><\/p>\n\s+<p class="legal-updated" id="last-updated">Last updated: \[DATE\]<\/p>/, `${page}: Last updated right under the title`);
    assert.match(html, /<body class="lander">/, `${page}: same CSS as the lander`);
    assert.ok(html.includes('<link rel="stylesheet" href="/lander.css">'));
    assert.equal(PAGES[page].kind, "lander", `${page}: the public header and footer`);
    assert.ok(!/<script/i.test(html), `${page}: no scripts at all`);
    assert.ok(!/name="robots"/.test(html), `${page}: may be indexed`);
    assert.ok(!/marketing/i.test(html), page);
  }
  assert.match(read("public/terms.html"), /<h1 id="legal-title">Terms of Service<\/h1>/);
  assert.match(read("public/privacy.html"), /<h1 id="legal-title">Privacy Policy<\/h1>/);
  assert.ok(!read("vercel.json").includes("/terms") && !read("vercel.json").includes("/privacy"), "no X-Robots-Tag or other headers added for them");
});

test("the Markdown converter: headings, lists, notes, bold, code, safe links, everything escaped", () => {
  const html = legalHtml("# T\n\nLast updated: [DATE]\n\n> Draft\n\n## 1. Who we are\nLine one\nline <two> & **bold** `code` [Terms](/terms) [x](javascript:alert(1))\n\n- a\n- **b.** c", "");
  assert.equal(
    html,
    [
      '<h1 id="legal-title">T</h1>',
      '<p class="legal-updated" id="last-updated">Last updated: [DATE]</p>',
      '<p class="legal-note" role="note">Draft</p>',
      '<h2 id="who-we-are">1. Who we are</h2>',
      '<p>Line one line &lt;two&gt; &amp; <strong>bold</strong> <code>code</code> <a href="/terms">Terms</a> [x](javascript:alert(1))</p>',
      "<ul>",
      "  <li>a</li>",
      "  <li><strong>b.</strong> c</li>",
      "</ul>",
    ].join("\n"),
  );
});

/* ------------------------------- footer links ------------------------------- */

test("every page's footer links to /terms and /privacy (public and technician footers)", () => {
  for (const kind of ["lander", "tool", "dashboard", "plan"]) {
    const f = footer({ kind });
    assert.match(f, /<a href="\/terms">Terms<\/a> · <a href="\/privacy">Privacy<\/a>/, kind);
  }
  for (const page of HTML) {
    const f = read(page).match(FOOTER_RE)?.[0] || "";
    assert.ok(f.includes('<a href="/terms">Terms</a>') && f.includes('<a href="/privacy">Privacy</a>'), page);
  }
});

/* -------------------------------- disclaimer -------------------------------- */

test("disclaimer block: the text with real links to /terms and /privacy, plus the service-agreement line on Fix Plans", () => {
  const doc = fakeDoc();
  const box = disclaimerBlock({}, doc);
  assert.equal(box.className, "results-disclaimer");
  assert.equal(box.attrs.role, "note");
  assert.equal(box.textContent, RESULTS_DISCLAIMER.replace("[Terms](/terms)", "Terms").replace("[Privacy Policy](/privacy)", "Privacy Policy"));
  const links = box.children[0].children.filter((c) => typeof c !== "string");
  assert.deepEqual(links.map((a) => [a.attrs.href, a.textContent]), [["/terms", "Terms"], ["/privacy", "Privacy Policy"]]);
  const plan = disclaimerBlock({ fixPlan: true }, doc);
  assert.equal(plan.children[1].textContent, FIX_PLAN_TERMS);
  assert.deepEqual(inlineNodes("go [here](https://evil.example.net)", doc), ["go [here](https://evil.example.net)"], "only same-site links");
});

test("the disclaimer appears on the lander preview, the Email, Website and Domain reports, and the Fix Plan (screen and print)", () => {
  assert.match(read("public/index.html"), /<div class="preview-result" id="preview-result" hidden>[\s\S]*<div class="preview-disclaimer" id="preview-disclaimer"><\/div>[\s\S]*<\/div>/);
  assert.match(read("public/lander.js"), /fillDisclaimer\(\$\("preview-disclaimer"\)\);/);
  assert.match(read("public/tools/email.html"), /<section class="report wrap" id="report" hidden>[\s\S]*<div id="results-disclaimer"><\/div>/);
  assert.match(read("public/email.js"), /fillDisclaimer\(\$\("results-disclaimer"\)\);/);
  // Website and Domain reports share report-view.js.
  assert.match(read("public/report-view.js"), /disclaimerBlock\(\),\n\s+h\("p", \{ class: "report-foot" \}/);
  for (const f of ["public/website.js", "public/domain.js"]) assert.match(read(f), /createReportView\(/, f);
  // Fix Plan: in the client document (printed), never inside a no-print block.
  const plan = read("public/plan.js");
  assert.match(plan, /root\.append\(disclaimerBlock\(\{ fixPlan: true \}\)\);/);
  const css = read("public/brand.css");
  assert.ok(!/\.results-disclaimer[^{]*\{[^}]*display:\s*none/.test(css), "never hidden in print");
});

/* ----------------------------- consent checkbox ----------------------------- */

const FORMS = {
  "public/index.html": ["preview-form", "preview-consent", "public/lander.js", "preview-btn"],
  "public/tools/email.html": ["scan-form", "scan-consent", "public/email.js", "els.button"],
  "public/tools/website.html": ["website-form", "website-consent", "public/website.js", "website-btn"],
  "public/tools/domain.html": ["domain-form", "domain-consent", "public/domain.js", "domain-btn"],
  "public/plan.html": ["plan-form", "plan-consent", "public/plan.js", "plan-btn"],
};

test("every scan form has the required consent checkbox, and its script keeps the button disabled until it's ticked", () => {
  assert.equal(CONSENT_LABEL, "I own this domain or have the owner's permission to check it.");
  for (const [page, [form, id, script, button]] of Object.entries(FORMS)) {
    const html = read(page);
    assert.ok(html.includes(`<label><input type="checkbox" id="${id}" form="${form}" required aria-describedby="${id}-note"> ${CONSENT_LABEL}</label></p>`), `${page}: checkbox`);
    // The explanation sits right under it, empty in the page: legal.js fills it from CONSENT_NOTE.
    assert.match(html, new RegExp(`aria-describedby="${id}-note">[^\\n]*</p>\\n\\s*<p class="consent-note( no-print)?" id="${id}-note"></p>`), `${page}: note`);
    assert.ok(!html.includes("read-only check of public records"), `${page}: note text lives in public/legal.js`);
    const js = read(script);
    const btnRef = button.startsWith("els.") ? button.replace(".", "\\.") : `\\$\\("${button}"\\)`;
    assert.match(js, new RegExp(`wireConsent\\(\\$\\("${id}"\\), ${btnRef}\\)`), `${script}: wired to ${button}`);
    assert.match(js, /consent\.ok\(\)/, `${script}: checks consent on submit`);
    assert.match(js, /consent=true|consent: true/, `${script}: sends consent to the API`);
    assert.ok(!/\son[a-z]+=/i.test(html) && !/<script(?![^>]*\bsrc=)/.test(html), `${page}: no inline JS`);
  }
  // The Fix Plan no longer builds a plan by itself from a ?d= link: it only pre-fills the domain.
  const plan = read("public/plan.js");
  assert.ok(!/if \(d\) buildPlan\(d\)/.test(plan));
  assert.match(plan, /function prefillFromLink\(\)/);
});

test("consent note: one shared text, linking Terms, filled into the element the checkbox's aria-describedby names", () => {
  assert.equal(
    CONSENT_NOTE.replace("[Terms](/terms)", "Terms"),
    "This runs a read-only check of public records (DNS, email settings, and your homepage). Nothing is changed or logged into. By checking this box you confirm you're allowed to request this check and agree to our Terms.",
  );
  const doc = fakeDoc();
  const note = doc.createElement("p");
  doc.getElementById = (id) => (id === "x-consent-note" ? note : null);
  const box = doc.createElement("input");
  box.ownerDocument = doc;
  box.getAttribute = (k) => (k === "aria-describedby" ? "x-consent-note" : null);
  wireConsent(box, doc.createElement("button"));
  assert.equal(note.textContent, CONSENT_NOTE.replace("[Terms](/terms)", "Terms"));
  const links = note.children.filter((c) => typeof c !== "string");
  assert.deepEqual(links.map((a) => [a.attrs.href, a.textContent]), [["/terms", "Terms"]]);
  for (const f of [...HTML, "public/lander.js", "public/email.js", "public/plan.js", "public/website.js", "public/domain.js"]) {
    assert.ok(!read(f).includes("Nothing is changed or logged into"), `${f}: uses public/legal.js`);
  }
});

test("wireConsent: disabled until ticked, enabled when ticked, disabled again when unticked", () => {
  const doc = fakeDoc();
  const box = doc.createElement("input");
  const btn = doc.createElement("button");
  box.checked = false;
  const c = wireConsent(box, btn);
  assert.equal(btn.disabled, true);
  assert.equal(c.ok(), false);
  box.checked = true;
  box.listeners.change();
  assert.equal(btn.disabled, false);
  assert.equal(c.ok(), true);
  box.checked = false;
  box.listeners.change();
  assert.equal(btn.disabled, true);
  btn.disabled = false; // a scan finished and re-enabled it
  c.refresh();
  assert.equal(btn.disabled, true, "refresh() respects the checkbox again");
});

/* ------------------------------ server side ------------------------------ */

let saved;
let events;
let stop;
beforeEach(() => {
  saved = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = SECRET;
  setStoreForTests(memoryStore());
  events = [];
  stop = onAudit((e) => events.push(e));
});
afterEach(() => {
  stop();
  setStoreForTests(undefined);
  setPreviewRunnerForTests(null);
  setScanDepsForTests(null);
  if (saved === undefined) delete process.env.SESSION_SECRET;
  else process.env.SESSION_SECRET = saved;
});
async function call(handler, url, { method = "GET", body, signedIn = true } = {}) {
  const res = { statusCode: 0, headers: {}, body: "", setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(b) { this.body = b ?? ""; } };
  const req = {
    method,
    url,
    headers: { host: "officetech.nwimpm.com", origin: "https://officetech.nwimpm.com", "x-real-ip": "203.0.113.5", "user-agent": "t", ...(signedIn ? { cookie: `ohc_tech=${encodeSession(newSession(), SECRET)}` } : {}) },
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
  return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : null };
}

test("consentGiven: only an explicit consent=true or { consent: true }", () => {
  const u = (q) => new URL(`http://x/api?${q}`);
  assert.equal(consentGiven(u("consent=true")), true);
  for (const q of ["", "consent=1", "consent=TRUE", "consent=yes", "consent="]) assert.equal(consentGiven(u(q)), false, q);
  assert.equal(consentGiven(null, { consent: true }), true);
  assert.equal(consentGiven(null, { consent: "true" }), false);
  assert.equal(consentGiven(null, null), false);
});

test("the scan APIs refuse a request without consent (400, plain message) before scanning or counting anything", async () => {
  let ran = 0;
  setPreviewRunnerForTests(async () => {
    ran++;
    return { domain: "example.com", grade: "A", items: [] };
  });
  setScanDepsForTests({ resolver: { resolveMx: async () => (ran++, []) } });
  const cases = [
    [previewHandler, "/api/preview?domain=example.com", { signedIn: false }],
    [scanHandler, "/api/scan?domain=example.com", {}],
    [websiteHandler, "/api/website?target=example.com", {}],
    [domainHandler, "/api/domain?domain=example.com", {}],
    [planHandler, "/api/plan?domain=example.com", {}],
    [planHandler, "/api/plan", { method: "POST", body: { domain: "example.com" } }],
    [previewHandler, "/api/preview?domain=example.com&consent=yes", { signedIn: false }],
  ];
  for (const [handler, url, opts] of cases) {
    const r = await call(handler, url, opts);
    assert.equal(r.status, 400, `${opts.method || "GET"} ${url}`);
    assert.deepEqual(r.json, { error: CONSENT_REQUIRED });
  }
  assert.equal(ran, 0, "nothing was scanned");
  assert.deepEqual(events, [], "nothing new is logged about the visitor");
  // The preview's rate-limit counters weren't touched by the refused requests.
  const store = memoryStore();
  setStoreForTests(store);
  await call(previewHandler, "/api/preview?domain=example.com", { signedIn: false });
  assert.equal((await store.hit("preview-ip:203.0.113.5", 600, 0)).count, 0);
});

test("with consent the preview runs, and its existing audit event records consent: true (nothing else new)", async () => {
  setPreviewRunnerForTests(async () => ({ domain: "example.com", grade: "B", items: [{ id: "spf", title: "SPF", status: "pass" }] }));
  const r = await call(previewHandler, "/api/preview?domain=example.com&consent=true", { signedIn: false });
  assert.equal(r.status, 200);
  const e = events.find((x) => x.event === "preview_scan");
  assert.deepEqual(e.data, { grade: "B", consent: true });
  assert.deepEqual(Object.keys(e).sort(), ["audit", "data", "domain", "event", "ip", "ts"]);
});

/* ------------------------- attribution and offers ------------------------- */

test("breach data attribution stays on /tools/breach (linked), and Breach Check stays off", () => {
  const html = read("public/tools/breach.html");
  assert.match(html, /Breach data from <a href="https:\/\/xposedornot\.com\/"[^>]*>XposedOrNot<\/a>/);
  assert.match(html, /Password data from <a href="https:\/\/haveibeenpwned\.com\/Passwords"[^>]*>Have I Been Pwned<\/a>/);
  // No other page shows breach data (the Privacy Policy may name the providers).
  for (const f of HTML.filter((p) => p !== "public/tools/breach.html" && !LEGAL.includes(p))) assert.ok(!/xposedornot|haveibeenpwned/i.test(read(f)), f);
  assert.equal(breachCheckEnabled({}), false);
  assert.ok(!read("vercel.json").includes("BREACH_CHECK_ENABLED"));
});

test("founding testimonials: a disclosure note is ready in the config, and no testimonial is shown anywhere", () => {
  assert.equal(CONFIG.TESTIMONIAL_DISCLOSURE, "This client received a discounted rate.");
  for (const f of HTML) assert.ok(!/testimonial/i.test(read(f)), `${f}: no testimonials yet`);
});
