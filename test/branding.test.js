// Site-wide branding: every page carries the canonical header and footer (scripts/site-chrome.js),
// loads brand.css first, is CSP-safe, stays inside the wording rules, and the brand tokens meet
// WCAG 2.2 AA contrast on screen and in print. Offline.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { PAGES, header, footer, menuGroups, HEADER_RE, FOOTER_RE } from "../scripts/site-chrome.js";
import { TOOLS, CATEGORIES } from "../public/tools.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (p) => readFileSync(join(root, p), "utf8");
const walk = (dir, re, out = []) => {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p, re, out);
    else if (re.test(f)) out.push(relative(root, p).split("\\").join("/"));
  }
  return out;
};
const HTML = walk(join(root, "public"), /\.html$/);
const PAGE_JS = walk(join(root, "public"), /\.js$/);
const TECH = Object.entries(PAGES).filter(([, p]) => p.kind !== "lander").map(([f]) => f);
const WITH_MENU = Object.entries(PAGES).filter(([, p]) => p.kind === "tool" || p.kind === "plan").map(([f]) => f);
const LIVE = TOOLS.filter((t) => t.status === "live" && t.href);
const SOON = TOOLS.filter((t) => t.status !== "live");
const headerOf = (f) => read(f).match(HEADER_RE)[0];
const menuOf = (f) => headerOf(f).match(/<details class="tools-menu">[\s\S]*?<\/details>/)?.[0];

/* ------------------------------ shared chrome ------------------------------ */

test("every page in public/ is listed in scripts/site-chrome.js", () => {
  assert.deepEqual([...HTML].sort(), Object.keys(PAGES).sort());
});

test("every page: brand.css first, dark color-scheme, skip link, <main id=main>, contact details", () => {
  for (const f of HTML) {
    const html = read(f);
    const sheets = [...html.matchAll(/<link rel="stylesheet" href="([^"]+)">/g)].map((m) => m[1]);
    assert.equal(sheets[0], "/brand.css", `${f}: brand.css is loaded first`);
    assert.match(html, /<meta name="color-scheme" content="dark">/, f);
    assert.match(html, /<meta name="robots" content="noindex, nofollow">/, f);
    assert.match(html, /<body[^>]*>\n {2}<a class="skip-link" href="#main">Skip to content<\/a>/, `${f}: the skip link is the first thing in <body>`);
    assert.match(html, /<main id="main"[ >]/, f);
    for (const s of ["Powered by NWIM Project Management", 'href="tel:+15073604479"', 'href="mailto:info@nwimpm.com"']) assert.ok(html.includes(s), `${f}: ${s}`);
  }
});

test("every page carries the canonical header and footer (only the page kind and current nav item differ)", () => {
  for (const [f, page] of Object.entries(PAGES)) {
    const html = read(f);
    assert.equal(html.match(HEADER_RE)?.[0], header(page), `${f}: header differs from scripts/site-chrome.js (run node scripts/sync-chrome.js)`);
    assert.equal(html.match(FOOTER_RE)?.[0], footer(page), `${f}: footer differs from scripts/site-chrome.js (run node scripts/sync-chrome.js)`);
    assert.equal(html.match(/<header\b/g).length, 1, `${f}: one header`);
    assert.equal(html.match(/<footer\b/g).length, 1, `${f}: one footer`);
    assert.ok(html.indexOf("</main>") < html.indexOf("<footer"), `${f}: footer after main`);
  }
});

test("technician pages: the nav (with #lock-btn) and 'Back to home' both start hidden until the session check answers", () => {
  for (const f of TECH) {
    const html = read(f);
    assert.match(html, /<nav class="tech-nav" id="tech-nav" aria-label="Technician" hidden>/, f);
    assert.match(html, /<button type="button" class="nav-signout" id="lock-btn" hidden>Sign out<\/button>/, f);
    assert.match(html, /<a class="header-home" id="gate-home" href="\/" hidden>Back to home<\/a>/, f);
    assert.match(headerOf(f), /<a href="\/plan"( aria-current="page")?>Fix Plan<\/a>\n\s+<button type="button" class="nav-signout"/, `${f}: Fix Plan, then Sign out`);
    assert.ok(!html.includes("Tech sign in"), `${f}: never "Tech sign in" on the gate`);
    assert.ok(!/header-links|header-link|back-link|← All tools/.test(html), `${f}: old header links are gone`);
    assert.match(html, /<header class="site-header no-print">/, f);
    assert.match(html, /<footer class="site-footer no-print">/, f);
    // The sign-in gate: same IDs as before, errors announced.
    for (const id of ["gate", "gate-form", "access-code", "gate-error"]) assert.match(html, new RegExp(`id="${id}"`), `${f}: #${id}`);
    assert.match(html, /<p class="form-error" id="gate-error" role="alert" hidden><\/p>/, f);
    assert.match(html, /<label for="access-code">/, `${f}: the access code has a visible label`);
    // No per-tool buttons in the header bar: tools are reached through the menu (or the dashboard cards).
    const bar = headerOf(f).replace(/<details class="tools-menu">[\s\S]*?<\/details>/, "");
    for (const t of LIVE) assert.ok(!bar.includes(`href="${t.href}"`), `${f}: no ${t.name} button in the header bar`);
  }
  const lander = read("public/index.html");
  assert.ok(!lander.includes('id="tech-nav"') && !lander.includes('id="lock-btn"') && !lander.includes("tools-menu"));
  assert.match(lander, /<a class="l-btn l-btn-ghost signin-btn" href="\/tools">Tech sign in<\/a>/);
});

test("dashboard header: only Fix Plan and Sign out, no Tools menu (the cards are the tool picker)", () => {
  const h = headerOf("public/tools.html");
  assert.equal(PAGES["public/tools.html"].kind, "dashboard");
  assert.ok(!h.includes("tools-menu"), "no Tools menu on the dashboard");
  const nav = h.match(/<nav [^>]*>([\s\S]*?)<\/nav>/)[1];
  assert.deepEqual([...nav.matchAll(/<(a|button)\b[^>]*>([^<]*)</g)].map((m) => m[2]), ["Fix Plan", "Sign out"]);
  assert.ok(!h.includes('aria-current="page"'));
  // The dashboard script renders every tool from the same registry.
  assert.match(read("public/tools.html"), /<script src="\/dashboard\.js" type="module"><\/script>/);
  assert.match(read("public/dashboard.js"), /import \{ TOOLS \} from "\.\/tools\.js";/);
  assert.match(read("public/dashboard.js"), /TOOLS\.filter\(\(t\) => !t\.admin \|\| isAdminSession\(\)\)\.map\(card\)/);
});

test("tool pages and /plan: a Tools menu with All tools, then every live tool grouped by category, current one marked", () => {
  assert.ok(LIVE.length >= 3 && SOON.length >= 1);
  for (const t of TOOLS) assert.ok(CATEGORIES.includes(t.category), `${t.id}: category ${t.category}`);
  for (const f of WITH_MENU) {
    const menu = menuOf(f);
    assert.ok(menu, `${f}: has the Tools menu`);
    assert.match(menu, /^<details class="tools-menu">\n\s+<summary>Tools<\/summary>/, `${f}: a <details>/<summary> menu, no JS needed`);
    const links = [...menu.matchAll(/<a\b[^>]*href="([^"]+)"[^>]*>([^<]+)<\/a>/g)].map((m) => [m[1], m[2]]);
    assert.deepEqual(links[0], ["/tools", "All tools"], `${f}: All tools first`);
    // Exactly the live tools, in category order, each under its category heading; never a coming-soon tool.
    const expected = CATEGORIES.flatMap((c) => LIVE.filter((t) => t.category === c)).map((t) => [t.href, t.name]);
    assert.deepEqual(links.slice(1), expected, `${f}: every live tool, grouped`);
    for (const t of SOON) assert.ok(!menu.includes(t.name), `${f}: ${t.name} (coming soon) is not in the menu`);
    const headings = [...menu.matchAll(/<p class="tools-menu-heading" id="([^"]+)"(?: data-admin hidden)?>([^<]+)<\/p>\n\s+<ul aria-labelledby="([^"]+)"(?: data-admin hidden)?>/g)];
    assert.deepEqual(headings.map((m) => m[2]), menuGroups().map((g) => g.category), `${f}: category headings`);
    for (const m of headings) assert.equal(m[1], m[3], `${f}: each list is labelled by its heading`);
    const page = PAGES[f];
    const currentLinks = [...headerOf(f).matchAll(/<a href="([^"]+)" aria-current="page"( hidden)?>/g)].map((m) => m[1]);
    assert.deepEqual(currentLinks, [page.kind === "plan" ? "/plan" : page.current], `${f}: exactly one current item`);
  }
  // Every live tool has its own page, registered as a tool page for its href (so it gets the menu with itself marked).
  for (const t of LIVE) {
    const entry = Object.entries(PAGES).find(([, p]) => p.kind === "tool" && p.current === t.href);
    assert.ok(entry, `${t.href} is registered in scripts/site-chrome.js`);
    assert.equal(entry[0], `public${t.href}.html`);
  }
});

test("menuGroups: only live tools, categories in order, empty categories dropped, unknown categories rejected", () => {
  const tools = [
    { id: "a", category: "Office", status: "live", href: "/tools/a", name: "A" },
    { id: "b", category: "Email", status: "live", href: "/tools/b", name: "B" },
    { id: "c", category: "Email", status: "soon", href: null, name: "C" },
    { id: "d", category: "Web", status: "soon", href: null, name: "D" },
  ];
  assert.deepEqual(menuGroups(tools).map((g) => [g.category, g.tools.map((t) => t.id)]), [["Email", ["b"]], ["Office", ["a"]]]);
  assert.throws(() => menuGroups([{ id: "x", category: "Misc", status: "live", href: "/tools/x", name: "X" }]), /unknown category/);
});

test("Tools menu: Escape closes it and returns focus to Tools; a click or focus outside closes it", async () => {
  const listeners = {};
  const summary = { focused: false, focus() { this.focused = true; } };
  const inside = {};
  const menu = { open: true, querySelector: () => summary, contains: (el) => el === inside || el === summary };
  const doc = { querySelector: (sel) => (sel === "details.tools-menu" ? menu : null), addEventListener: (t, fn) => (listeners[t] = fn) };
  globalThis.document = { getElementById: () => null };
  const { initToolsMenu } = await import(`../public/tech-session.js?menu=${Date.now()}`);
  initToolsMenu(doc);
  listeners.click({ target: inside });
  assert.equal(menu.open, true, "a click inside keeps it open");
  listeners.keydown({ key: "Enter" });
  assert.equal(menu.open, true);
  listeners.keydown({ key: "Escape" });
  assert.equal(menu.open, false);
  assert.equal(summary.focused, true, "focus goes back to Tools");
  menu.open = true;
  listeners.click({ target: {} });
  assert.equal(menu.open, false, "a click outside closes it");
  menu.open = true;
  listeners.focusin({ target: {} });
  assert.equal(menu.open, false, "tabbing out closes it");
  initToolsMenu({ getElementById: () => null }); // pages without the menu (and fake DOMs) are fine
});

test("no sign-in flash: technician pages load in a neutral 'checking your sign-in' state", () => {
  const CONTENT = { dashboard: "dashboard", tool: "tool", plan: "builder" };
  for (const f of TECH) {
    const html = read(f);
    const main = html.slice(html.indexOf("<main"), html.indexOf("</main>"));
    // The neutral panel is the first thing in <main> and starts visible, announced politely.
    assert.match(main, /^<main id="main"[^>]*>\n\s+<!--[^>]*-->\n\s+<section class="session-check" id="session-check" role="status" aria-live="polite">/, `${f}: #session-check first in <main>`);
    assert.ok(!/id="session-check"[^>]*\bhidden\b/.test(html), `${f}: #session-check starts visible`);
    assert.match(main, /<span class="sr-only">Checking your sign-in…<\/span>/, f);
    assert.match(main, /<noscript><p class="session-check-note">The technician tools need JavaScript\.<\/p><\/noscript>/, f);
    // Neither the sign-in form nor the page content is visible before the check answers.
    assert.match(html, /<section class="gate[^"]*" id="gate" aria-labelledby="gate-title" hidden>/, `${f}: the sign-in form starts hidden`);
    const content = CONTENT[PAGES[f].kind];
    assert.match(html, new RegExp(`id="${content}"[^>]*\\bhidden\\b`), `${f}: #${content} starts hidden`);
  }
  assert.match(read("public/plan.css"), /\.session-check \{/);
  // Both gate scripts use the shared check; nothing calls GET /api/session on its own any more.
  assert.match(read("public/tech-session.js"), /return checkSession\(\{ show: unlock,/);
  assert.match(read("public/plan.js"), /\ncheckSession\(\{\n\s+apiFn: api,/);
  for (const f of PAGE_JS) assert.ok(!/api\("\/api\/session"\)\s*\n?\s*\.then/.test(read(f)), `${f}: no direct session check`);
});

async function sessionCheckHarness() {
  const els = { "session-check": { hidden: false } };
  globalThis.document = { getElementById: (id) => els[id] || null };
  const mod = await import(`../public/tech-session.js?check=${Date.now()}${Math.random()}`);
  const calls = [];
  const errors = [];
  return { els, calls, errors, run: (apiFn, timeoutMs = 1000) => mod.checkSession({ apiFn, timeoutMs, show: (on) => calls.push(on), onError: (m) => errors.push(m) }) };
}
const reply = (body, status = 200) => async () => ({ res: { ok: status < 400, status }, body });

test("checkSession: signed in shows the page only; the sign-in form is never shown on the way", async () => {
  const h = await sessionCheckHarness();
  let resolve;
  const pending = h.run(() => new Promise((r) => (resolve = r)));
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(h.calls, [], "nothing is shown while the check is in flight");
  assert.equal(h.els["session-check"].hidden, false, "the neutral panel stays up meanwhile");
  resolve({ res: { ok: true, status: 200 }, body: { authenticated: true } });
  await pending;
  assert.deepEqual(h.calls, [true], "show(true) once, never show(false)");
  assert.equal(h.els["session-check"].hidden, true);
  assert.deepEqual(h.errors, []);
});

test("checkSession: signed out, server errors, network failures and timeouts show the sign-in form", async () => {
  let h = await sessionCheckHarness();
  await h.run(reply({ authenticated: false }));
  assert.deepEqual([h.calls, h.errors, h.els["session-check"].hidden], [[false], [], true]);

  h = await sessionCheckHarness();
  await h.run(reply({ error: "Technician tools are locked." }, 503));
  assert.deepEqual([h.calls, h.errors], [[false], ["Technician tools are locked."]]);

  h = await sessionCheckHarness();
  await h.run(async () => {
    throw new Error("offline");
  });
  assert.deepEqual([h.calls, h.errors], [[false], ["Couldn't reach the server."]]);

  // No answer in time: show the form with a note; a late "signed in" still unlocks the page.
  h = await sessionCheckHarness();
  let resolve;
  const pending = h.run(() => new Promise((r) => (resolve = r)), 20);
  await new Promise((r) => setTimeout(r, 40));
  assert.deepEqual(h.calls, [false]);
  assert.match(h.errors[0], /taking a while/);
  resolve({ res: { ok: true, status: 200 }, body: { authenticated: true } });
  await pending;
  assert.deepEqual(h.calls, [false, true]);
});

test("signing in shows the nav and hides 'Back to home'; signing out reverses it (tech-session.js)", async () => {
  const els = {};
  for (const id of ["tech-nav", "gate-home"]) els[id] = { hidden: id === "tech-nav" };
  globalThis.document = { getElementById: (id) => els[id] || null };
  const { showSignedInChrome } = await import(`../public/tech-session.js?t=${Date.now()}`);
  showSignedInChrome(true);
  assert.deepEqual([els["tech-nav"].hidden, els["gate-home"].hidden], [false, true]);
  showSignedInChrome(false);
  assert.deepEqual([els["tech-nav"].hidden, els["gate-home"].hidden], [true, false]);
  delete els["gate-home"];
  showSignedInChrome(true); // pages without the header (and test DOMs) are fine
  assert.match(read("public/tech-session.js"), /\$\("lock-btn"\)\.hidden = !on;\n\s+showSignedInChrome\(on\);/);
  assert.match(read("public/plan.js"), /\$\("lock-btn"\)\.hidden = !on;\n\s+showSignedInChrome\(on\);/);
});

/* --------------------------------- CSP --------------------------------- */

test("no page has inline script/style, style= or on*= attributes, or third-party resources", () => {
  for (const f of HTML) {
    const html = read(f);
    assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), `${f}: inline <script>`);
    assert.ok(!/<style\b/i.test(html), `${f}: <style>`);
    assert.ok(!/\sstyle\s*=/i.test(html), `${f}: style=`);
    assert.ok(!/\son[a-z]+\s*=/i.test(html), `${f}: on*=`);
    for (const m of html.matchAll(/<(?!a\b)[a-z]+\b[^>]*\b(?:src|href)\s*=\s*"(?:https?:)?\/\/[^"]*"/gi)) assert.fail(`${f}: external resource ${m[0]}`);
  }
  for (const f of walk(join(root, "public"), /\.css$/)) assert.ok(!/@import|url\(\s*["']?(?:https?:)?\/\//i.test(read(f)), `${f}: no external CSS or fonts`);
});

test("the icon sprite is well-formed, script-free, and has every symbol the pages and dashboard use", () => {
  const svg = read("public/assets/icons.svg");
  for (const m of svg.matchAll(/<!--([\s\S]*?)-->/g)) assert.ok(!m[1].includes("--"), "'--' inside an XML comment breaks the whole sprite");
  assert.ok(!/<script/i.test(svg) && !/\sstyle\s*=/i.test(svg) && !/\son[a-z]+\s*=/i.test(svg) && !/href\s*=\s*"https?:/i.test(svg));
  const used = new Set();
  for (const f of HTML) for (const m of read(f).matchAll(/icons\.svg#([\w-]+)/g)) used.add(m[1]);
  for (const m of read("public/tools.js").matchAll(/icon: "([\w-]+)"/g)) used.add(m[1]);
  for (const id of ["shield-logo", "mail", "globe-lock", "domain"]) assert.ok(used.has(id), id);
  for (const id of used) assert.match(svg, new RegExp(`<symbol id="${id}"`), `symbol ${id}`);
});

/* ------------------------------- wording ------------------------------- */

test("wording: no non-compete or invented-claim wording on any page or in page JS", () => {
  // "review" as a verb (a technician reviewing DNS changes) is fine on technician pages; customer/online reviews are not.
  const nonCompete = /\bSEO\b|search engine|Google Business|\b(customer|online|google|yelp|star|5-star) reviews?\b|\breviews? (site|platform|management)\b|\brankings?\b|grow your business|more customers|marketing/i;
  const fabricated = /\b(testimonials?|trusted by|certified|award(-winning|s)?|\d+\+? (years|clients|customers)|star rating)\b/i;
  for (const f of [...HTML, ...PAGE_JS]) {
    const text = read(f);
    assert.ok(!nonCompete.test(text), `${f}: "${(text.match(nonCompete) || [])[0]}"`);
    assert.ok(!fabricated.test(text), `${f}: "${(text.match(fabricated) || [])[0]}"`);
  }
  assert.ok(HTML.length >= 6 && PAGE_JS.length >= 8);
});

/* ------------------------------- contrast ------------------------------- */

// WCAG 2.2 relative luminance and contrast ratio.
const channel = (c) => {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
};
const luminance = (hex) => {
  const [r, g, b] = hex.slice(1).match(/../g).map((x) => channel(parseInt(x, 16)));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const contrast = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

/** The custom properties in brand.css: { screen, print }, each { name: "#rrggbb" }. */
function brandTokens() {
  const css = read("public/brand.css");
  const vars = (block) => Object.fromEntries([...block.matchAll(/--([\w-]+):\s*(#[0-9a-f]{6})\s*;/gi)].map((m) => [m[1], m[2].toLowerCase()]));
  const screen = vars(css.match(/^:root \{([\s\S]*?)^\}/m)[1]);
  const print = { ...screen, ...vars(css.match(/@media print \{\s*:root \{([\s\S]*?)\n {2}\}/)[1]) };
  return { screen, print };
}

const TEXT_PAIRS = [
  ["text", "bg"], ["text", "surface"], ["text", "surface-2"],
  ["muted", "bg"], ["muted", "surface"], ["muted", "surface-2"], // secondary text, placeholders, footer
  ["accent", "bg"], ["accent", "surface"], ["accent", "surface-2"], // links, incl. inside report cards
  ["accent-ink", "accent"], // primary buttons, skip link
  ["code-text", "code-bg"], // snippets and technical details
  ["pass", "pass-bg"], ["warn", "warn-bg"], ["fail", "fail-bg"], ["info", "info-bg"], // pills, diff added/removed, verdicts
  ["pass", "surface"], ["warn", "surface"], ["fail", "surface"], ["fail", "bg"], // status text on cards, form errors
  ["text", "warn-bg"], ["text", "info-bg"], ["text", "pass-bg"], ["text", "fail-bg"], // risk box, guide note
  ...["a", "b", "c", "d", "f", "none"].map((g) => ["grade-ink", `grade-${g}`]),
];
const UI_PAIRS = [
  ["control-border", "bg"], ["control-border", "surface"], ["control-border", "surface-2"], // inputs, outline buttons
  ["accent", "bg"], ["accent", "surface"], // focus ring
  ["pass", "surface"], ["warn", "surface"], ["fail", "surface"], ["info", "surface"], // check cards' status edge
];

test("contrast: screen and print tokens meet WCAG 2.2 AA (4.5:1 text, 3:1 UI)", () => {
  const { screen, print } = brandTokens();
  for (const [name, t] of Object.entries({ screen, print })) {
    for (const [fg, bg] of TEXT_PAIRS) {
      assert.ok(t[fg] && t[bg], `${name}: --${fg} / --${bg} defined`);
      const r = contrast(t[fg], t[bg]);
      assert.ok(r >= 4.5, `${name}: --${fg} on --${bg} is ${r.toFixed(2)}:1`);
    }
    for (const [fg, bg] of UI_PAIRS) {
      const r = contrast(t[fg], t[bg]);
      assert.ok(r >= 3, `${name}: --${fg} against --${bg} is ${r.toFixed(2)}:1`);
    }
  }
  assert.equal(screen.bg, "#0b1324");
  assert.equal(print.bg, "#ffffff");
  assert.equal(print.text, "#111111");
});

test("contrast: the lander's light sections and hard-coded colours meet AA too", () => {
  const css = read("public/lander.css");
  const v = (n) => css.match(new RegExp(`--${n}:\\s*(#[0-9a-f]{6})`))[1];
  const pairs = [[v("l-light-text"), v("l-light-bg")], [v("l-light-muted"), v("l-light-bg")], [v("l-light-accent"), v("l-light-bg")], ["#ffffff", v("l-light-accent")], [v("l-light-muted"), "#ffffff"]];
  for (const [fg, bg] of pairs) assert.ok(contrast(fg, bg) >= 4.5, `${fg} on ${bg}: ${contrast(fg, bg).toFixed(2)}`);
  // No stray hard-coded colours in the shared stylesheets: everything goes through brand.css tokens.
  for (const f of ["public/styles.css", "public/tools.css", "public/plan.css"]) assert.ok(!/#[0-9a-f]{3,6}\b/i.test(read(f)), `${f} uses tokens only`);
  assert.ok(!/prefers-color-scheme/.test(read("public/styles.css")), "the old light/dark split is gone");
});

/* -------------------------------- budget -------------------------------- */

test("CSS budget: under 40 KB of CSS per page", () => {
  for (const f of HTML) {
    const sheets = [...read(f).matchAll(/<link rel="stylesheet" href="\/([^"]+)">/g)].map((m) => m[1]);
    const bytes = sheets.reduce((n, s) => n + Buffer.byteLength(read(`public/${s}`)), 0);
    assert.ok(bytes < 40_000, `${f}: ${bytes} bytes of CSS`);
  }
});

/* ------------------------------ example domains ------------------------------ */

test("examples, tests and docs use reserved example domains, not real-looking business domains", () => {
  const files = [...["api", "lib", "public", "scripts", "test"].flatMap((d) => walk(join(root, d), /\.(js|html|css|json|txt|csv|md)$/)), "README.md"];
  const business = /\b(acme(dental|accounting)?|otherdental|oldoffice|yourbusiness|clientbusiness|r53co|csvco)\.(com|co)\b|-dental\.com\b|tinywidgets\.io/i;
  for (const f of files) {
    if (f === "test/branding.test.js") continue;
    const m = read(f).match(business);
    assert.ok(!m, `${f}: "${m && m[0]}" (use example.com, example.net or example.org)`);
  }
});

/* --------------------------------- logo --------------------------------- */

test("logo: the shield replaces the old checkmark in the header, the sign-in card and the favicon", () => {
  const svg = read("public/assets/icons.svg");
  const symbol = svg.match(/<symbol id="shield-logo" viewBox="4 2 24 28">([\s\S]*?)<\/symbol>/)?.[1];
  assert.ok(symbol, "#shield-logo symbol");
  assert.ok(!/<symbol id="logo"/.test(svg), "the old #logo symbol is gone");
  const shapes = (text) => [...text.matchAll(/<path d="([^"]+)"/g)].map((m) => m[1]);
  const favicon = read("public/favicon.svg");
  assert.deepEqual(shapes(favicon), shapes(symbol), "the favicon draws the same shield as the sprite");
  assert.match(favicon, /viewBox="4 2 24 28"/, "same tight viewBox as the sprite, so the shield fills the icon");
  assert.ok(!/<script|\son[a-z]+\s*=|\sstyle\s*=|href\s*=/i.test(favicon), "the favicon is a plain, self-contained SVG");
  assert.match(favicon, /fill="#4c8dff"/, "brand blue (--accent)");
  assert.match(favicon, /stroke="#0b1324"/, "navy detail (--accent-ink)");
  for (const f of HTML) {
    const html = read(f);
    assert.match(html, /<link rel="icon" href="\/favicon\.svg" type="image\/svg\+xml">/, `${f}: favicon`);
    assert.ok(!/data:image\/svg/.test(html), `${f}: no inline data-URI favicon`);
    assert.ok(!/icons\.svg#logo"/.test(html), `${f}: no reference to the old mark`);
    assert.match(headerOf(f), /<svg class="brand-mark" width="32" height="32" aria-hidden="true" focusable="false"><use href="\/assets\/icons\.svg#shield-logo"\/><\/svg>/, `${f}: header shield`);
    assert.match(headerOf(f), /<span class="brand-name">Office Tech Health Check<\/span>\n\s+<span class="brand-sub">Powered by NWIM Project Management<\/span>/, `${f}: wordmark unchanged`);
  }
  for (const f of TECH) assert.match(read(f), /<svg class="gate-logo" width="48" height="48" aria-hidden="true" focusable="false"><use href="\/assets\/icons\.svg#shield-logo"\/><\/svg>/, `${f}: sign-in card shield`);
  // The old checkmark path appears nowhere.
  for (const f of [...HTML, ...PAGE_JS, "public/assets/icons.svg", "public/favicon.svg", "scripts/site-chrome.js"]) assert.ok(!read(f).includes("M9 16.5l4.5 4.5L23 11.5"), `${f}: no checkmark`);
});
