// Admin pricing sheet (/tools/pricing): admin-only access through one isAdmin hook, every amount from
// lib/config.js, the internal note, printable, and never linked from the lander or client plans.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import pricingHandler from "../api/pricing.js";
import sessionHandler from "../api/session.js";
import { isAdmin } from "../lib/admin.js";
import { pricingSheet } from "../lib/pricing.js";
import { buildPlan } from "../lib/plan.js";
import * as CONFIG from "../lib/config.js";
import { setStoreForTests, memoryStore } from "../lib/store.js";
import { encodeSession, newSession } from "../lib/session.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (p) => readFileSync(join(root, p), "utf8");
const SECRET = "test-session-secret-0123456789-abcdefgh";
let saved;
beforeEach(() => {
  saved = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = SECRET;
  setStoreForTests(memoryStore());
});
afterEach(() => {
  setStoreForTests(undefined);
  if (saved === undefined) delete process.env.SESSION_SECRET;
  else process.env.SESSION_SECRET = saved;
});
async function call(handler, url, { signedIn = true, method = "GET" } = {}) {
  const res = { statusCode: 0, headers: {}, body: "", setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(b) { this.body = b ?? ""; } };
  const cookie = signedIn ? { cookie: `ohc_tech=${encodeSession(newSession(), SECRET)}` } : {};
  await handler({ method, url, headers: { host: "officetech.nwimpm.com", "x-real-ip": "203.0.113.9", "user-agent": "t", ...cookie }, socket: {} }, res);
  return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : null };
}

test("isAdmin: true for any signed-in technician today; false without a session (one hook to change later)", () => {
  assert.equal(isAdmin({ sid: "abc", exp: 1 }), true);
  assert.equal(isAdmin(null), false);
  assert.equal(isAdmin({}), false);
});

test("/api/pricing: signed-in admins only; the session tells pages whether this technician is an admin", async () => {
  assert.equal((await call(pricingHandler, "/api/pricing", { signedIn: false })).status, 401);
  assert.equal((await call(pricingHandler, "/api/pricing", { method: "POST" })).status, 405);
  const r = await call(pricingHandler, "/api/pricing");
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, pricingSheet());
  assert.equal((await call(sessionHandler, "/api/session")).json.admin, true);
  assert.ok(!("admin" in (await call(sessionHandler, "/api/session", { signedIn: false })).json));
});

test("the sheet shows every price from lib/config.js with the right labels, the founding offer and the internal note", () => {
  const s = pricingSheet();
  assert.deepEqual(s.packages.map((p) => [p.name, p.label]), [["Standard", "$350"], ["Plus", "$550"]]);
  assert.deepEqual(s.recurring.map((r) => [r.name, r.label]), [["Quarterly Checkups", "$150/year"], ["Monthly Watch", "$35/month"]]);
  assert.deepEqual(
    [s.founding.label, s.founding.packageName, s.founding.regularLabel, s.founding.bonus, s.founding.limit],
    ["$210", "Standard", "$350", { name: "Quarterly Checkups", regularLabel: "$150/year" }, 3],
  );
  assert.match(s.founding.terms, /written testimonial and permission to use your business name/);
  assert.equal(s.founding.note, "Founding offer is Standard pricing. Plus-level work for founding clients is decided case by case.");
  assert.deepEqual(s.quotes, [{ id: "email-migration", title: "Move email to Google Workspace or Microsoft 365", label: "Quote, from $1,500" }]);
  assert.equal(s.approved, CONFIG.PRICES_APPROVED);
  // Change the config and the sheet follows: nothing is hard-coded.
  const custom = pricingSheet({ packages: [{ id: "standard", name: "Standard", price: 400, scope: "x", blurb: "y" }], recurring: [], founding: null, quotes: {} });
  assert.deepEqual(custom.packages.map((p) => p.label), ["$400"]);
  assert.equal(custom.founding, null);
});

test("the internal note never reaches client plans; the client founding offer stays 'Standard fix for $210'", () => {
  const report = { domain: "example.com", scannedAt: "2026-10-15T00:00:00Z", provider: { key: "google", name: "Google Workspace" }, checks: [{ id: "dmarc", title: "DMARC", weight: 25, status: "fail", data: { code: "missing", records: [] } }], unverified: [] };
  const plan = buildPlan(report);
  assert.equal(plan.pricing.founding.packageName, "Standard");
  assert.equal(plan.pricing.founding.label, "$210");
  assert.ok(!JSON.stringify(plan).includes("case by case"), "the admin note stays internal");
  assert.ok(!JSON.stringify(plan).includes("/tools/pricing"));
});

test("/tools/pricing: registered under Admin, hidden from non-admins, printable, no amounts in the page, never linked publicly or from client plans", () => {
  const registry = read("public/tools.js");
  assert.match(registry, /id: "pricing-sheet", category: "Admin".*href: "\/tools\/pricing", status: "live", admin: true/);
  assert.match(registry, /export const CATEGORIES = \[.*"Admin"\]/);
  // Tools menu on every tool page: the Admin group starts hidden and is shown only for admin sessions.
  for (const f of ["public/tools/email.html", "public/tools/website.html", "public/tools/domain.html", "public/tools/breach.html", "public/plan.html"]) {
    assert.match(read(f), /<p class="tools-menu-heading" id="tools-menu-admin" data-admin hidden>Admin<\/p>\n\s+<ul aria-labelledby="tools-menu-admin" data-admin hidden>\n\s+<li><a href="\/tools\/pricing">Pricing sheet<\/a><\/li>/, f);
  }
  assert.match(read("public/tech-session.js"), /for \(const el of doc\.querySelectorAll\("\[data-admin\]"\)\) el\.hidden = !admin;/);
  const html = read("public/tools/pricing.html");
  assert.match(html, /<button type="button" class="btn-ghost no-print" id="print-pricing">Print<\/button>/);
  assert.match(html, /<script src="\/pricing\.js" type="module"><\/script>/);
  const js = read("public/pricing.js");
  assert.match(js, /window\.print\(\)/);
  assert.match(js, /if \(!isAdminSession\(\)\) return showError\("pricing-error", "This page is for admins only\."\);/);
  for (const f of ["public/tools/pricing.html", "public/pricing.js"]) assert.ok(!/\$\d/.test(read(f).replace(/`\$\{/g, "")), `${f}: no amounts written in the page`);
  // Never linked from the public lander or anything a client sees.
  for (const f of ["public/index.html", "public/lander.js", "public/plan.js", "lib/plan.js"]) assert.ok(!read(f).includes("/tools/pricing"), f);
  assert.ok(read("vercel.json").includes('"api/pricing.js"'));
  assert.match(read("scripts/dev-server.js"), /pathname === "\/api\/pricing"/);
});

test("the sheet renders with textContent only", async () => {
  class El {
    constructor(tag) {
      this.tag = tag;
      this.children = [];
    }
    setAttribute() {}
    addEventListener() {}
    append(...c) {
      this.children.push(...c);
    }
    get textContent() {
      return this.children.map((c) => (typeof c === "string" ? c : c.textContent)).join(" ");
    }
  }
  globalThis.Node = El;
  globalThis.document = { getElementById: () => null, createElement: (t) => new El(t), createTextNode: (t) => t };
  const { renderSheet } = await import(`../public/pricing.js?t=${Date.now()}`);
  const text = renderSheet(pricingSheet()).map((n) => n.textContent).join("\n");
  for (const s of ["Standard", "$350", "Plus", "$550", "Quarterly Checkups", "$150/year", "Monthly Watch", "$35/month", "$210 Standard fix", "free first year of Quarterly Checkups", "first 3 clients", "Plus-level work for founding clients is decided case by case", "Quote, from $1,500"]) {
    assert.ok(text.includes(s), s);
  }
  assert.ok(!/innerHTML/.test(read("public/pricing.js")));
});
