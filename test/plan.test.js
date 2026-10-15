import { test } from "node:test";
import assert from "node:assert/strict";
import { runScan } from "../lib/scan.js";
import { buildPlan, recommendSpf, recommendDmarc, packageFit, periodLabel, formatPrice } from "../lib/plan.js";
import * as CONFIG from "../lib/config.js";
import { identifyDnsHost } from "../lib/checks/dnshost.js";
import handler, { passcodeMatches } from "../api/plan.js";
import { setStoreForTests, memoryStore } from "../lib/store.js";
import { fakeDeps, goodTls, rdapData, DKIM_RECORD } from "./fakes.js";

const BIZ = { name: "NWIM PM", fullName: "x", contactEmail: "josh@nwimpm.com", bookingUrl: "https://cal.com/x", dmarcReportAddress: "dmarc@nwimpm.com" };
// The real packages, recurring options and founding offer from lib/config.js (the single source of truth).
const opts = { business: BIZ, quotes: { "email-migration": { title: "Move email", from: 1500 } } };

async function neglectedOffice() {
  const d = "old.example.net";
  return runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "mx1.mail.secureserver.net", priority: 0 }] },
    ns: { [d]: ["ns55.domaincontrol.com", "ns56.domaincontrol.com"] },
    http: { ok: true, status: 200 },
    tls: { [d]: { ...goodTls, authorized: false, authorizationError: "CERT_HAS_EXPIRED" } },
    rdap: rdapData({ expiry: "2026-10-20T00:00:00Z", locked: false }),
  }));
}

test("DNS host detection from nameservers", () => {
  assert.equal(identifyDnsHost(["maciej.ns.cloudflare.com"]).key, "cloudflare");
  assert.equal(identifyDnsHost(["ns55.domaincontrol.com"]).key, "godaddy");
  assert.equal(identifyDnsHost(["dns1.registrar-servers.com"]).key, "namecheap");
  assert.equal(identifyDnsHost(["ns-12.awsdns-01.com"]).key, "route53");
  assert.equal(identifyDnsHost(["ns1.example-dns.net"]).key, "other");
});

test("neglected office: one plan item per real finding, in the right order", async () => {
  const report = await neglectedOffice();
  const plan = buildPlan(report, opts);
  assert.deepEqual(plan.items.map((i) => i.id), ["domain-security", "spf", "dkim", "dmarc", "ssl", "https-redirect"]);
  assert.deepEqual(plan.items.map((i) => i.phase), [1, 2, 2, 3, 4, 4]);
  assert.equal(plan.dnsHost.key, "godaddy");
  assert.match(plan.dnsHost.where, /GoDaddy/);
  // Every item maps back to a check that failed or warned in the report
  for (const it of plan.items) {
    for (const id of it.fixes) {
      const c = report.checks.find((x) => x.id === id);
      assert.ok(["fail", "warn"].includes(c.status), `${it.id} fixes ${id}, which was ${c.status}`);
    }
  }
});

test("neglected office: exact records, urgent renewal, package pricing and projection", async () => {
  const plan = buildPlan(await neglectedOffice(), opts);
  const spf = plan.items.find((i) => i.id === "spf");
  assert.equal(spf.records[0].value, "v=spf1 include:secureserver.net ~all");
  const dmarc = plan.items.find((i) => i.id === "dmarc");
  assert.deepEqual(dmarc.records.filter((r) => !r.zone).map((r) => r.value), [
    "v=DMARC1; p=none; rua=mailto:dmarc@nwimpm.com; fo=1",
    "v=DMARC1; p=quarantine; rua=mailto:dmarc@nwimpm.com; fo=1",
    "v=DMARC1; p=reject; rua=mailto:dmarc@nwimpm.com; fo=1",
  ]);
  assert.ok(dmarc.steps.some((s) => s.includes("*._report._dmarc")), "explains external report authorization");
  const dom = plan.items.find((i) => i.id === "domain-security");
  assert.match(dom.title, /urgent/);
  assert.ok(plan.items.every((it) => !("price" in it) && !("priceKeys" in it)), "no per-fix prices in the plan");
  // One domain, one email provider, no extra senders: Standard, with Plus shown alongside.
  assert.deepEqual(plan.pricing.packages.map((p) => [p.id, p.name, p.label, p.recommended]), [["standard", "Standard", "$350", true], ["plus", "Plus", "$550", false]]);
  assert.deepEqual(plan.pricing.recommended, { id: "standard", name: "Standard", price: 350, label: "$350", reasons: [] });
  assert.equal(plan.pricing.recommendedTotal, 350);
  assert.deepEqual(plan.pricing.recurring.map((r) => [r.name, r.label]), [["Quarterly Checkups", "$150/year"], ["Monthly Watch", "$35/month"]]);
  assert.deepEqual(plan.pricing.founding, {
    name: "Founding client offer",
    limit: 3,
    price: 210,
    label: "$210",
    packageName: "Standard",
    regularLabel: "$350",
    bonus: { name: "Quarterly Checkups", regularLabel: "$150/year" },
    terms: "For our first 3 clients only, in exchange for a short written testimonial and permission to use your business name.",
  });
  assert.equal(plan.current.grade, "F");
  assert.equal(plan.projected.grade, "A");
  assert.equal(plan.quoteItems[0].id, "email-migration");
  assert.ok(plan.accessNeeded.some((a) => /GoDaddy/.test(a)));
});

test("a single finding produces a single item and the Standard package", async () => {
  const d = "example.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ip4:1.2.3.4 ~all"], [`google._domainkey.${d}`]: [DKIM_RECORD] },
    tls: { [d]: goodTls, [`www.${d}`]: goodTls },
    http: { ok: true, status: 301, location: `https://${d}/` },
    rdap: rdapData(),
  }));
  const plan = buildPlan(report, opts);
  assert.deepEqual(plan.items.map((i) => i.id), ["dmarc"]);
  assert.equal(plan.pricing.recommended.id, "standard");
  assert.equal(plan.pricing.recommendedTotal, 350);
});

test("a healthy domain gets an empty plan", async () => {
  const d = "example.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ip4:1.2.3.4 ~all"], [`_dmarc.${d}`]: ["v=DMARC1; p=reject; rua=mailto:x@example.com"], [`google._domainkey.${d}`]: [DKIM_RECORD] },
    tls: { [d]: goodTls, [`www.${d}`]: goodTls },
    http: { ok: true, status: 301, location: `https://${d}/` },
    rdap: rdapData(),
  }));
  const plan = buildPlan(report, opts);
  assert.equal(plan.nothingToFix, true);
  assert.equal(plan.pricing.recommendedTotal, 0);
  assert.deepEqual(plan.pricing.packages, [], "no fix package when there's nothing to fix");
  assert.equal(plan.pricing.founding, null);
  assert.equal(plan.pricing.recurring.length, 2, "ongoing checkups are still offered");
});

test("unverifiable DKIM becomes a free 'confirm at kickoff' item, not a paid fix", async () => {
  const d = "example.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ip4:1.2.3.4 ~all"], [`_dmarc.${d}`]: ["v=DMARC1; p=reject; rua=mailto:x@example.com"] },
    tls: { [d]: goodTls, [`www.${d}`]: goodTls },
    http: { ok: true, status: 301, location: `https://${d}/` },
    rdap: rdapData(),
  }));
  const plan = buildPlan(report, opts);
  assert.ok(!plan.items.some((i) => i.id === "dkim"));
  assert.ok(plan.verifyItems.some((v) => /DKIM/.test(v.title)));
});

test("recommendSpf merges, dedupes, removes +all and adds the platform", () => {
  // The platform include now goes before the final "all" (merge-safe order), not at the front.
  assert.equal(
    recommendSpf(["v=spf1 include:mailgun.org +all", "v=spf1 include:mailgun.org ip4:1.2.3.4 -all"], "microsoft").value,
    "v=spf1 include:mailgun.org ip4:1.2.3.4 include:spf.protection.outlook.com ~all",
  );
  // A redirect with no other senders stays a redirect (RFC 7208 §6.1); it isn't turned into an include.
  assert.equal(recommendSpf(["v=spf1 redirect=_spf.example.com"], "other").value, "v=spf1 redirect=_spf.example.com");
  assert.equal(recommendSpf([], "google").value, "v=spf1 include:_spf.google.com ~all");
  assert.equal(recommendDmarc("none", "d@example.net").value, "v=DMARC1; p=none; rua=mailto:d@example.net; fo=1");
});

test("DMARC staging respects an existing enforced policy", async () => {
  const d = "example.com";
  const base = {
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    tls: { [d]: goodTls, [`www.${d}`]: goodTls }, http: { ok: true, status: 301, location: `https://${d}/` }, rdap: rdapData(),
  };
  const txtBase = { [d]: ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ip4:1.2.3.4 ~all"], [`google._domainkey.${d}`]: [DKIM_RECORD] };
  const partial = buildPlan(await runScan(d, fakeDeps({ ...base, txt: { ...txtBase, [`_dmarc.${d}`]: ["v=DMARC1; p=quarantine; pct=50; rua=mailto:x@example.com"] } })), opts);
  assert.deepEqual(partial.items.find((i) => i.id === "dmarc").records.filter((r) => !r.zone).map((r) => r.value.match(/p=(\w+)/)[1]), ["quarantine", "reject"]);
  // p=reject without a report address passes the scan, so the plan must NOT charge to "fix" it
  const noReports = buildPlan(await runScan(d, fakeDeps({ ...base, txt: { ...txtBase, [`_dmarc.${d}`]: ["v=DMARC1; p=reject"] } })), opts);
  assert.ok(!noReports.items.some((i) => i.id === "dmarc"));
  const monitor = buildPlan(await runScan(d, fakeDeps({ ...base, txt: { ...txtBase, [`_dmarc.${d}`]: ["v=DMARC1; p=none; rua=mailto:x@example.com"] } })), opts);
  assert.deepEqual(monitor.items.find((i) => i.id === "dmarc").records.filter((r) => !r.zone).map((r) => r.value.match(/p=(\w+)/)[1]), ["none", "quarantine", "reject"]);
});

function fakeRes() {
  return {
    statusCode: 0, headers: {}, body: "",
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    end(b) { this.body = b; },
  };
}

test("plan API is locked without SESSION_SECRET and no longer accepts a header passcode", async () => {
  const saved = { ...process.env };
  try {
    delete process.env.SESSION_SECRET;
    process.env.PLAN_PASSCODE = "correct-horse-battery";
    setStoreForTests(memoryStore());
    let res = fakeRes();
    await handler({ method: "GET", url: "/api/plan?domain=example.com", headers: {}, socket: {} }, res);
    assert.equal(res.statusCode, 503);

    process.env.SESSION_SECRET = "x".repeat(40);
    res = fakeRes();
    await handler({ method: "GET", url: "/api/plan?domain=example.com", headers: { "x-plan-passcode": "correct-horse-battery", "x-real-ip": "9.9.9.9" }, socket: {} }, res);
    assert.equal(res.statusCode, 401, "the old header is ignored");
    assert.equal(res.headers["cache-control"], "no-store");

    assert.equal(passcodeMatches("a", "a"), true);
    assert.equal(passcodeMatches("a", "b"), false);
    assert.equal(passcodeMatches("", "b"), false);
  } finally {
    setStoreForTests(undefined);
    for (const k of ["SESSION_SECRET", "PLAN_PASSCODE"]) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
});

test("technician checklist shows what's there now and exactly what to change", async () => {
  const plan = buildPlan(await neglectedOffice(), opts);
  const item = (id) => plan.items.find((i) => i.id === id);

  const dom = item("domain-security");
  assert.ok(dom.found.some((f) => f === "Transfer lock: Off"));
  assert.deepEqual(dom.settings.find((s) => /Transfer lock/.test(s.what)), { what: "Transfer lock (Domain/Registrar Lock)", now: "Off", to: "On" });

  const spf = item("spf");
  assert.match(spf.found[0], /No SPF record/);
  assert.equal(spf.records[0].action, "Add");

  const dkim = item("dkim");
  assert.deepEqual(dkim.settings[0], { what: "DKIM signing in GoDaddy email", now: "Not set up", to: "On (2048-bit key where offered)" });

  const dmarc = item("dmarc");
  assert.deepEqual(dmarc.records.map((r) => r.action), ["Add", "Replace", "Replace", "Add"]);
  assert.equal(dmarc.records[1].current, dmarc.records[0].value, "stage 2 replaces stage 1");
  assert.equal(dmarc.records[3].zone, "nwimpm.com", "report authorization goes on the report domain");

  assert.match(item("ssl").settings[0].now, /^Expired \(CERT_HAS_EXPIRED\)$/);
  assert.match(item("https-redirect").settings[0].now, /Off \(HTTP 200\)/);
  assert.match(item("https-redirect").settings[0].to, /https:\/\/old\.example\.net\//);
});

test("duplicate SPF records: edit the first in place to the merged record, delete the rest; existing senders are named", async () => {
  const d = "example.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "example-com.mail.protection.outlook.com", priority: 0 }] },
    txt: { [d]: ["v=spf1 include:spf.protection.outlook.com -all", "v=spf1 include:sendgrid.net ~all"] },
  }));
  const spf = buildPlan(report, opts).items.find((i) => i.id === "spf");
  assert.deepEqual(spf.records.map((r) => r.action), ["Replace", "Delete"]);
  assert.equal(spf.records[0].current, "v=spf1 include:spf.protection.outlook.com -all");
  assert.equal(spf.records[0].value, "v=spf1 include:spf.protection.outlook.com include:sendgrid.net ~all");
  assert.equal(spf.records[1].value, "v=spf1 include:sendgrid.net ~all");
  assert.match(spf.rollback, /back to exactly: v=spf1 include:spf\.protection\.outlook\.com -all/);
  assert.ok(spf.found.some((f) => /SendGrid/.test(f) && /Microsoft 365/.test(f)));

  const dkim = buildPlan(report, opts).items.find((i) => i.id === "dkim");
  assert.deepEqual(dkim.records.map((r) => [r.type, r.name, r.generated]), [["CNAME", "selector1._domainkey", true], ["CNAME", "selector2._domainkey", true]]);
});

test("existing SPF is replaced, showing the current value next to the new one", async () => {
  const d = "example.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:mailgun.org +all"], "mailgun.org": ["v=spf1 ip4:1.2.3.4 -all"] },
  }));
  const spf = buildPlan(report, opts).items.find((i) => i.id === "spf");
  assert.equal(spf.records.length, 1);
  assert.equal(spf.records[0].action, "Replace");
  assert.equal(spf.records[0].current, "v=spf1 include:mailgun.org +all");
  assert.equal(spf.records[0].value, "v=spf1 include:mailgun.org include:_spf.google.com ~all");
  assert.ok(spf.found.some((f) => /\+all/.test(f)));
});

/* ------------------------------- pricing (Oct 15 2026) ------------------------------- */

test("approved prices live in lib/config.js: Standard $350, Plus $550, Quarterly $150/year, Monthly $35/month, founding $210", () => {
  assert.deepEqual(CONFIG.PACKAGES.map((p) => [p.id, p.price]), [["standard", 350], ["plus", 550]]);
  assert.match(CONFIG.PACKAGES[0].scope, /one domain and one email provider/i);
  assert.match(CONFIG.PACKAGES[1].scope, /extra sending services or messy records/i);
  assert.deepEqual(CONFIG.RECURRING_OPTIONS.map((r) => [r.name, r.price, r.period]), [["Quarterly Checkups", 150, "year"], ["Monthly Watch", 35, "month"]]);
  assert.deepEqual([CONFIG.FOUNDING_OFFER.price, CONFIG.FOUNDING_OFFER.limit, CONFIG.FOUNDING_OFFER.packageId, CONFIG.FOUNDING_OFFER.bonusRecurringId], [210, 3, "standard", "quarterly-checkups"]);
  assert.deepEqual(CONFIG.QUOTE_ITEMS["email-migration"], { title: "Move email to Google Workspace or Microsoft 365", from: 1500 }, "the migration quote is unchanged");
  assert.equal(CONFIG.ITEM_PRICES, undefined, "no per-fix prices");
  assert.equal(CONFIG.MONTHLY_OFFER, undefined, "the old $300 Monthly Tech Desk is gone");
  const text = JSON.stringify([CONFIG.PACKAGES, CONFIG.RECURRING_OPTIONS, CONFIG.FOUNDING_OFFER]);
  assert.ok(!/per[- ]user|user adds|removals/i.test(text), "flat fees per business, never per user");
  assert.ok(!/\bSEO\b|marketing|Google Business|reviews?\b/i.test(text), "non-compete");
});

test("period labels: /year and /month from the config, never assumed", () => {
  assert.equal(periodLabel(150, "year"), "$150/year");
  assert.equal(periodLabel(35, "month"), "$35/month");
  assert.equal(formatPrice(1500), "$1,500");
  assert.throws(() => periodLabel(35, "week"), /Unknown billing period/);
  assert.throws(() => periodLabel(35, undefined), /Unknown billing period/);
});

test("Plus is recommended for extra sending services or messy records; Standard otherwise", () => {
  const google = { key: "google", name: "Google Workspace" };
  const report = (checks) => ({ checks });
  const spf = (records, codes = []) => ({ id: "spf", status: "warn", data: { records, codes } });
  assert.deepEqual(packageFit(report([spf(["v=spf1 include:_spf.google.com ~all"])]), google), { id: "standard", reasons: [] }, "only the email provider");
  const extra = packageFit(report([spf(["v=spf1 include:_spf.google.com include:sendgrid.net include:servers.mcsv.net ~all"])]), google);
  assert.equal(extra.id, "plus");
  assert.match(extra.reasons[0], /also sent through SendGrid, Mailchimp/);
  assert.equal(packageFit(report([spf(["v=spf1 redirect=_spf.other-host.example.net"])]), google).id, "plus", "a redirect to another service counts too");
  assert.equal(packageFit(report([spf(["v=spf1 include:_spf.google.com ~all", "v=spf1 -all"], ["multiple"])]), google).id, "plus", "duplicate SPF records");
  assert.equal(packageFit(report([spf(["v=spf1 include:_spf.google.com ~all"], ["too-many-lookups"])]), google).id, "plus", "SPF over its limits");
  assert.equal(packageFit(report([{ id: "dmarc", status: "fail", data: { code: "multiple", records: ["a", "b"] } }]), google).id, "plus", "duplicate DMARC records");
  assert.equal(packageFit(report([{ id: "email-platform", status: "warn", data: { code: "mixed-mx", mx: ["a", "b"] } }]), google).id, "plus", "mail split across providers");
  assert.equal(packageFit(report([]), google).id, "standard");
});

test("a plan for a business that also sends through another service recommends Plus, and says why", async () => {
  const d = "example.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:_spf.google.com include:sendgrid.net ~all"], "_spf.google.com": ["v=spf1 ip4:1.2.3.4 ~all"], "sendgrid.net": ["v=spf1 ip4:5.6.7.8 ~all"], [`google._domainkey.${d}`]: [DKIM_RECORD] },
    tls: { [d]: goodTls, [`www.${d}`]: goodTls },
    http: { ok: true, status: 301, location: `https://${d}/` },
    rdap: rdapData(),
  }));
  const plan = buildPlan(report, opts);
  assert.equal(plan.pricing.recommended.id, "plus");
  assert.equal(plan.pricing.recommendedTotal, 550);
  assert.deepEqual(plan.pricing.packages.map((p) => [p.id, p.recommended]), [["standard", false], ["plus", true]]);
  assert.match(plan.pricing.recommended.reasons.join(" "), /SendGrid/);
});

test("Fix Plan page: shows both packages and both recurring options with their own period; the founding offer is a toggle, off by default", async () => {
  const { readFileSync } = await import("node:fs");
  const js = readFileSync(new URL("../public/plan.js", import.meta.url), "utf8");
  const html = readFileSync(new URL("../public/plan.html", import.meta.url), "utf8");
  assert.ok(!/\/month/.test(js), "no hard-coded /month: every period label comes from the plan (lib/config.js)");
  assert.ok(!/money\(it\.price\)|itemsTotal|pricing\.package\b|pricing\.monthly/.test(js), "no per-fix prices or the old single package/monthly line");
  assert.match(js, /p\.packages\.map\(\(pk\) =>/);
  assert.match(js, /plan\.pricing\.recurring\.map\(\(r\) =>/);
  assert.match(js, /h\("span", \{ class: "price" \}, r\.label\)/);
  assert.match(js, /let showFoundingOffer = false;/);
  assert.match(js, /if \(p\.founding && showFoundingOffer\)/);
  assert.match(js, /showFoundingOffer = false;\n\s+\$\("founding-toggle"\)\.checked = false;/, "reset to off for every new plan");
  assert.match(html, /<p class="founding-toggle no-print" id="founding-row" hidden>\s*<label class="check-row"><input type="checkbox" id="founding-toggle"> Show the founding client offer/);
  assert.ok(!/<input type="checkbox" id="founding-toggle"[^>]*checked/.test(html), "unchecked by default");
  assert.ok(!/\$\d/.test(html) && !/\$\d/.test(js.replace(/`\$\$\{/g, "")), "no prices written into the page: they all come from lib/config.js");
});

test("the public lander shows no prices", async () => {
  const { readFileSync } = await import("node:fs");
  for (const f of ["../public/index.html", "../public/lander.js"]) assert.ok(!/\$\s?\d|\/month|\/year|per user/i.test(readFileSync(new URL(f, import.meta.url), "utf8")), f);
});

test("the README's price table matches lib/config.js", async () => {
  const { readFileSync } = await import("node:fs");
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  for (const p of CONFIG.PACKAGES) assert.ok(readme.includes(`| ${p.name} fix (one-time) | ${formatPrice(p.price)} |`), p.name);
  for (const r of CONFIG.RECURRING_OPTIONS) assert.ok(readme.includes(`| ${r.name} (optional) | ${periodLabel(r.price, r.period)} |`), r.name);
  assert.ok(readme.includes(`a Standard fix for ${formatPrice(CONFIG.FOUNDING_OFFER.price)}`));
  assert.ok(readme.includes(`from ${formatPrice(CONFIG.QUOTE_ITEMS["email-migration"].from)}`));
});
