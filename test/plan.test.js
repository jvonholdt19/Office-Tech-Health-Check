import { test } from "node:test";
import assert from "node:assert/strict";
import { runScan } from "../lib/scan.js";
import { buildPlan, recommendSpf, recommendDmarc } from "../lib/plan.js";
import { identifyDnsHost } from "../lib/checks/dnshost.js";
import handler, { passcodeMatches } from "../api/plan.js";
import { fakeDeps, goodTls, rdapData } from "./fakes.js";

const PRICES = { "domain-security": 75, "domain-renewal": 50, spf: 100, dkim: 75, dmarc: 200, ssl: 100, "https-redirect": 50 };
const PKG = [{ id: "pkg", name: "Package", price: 450, covers: Object.keys(PRICES), blurb: "All of it." }];
const BIZ = { name: "NWIM PM", fullName: "x", contactEmail: "josh@nwimpm.com", bookingUrl: "https://cal.com/x", dmarcReportAddress: "dmarc@nwimpm.com" };
const opts = { business: BIZ, prices: PRICES, packages: PKG, quotes: { "email-migration": { title: "Move email", from: 1500 } }, monthly: null };

async function neglectedOffice() {
  const d = "oldoffice.com";
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
  assert.equal(dom.price, 125);
  assert.equal(plan.pricing.itemsTotal, 650);
  assert.equal(plan.pricing.package.price, 450);
  assert.equal(plan.pricing.package.savings, 200);
  assert.equal(plan.pricing.recommendedTotal, 450);
  assert.equal(plan.current.grade, "F");
  assert.equal(plan.projected.grade, "A");
  assert.equal(plan.quoteItems[0].id, "email-migration");
  assert.ok(plan.accessNeeded.some((a) => /GoDaddy/.test(a)));
});

test("a single finding produces a single item and no package", async () => {
  const d = "acme.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ip4:1.2.3.4 ~all"], [`google._domainkey.${d}`]: ["v=DKIM1; p=MIIB"] },
    tls: { [d]: goodTls, [`www.${d}`]: goodTls },
    http: { ok: true, status: 301, location: `https://${d}/` },
    rdap: rdapData(),
  }));
  const plan = buildPlan(report, opts);
  assert.deepEqual(plan.items.map((i) => i.id), ["dmarc"]);
  assert.equal(plan.pricing.package, null);
  assert.equal(plan.pricing.recommendedTotal, 200);
});

test("a healthy domain gets an empty plan", async () => {
  const d = "acme.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ip4:1.2.3.4 ~all"], [`_dmarc.${d}`]: ["v=DMARC1; p=reject; rua=mailto:x@acme.com"], [`google._domainkey.${d}`]: ["v=DKIM1; p=MIIB"] },
    tls: { [d]: goodTls, [`www.${d}`]: goodTls },
    http: { ok: true, status: 301, location: `https://${d}/` },
    rdap: rdapData(),
  }));
  const plan = buildPlan(report, opts);
  assert.equal(plan.nothingToFix, true);
  assert.equal(plan.pricing.recommendedTotal, 0);
});

test("unverifiable DKIM becomes a free 'confirm at kickoff' item, not a paid fix", async () => {
  const d = "acme.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ip4:1.2.3.4 ~all"], [`_dmarc.${d}`]: ["v=DMARC1; p=reject; rua=mailto:x@acme.com"] },
    tls: { [d]: goodTls, [`www.${d}`]: goodTls },
    http: { ok: true, status: 301, location: `https://${d}/` },
    rdap: rdapData(),
  }));
  const plan = buildPlan(report, opts);
  assert.ok(!plan.items.some((i) => i.id === "dkim"));
  assert.ok(plan.verifyItems.some((v) => /DKIM/.test(v.title)));
});

test("recommendSpf merges, dedupes, removes +all and adds the platform", () => {
  assert.equal(
    recommendSpf(["v=spf1 include:mailgun.org +all", "v=spf1 include:mailgun.org ip4:1.2.3.4 -all"], "microsoft"),
    "v=spf1 include:spf.protection.outlook.com include:mailgun.org ip4:1.2.3.4 ~all",
  );
  assert.equal(recommendSpf(["v=spf1 redirect=_spf.acme.com"], "other"), "v=spf1 include:_spf.acme.com ~all");
  assert.equal(recommendSpf([], "google"), "v=spf1 include:_spf.google.com ~all");
  assert.equal(recommendDmarc("none", "d@x.com"), "v=DMARC1; p=none; rua=mailto:d@x.com; fo=1");
});

test("DMARC staging respects an existing enforced policy", async () => {
  const d = "acme.com";
  const base = {
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    tls: { [d]: goodTls, [`www.${d}`]: goodTls }, http: { ok: true, status: 301, location: `https://${d}/` }, rdap: rdapData(),
  };
  const txtBase = { [d]: ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ip4:1.2.3.4 ~all"], [`google._domainkey.${d}`]: ["v=DKIM1; p=MIIB"] };
  const partial = buildPlan(await runScan(d, fakeDeps({ ...base, txt: { ...txtBase, [`_dmarc.${d}`]: ["v=DMARC1; p=quarantine; pct=50; rua=mailto:x@acme.com"] } })), opts);
  assert.deepEqual(partial.items.find((i) => i.id === "dmarc").records.filter((r) => !r.zone).map((r) => r.value.match(/p=(\w+)/)[1]), ["quarantine", "reject"]);
  // p=reject without a report address passes the scan, so the plan must NOT charge to "fix" it
  const noReports = buildPlan(await runScan(d, fakeDeps({ ...base, txt: { ...txtBase, [`_dmarc.${d}`]: ["v=DMARC1; p=reject"] } })), opts);
  assert.ok(!noReports.items.some((i) => i.id === "dmarc"));
  const monitor = buildPlan(await runScan(d, fakeDeps({ ...base, txt: { ...txtBase, [`_dmarc.${d}`]: ["v=DMARC1; p=none; rua=mailto:x@acme.com"] } })), opts);
  assert.deepEqual(monitor.items.find((i) => i.id === "dmarc").records.filter((r) => !r.zone).map((r) => r.value.match(/p=(\w+)/)[1]), ["none", "quarantine", "reject"]);
});

function fakeRes() {
  return {
    statusCode: 0, headers: {}, body: "",
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    end(b) { this.body = b; },
  };
}

test("plan API is locked without a passcode and rejects wrong ones", async () => {
  const saved = process.env.PLAN_PASSCODE;
  try {
    delete process.env.PLAN_PASSCODE;
    let res = fakeRes();
    await handler({ method: "GET", url: "/api/plan?domain=acme.com", headers: {}, socket: {} }, res);
    assert.equal(res.statusCode, 503);

    process.env.PLAN_PASSCODE = "correct-horse-battery";
    res = fakeRes();
    await handler({ method: "GET", url: "/api/plan?domain=acme.com", headers: { "x-plan-passcode": "nope", "x-forwarded-for": "9.9.9.9" }, socket: {} }, res);
    assert.equal(res.statusCode, 401);
    assert.equal(res.headers["cache-control"], "no-store");

    res = fakeRes();
    await handler({ method: "GET", url: "/api/plan?domain=localhost", headers: { "x-plan-passcode": "correct-horse-battery", "x-forwarded-for": "8.8.8.8" }, socket: {} }, res);
    assert.equal(res.statusCode, 400, "right passcode, invalid domain");

    assert.equal(passcodeMatches("a", "a"), true);
    assert.equal(passcodeMatches("a", "b"), false);
    assert.equal(passcodeMatches("", "b"), false);
  } finally {
    if (saved === undefined) delete process.env.PLAN_PASSCODE;
    else process.env.PLAN_PASSCODE = saved;
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
  assert.match(item("https-redirect").settings[0].to, /https:\/\/oldoffice\.com\//);
});

test("duplicate SPF records: delete each one, then add the merged record; existing senders are named", async () => {
  const d = "acme.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "acme-com.mail.protection.outlook.com", priority: 0 }] },
    txt: { [d]: ["v=spf1 include:spf.protection.outlook.com -all", "v=spf1 include:sendgrid.net ~all"] },
  }));
  const spf = buildPlan(report, opts).items.find((i) => i.id === "spf");
  assert.deepEqual(spf.records.map((r) => r.action), ["Delete", "Delete", "Add"]);
  assert.equal(spf.records[2].value, "v=spf1 include:spf.protection.outlook.com include:sendgrid.net ~all");
  assert.ok(spf.found.some((f) => /SendGrid/.test(f) && /Microsoft 365/.test(f)));

  const dkim = buildPlan(report, opts).items.find((i) => i.id === "dkim");
  assert.deepEqual(dkim.records.map((r) => [r.type, r.name, r.generated]), [["CNAME", "selector1._domainkey", true], ["CNAME", "selector2._domainkey", true]]);
});

test("existing SPF is replaced, showing the current value next to the new one", async () => {
  const d = "acme.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:mailgun.org +all"], "mailgun.org": ["v=spf1 ip4:1.2.3.4 -all"] },
  }));
  const spf = buildPlan(report, opts).items.find((i) => i.id === "spf");
  assert.equal(spf.records.length, 1);
  assert.equal(spf.records[0].action, "Replace");
  assert.equal(spf.records[0].current, "v=spf1 include:mailgun.org +all");
  assert.equal(spf.records[0].value, "v=spf1 include:_spf.google.com include:mailgun.org ~all");
  assert.ok(spf.found.some((f) => /\+all/.test(f)));
});
