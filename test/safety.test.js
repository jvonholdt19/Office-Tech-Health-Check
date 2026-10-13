// DNS-change safety: the plan must never hand a technician a record that would break a
// client's working email. Each test is a real-world situation that could cause an outage.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runScan } from "../lib/scan.js";
import { buildPlan, recommendSpf, recommendDmarc, safetyCheckPlan } from "../lib/plan.js";
import { fakeDeps } from "./fakes.js";

const opts = {
  business: { name: "NWIM PM", fullName: "x", contactEmail: "josh@nwimpm.com", bookingUrl: "x", dmarcReportAddress: "dmarc@nwimpm.com" },
  prices: { spf: 100, dkim: 75, dmarc: 200 }, packages: [], quotes: {}, monthly: null,
};

// Include trees shaped like the real ones: Google's include costs 4 lookups in total.
const REAL_INCLUDES = {
  "_spf.google.com": ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"],
  "_netblocks.google.com": ["v=spf1 ip4:35.190.247.0/24 ~all"],
  "_netblocks2.google.com": ["v=spf1 ip6:2001:4860:4000::/36 ~all"],
  "_netblocks3.google.com": ["v=spf1 ip4:172.217.0.0/19 ~all"],
  "spf.protection.outlook.com": ["v=spf1 ip4:40.92.0.0/15 -all"],
  "sendgrid.net": ["v=spf1 ip4:167.89.0.0/17 ~all"],
  "servers.mcsv.net": ["v=spf1 ip4:205.201.128.0/20 ~all"],
  "spf.constantcontact.com": ["v=spf1 ip4:208.75.120.0/22 ~all"],
  "_spf.intuit.com": ["v=spf1 ip4:206.108.40.0/21 ~all"],
  "mailgun.org": ["v=spf1 ip4:69.72.32.0/20 ~all"],
  "amazonses.com": ["v=spf1 ip4:54.240.0.0/18 ~all"],
};
const google = [{ exchange: "smtp.google.com", priority: 1 }];

async function plan(d, { mx = google, txt = {} } = {}) {
  const deps = fakeDeps({ mx: { [d]: mx }, txt: { ...REAL_INCLUDES, ...txt } });
  return { plan: buildPlan(await runScan(d, deps), opts), deps };
}

test("SAFETY: adding the email platform must not push SPF over 10 lookups (record is blocked, not offered)", async () => {
  const d = "busyoffice.com";
  // 7 lookups today, Google missing. Adding Google's include (4 more) would make 11.
  const current = "v=spf1 include:sendgrid.net include:servers.mcsv.net include:spf.constantcontact.com include:_spf.intuit.com include:mailgun.org include:amazonses.com a ~all";
  const { plan: p, deps } = await plan(d, { txt: { [d]: [current] } });
  await safetyCheckPlan(p, deps);
  const rec = p.items.find((i) => i.id === "spf").records.find((r) => /^v=spf1/.test(r.value) && r.action !== "Delete");
  assert.equal(rec.lookups, 11);
  assert.equal(rec.blocked, true, "must not be offered for publishing");
  assert.match(p.items.find((i) => i.id === "spf").steps[0], /^STOP/);
  assert.equal(p.safety.problems.length, 1);
});

test("SAFETY: a normal SPF fix passes the live check and shows its lookup count", async () => {
  const d = "acme.com";
  const { plan: p, deps } = await plan(d, { txt: { [d]: ["v=spf1 include:sendgrid.net ~all"] } });
  await safetyCheckPlan(p, deps);
  const rec = p.items.find((i) => i.id === "spf").records[0];
  assert.equal(rec.value, "v=spf1 include:sendgrid.net include:_spf.google.com ~all");
  assert.equal(rec.lookups, 5);
  assert.ok(!rec.blocked);
  assert.deepEqual(p.safety.problems, []);
});

test("SAFETY: unknown mail server and no SPF: never offer a record that authorizes nobody", async () => {
  const d = "selfhosted.com";
  const { plan: p } = await plan(d, { mx: [{ exchange: "mail.selfhosted.com", priority: 10 }] });
  const spf = p.items.find((i) => i.id === "spf");
  assert.equal(spf.records.length, 1);
  assert.equal(spf.records[0].generated, true, "placeholder, no copy button");
  assert.ok(spf.steps.some((s) => s.startsWith("STOP")));
  assert.equal(recommendSpf([], "other"), null);
  assert.equal(recommendSpf([], "proofpoint"), null, "an inbound filter says nothing about who sends outbound mail");
});

test("SAFETY: the recommended SPF keeps every sender the domain allows today", () => {
  const cases = [
    ["v=spf1 include:sendgrid.net ip4:203.0.113.5 a mx ~all", "google"],
    ["v=spf1 +include:mailgun.org ip6:2001:db8::/32 -all", "microsoft"],
    ["v=spf1 redirect=_spf.acme.com", "other"],
    ["v=spf1 include:_spf.google.com exists:%{i}._spf.acme.com ~all", "google"],
  ];
  const terms = (r) => r.split(/\s+/).slice(1).filter((t) => !/all$/i.test(t)).map((t) => t.replace(/^\+/, "").replace(/^redirect=/, "include:").toLowerCase());
  for (const [current, provider] of cases) {
    const next = new Set(terms(recommendSpf([current], provider).value));
    for (const t of terms(current)) assert.ok(next.has(t), `${current} → lost ${t}`);
  }
});

test("SAFETY: an existing strict -all is kept; only +all, ?all and missing become ~all", () => {
  assert.equal(recommendSpf(["v=spf1 include:sendgrid.net -all"], "google").value, "v=spf1 include:sendgrid.net include:_spf.google.com -all");
  assert.equal(recommendSpf(["v=spf1 include:sendgrid.net +all"], "google").value, "v=spf1 include:sendgrid.net include:_spf.google.com ~all");
  assert.equal(recommendSpf(["v=spf1 include:sendgrid.net ?all"], "google").value, "v=spf1 include:sendgrid.net include:_spf.google.com ~all");
  assert.equal(recommendSpf(["v=spf1 include:sendgrid.net"], "google").value, "v=spf1 include:sendgrid.net include:_spf.google.com ~all");
});

test("SAFETY: DMARC keeps the client's own report addresses and subdomain policy", async () => {
  const d = "acme.com";
  const existing = "v=DMARC1; p=none; sp=quarantine; rua=mailto:reports@vendor.example; adkim=s";
  const { plan: p } = await plan(d, {
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], [`_dmarc.${d}`]: [existing], [`google._domainkey.${d}`]: ["v=DKIM1; p=MIIB"] },
  });
  const recs = p.items.find((i) => i.id === "dmarc").records.filter((r) => !r.zone);
  assert.equal(recs[0].current, existing);
  for (const r of recs) {
    assert.match(r.value, /rua=mailto:reports@vendor\.example,mailto:dmarc@nwimpm\.com/);
    assert.match(r.value, /sp=quarantine/);
    assert.match(r.value, /adkim=s/);
  }
  assert.equal(recommendDmarc("none", "d@x.com"), "v=DMARC1; p=none; rua=mailto:d@x.com; fo=1", "unchanged for a new record");
});

test("SAFETY: DMARC never starts above monitor-only unless the client already enforces", async () => {
  const d = "acme.com";
  const { plan: p } = await plan(d, { txt: { [d]: ["v=spf1 include:_spf.google.com ~all"] } });
  const dm = p.items.find((i) => i.id === "dmarc");
  assert.match(dm.records[0].value, /p=none/, "stage 1 only monitors");
  assert.ok(dm.steps.some((s) => /do NOT advance/.test(s)), "explicit gate before tightening");
  assert.match(dm.rollback, /step back one stage/);
});

test("SAFETY: duplicate DMARC records: edit the first in place, delete the rest", async () => {
  const d = "acme.com";
  const { plan: p } = await plan(d, {
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], [`_dmarc.${d}`]: ["v=DMARC1; p=none", "v=DMARC1; p=reject"], [`google._domainkey.${d}`]: ["v=DKIM1; p=MIIB"] },
  });
  const recs = p.items.find((i) => i.id === "dmarc").records.filter((r) => !r.zone);
  assert.deepEqual(recs.map((r) => r.action).slice(0, 2), ["Replace", "Delete"]);
  assert.equal(recs[0].current, "v=DMARC1; p=none");
});

test("SAFETY: every DNS-changing fix says how to undo it", async () => {
  const d = "acme.com";
  const { plan: p } = await plan(d, { txt: { [d]: ["v=spf1 include:sendgrid.net +all"] } });
  assert.ok(p.items.length >= 3);
  for (const it of p.items) assert.ok(it.rollback, `${it.id} has no rollback`);
  assert.match(p.items.find((i) => i.id === "spf").rollback, /back to exactly: v=spf1 include:sendgrid\.net \+all/);
});
