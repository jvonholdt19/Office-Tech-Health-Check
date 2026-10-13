// Part 1 (zone import) and Part 2 (dry run + verify) against realistic exports.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseZone, zoneResolver, dkimSelectors, inventory, compareWithLive } from "../lib/zone.js";
import { applyPlan, exportChanges } from "../lib/simulate.js";
import { verifyLive } from "../lib/verify.js";
import { buildFullPlan } from "../api/plan.js";
import { fakeDeps, fakeResolver, DKIM_RECORD } from "./fakes.js";

const fixture = (f) => readFileSync(new URL(`./fixtures/${f}`, import.meta.url), "utf8");

// Third-party SPF includes, answered by the "live DNS" fallback.
const INCLUDES = {
  "_spf.google.com": ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"],
  "_netblocks.google.com": ["v=spf1 ip4:35.190.247.0/24 ~all"],
  "_netblocks2.google.com": ["v=spf1 ip6:2001:4860:4000::/36 ~all"],
  "_netblocks3.google.com": ["v=spf1 ip4:172.217.0.0/19 ~all"],
  "sendgrid.net": ["v=spf1 ip4:167.89.0.0/17 ~all"],
  "secureserver.net": ["v=spf1 ip4:68.178.213.0/24 ~all"],
  "servers.mcsv.net": ["v=spf1 ip4:205.201.128.0/20 ~all"],
  "spf.protection.outlook.com": ["v=spf1 ip4:40.92.0.0/15 -all"],
};

/* ---------------- Part 1: reading exports ---------------- */

test("zone import: Cloudflare export (absolute names, split DKIM strings, proxied comments)", () => {
  const z = parseZone(fixture("cloudflare.txt"), "acme.com");
  assert.equal(z.format, "bind");
  assert.equal(z.records.filter((r) => r.type === "TXT" && r.name === "acme.com").length, 2);
  assert.equal(z.records.find((r) => r.name === "custom2024._domainkey.acme.com").value, DKIM_RECORD);
  assert.equal(z.records.find((r) => r.type === "SOA").name, "acme.com", "SOA name without trailing dot is not doubled");
  assert.deepEqual(dkimSelectors(z.records, "acme.com").sort(), ["custom2024", "mail2025"]);
  const inv = inventory(z.records, "acme.com");
  assert.ok(inv.email.some((e) => e.role === "SPF (approved senders)"));
  assert.ok(inv.website.some((e) => e.name === "www"));
  assert.ok(inv.verification.some((e) => /google-site-verification/.test(e.value)));
});

test("zone import: GoDaddy export ($ORIGIN, @, multi-line SOA, relative CNAME target)", () => {
  const z = parseZone(fixture("godaddy.txt"), "oldoffice.com");
  assert.deepEqual(z.records.filter((r) => r.type === "MX").map((r) => [r.priority, r.value]), [[0, "mx1.mail.secureserver.net"], [10, "mx2.mail.secureserver.net"]]);
  assert.equal(z.records.find((r) => r.name === "www.oldoffice.com").value, "oldoffice.com");
  assert.equal(z.records.filter((r) => /^v=spf1/.test(r.value)).length, 2);
  assert.deepEqual(z.warnings, []);
});

test("zone import: CSV and Route 53 JSON exports", () => {
  const c = parseZone(fixture("hosts.csv"), "csvco.com");
  assert.equal(c.format, "csv");
  assert.equal(c.records.find((r) => r.type === "TXT" && r.name === "csvco.com").value, "v=spf1 mx include:spf.protection.outlook.com ~all");
  assert.equal(c.records.find((r) => r.type === "MX").priority, 10);
  const j = parseZone(fixture("route53.json"), "r53co.com");
  assert.equal(j.format, "route53-json");
  assert.equal(j.records.find((r) => r.name === "_dmarc.r53co.com").value, "v=DMARC1; p=none; rua=mailto:d@r53co.com");
  assert.ok(j.records.some((r) => r.name === "*.r53co.com"));
});

test("zone import refuses the wrong domain, empty files and unreadable CSVs", () => {
  assert.throws(() => parseZone(fixture("godaddy.txt"), "acme.com"), /for oldoffice\.com, not acme\.com/);
  assert.throws(() => parseZone("   ", "acme.com"), /empty/);
  assert.throws(() => parseZone("Foo,Bar\n1,2\n", "acme.com"), /no DNS records|Type, Name/i);
  assert.throws(() => parseZone(fixture("cloudflare.txt"), "other.com"), /for acme\.com, not other\.com/);
});

test("zone resolver: answers from the file, follows CNAMEs, and sends other names to live DNS", async () => {
  const z = parseZone(fixture("cloudflare.txt"), "acme.com");
  const live = fakeResolver({ txt: { ...INCLUDES, "mail2025.dkim.example-esp.net": ["v=DKIM1; p=LIVEKEY"], "_dmarc.acme.com": ["live value must not be used"] } });
  const r = zoneResolver(z.records, "acme.com", live);
  assert.deepEqual(await r.resolveTxt("_dmarc.acme.com"), [["v=DMARC1; p=none; rua=mailto:reports@vendor.example"]]);
  assert.deepEqual(await r.resolveTxt("mail2025._domainkey.acme.com"), [["v=DKIM1; p=LIVEKEY"]], "CNAME followed to the provider");
  assert.deepEqual(await r.resolveTxt("sendgrid.net"), [["v=spf1 ip4:167.89.0.0/17 ~all"]], "outside the zone → live");
  await assert.rejects(r.resolveTxt("nothing.acme.com"), { code: "ENOTFOUND" });
});

test("zone import finds DKIM keys the public scan can't guess", async () => {
  const domain = "acme.com";
  const deps = fakeDeps({ txt: INCLUDES });
  const { report, zone } = await buildFullPlan(domain, { text: fixture("cloudflare.txt"), filename: "acme.com.txt" }, deps);
  const dkim = report.checks.find((c) => c.id === "dkim");
  assert.equal(dkim.status, "pass", "custom2024 key found in the file");
  assert.match(dkim.detail, /custom2024/);
  assert.equal(zone.format, "bind");
  assert.equal(zone.filename, "acme.com.txt");
});

test("compare with live DNS flags an out-of-date export", async () => {
  const z = parseZone(fixture("cloudflare.txt"), "acme.com");
  const live = fakeResolver({
    mx: { "acme.com": [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { ...INCLUDES, "acme.com": ["v=spf1 include:sendgrid.net include:_spf.google.com ~all"], "_dmarc.acme.com": ["v=DMARC1; p=none; rua=mailto:reports@vendor.example"], "custom2024._domainkey.acme.com": [DKIM_RECORD] },
  });
  const diffs = await compareWithLive(z.records, "acme.com", live);
  const byLabel = Object.fromEntries(diffs.map((x) => [x.label, x]));
  assert.equal(byLabel["Mail servers (MX)"].match, true);
  assert.equal(byLabel.SPF.match, false, "live SPF differs from the file");
  assert.equal(byLabel.DMARC.match, true);
  assert.equal(byLabel['DKIM key "custom2024"'].match, true);
  assert.equal(byLabel['DKIM key "mail2025"'].match, false, "CNAME target not resolvable live");
});

/* ---------------- Part 2: dry run ---------------- */

test("dry run on a GoDaddy zone: duplicate SPF merged, DMARC added at p=none, verdict safe, nothing else touched", async () => {
  const domain = "oldoffice.com";
  const { plan, simulation } = await buildFullPlan(domain, { text: fixture("godaddy.txt") }, fakeDeps({ txt: INCLUDES }));
  assert.ok(plan.items.some((i) => i.id === "spf"));
  assert.equal(simulation.mode, "zone");
  assert.equal(simulation.verdict, "safe", simulation.blockers.join(" / "));
  const spfC = simulation.comparisons.find((c) => c.id === "spf");
  assert.equal(spfC.before, "fail");
  assert.equal(spfC.after, "pass");
  assert.ok(["warn", "pass"].includes(simulation.comparisons.find((c) => c.id === "dmarc").after), "p=none with reports is better than missing");
  assert.ok(simulation.after.score > simulation.before.score);
  assert.ok(simulation.changes.some((c) => c.status === "later"), "later DMARC stages listed but not applied");
  assert.ok(!plan.items.some((i) => i.id === "dkim") || simulation.changes.every((c) => c.status !== "conflict"));
  // export contains only changes, never the website or MX records
  assert.doesNotMatch(simulation.export.zone, /\bA\b\s+192\.0\.2\.20|IN MX/);
  assert.match(simulation.export.zone, /REPLACE oldoffice\.com\. TXT "v=spf1 include:secureserver\.net -all"/);
  assert.match(simulation.export.zone, /DELETE {2}oldoffice\.com\. TXT "v=spf1 include:servers\.mcsv\.net ~all"/);
  assert.match(simulation.export.csv, /^Action,Type,Name,Current value,New value/);
});

test("dry run blocks when the plan's 'current' value doesn't match the records (stale plan)", () => {
  const base = [{ name: "acme.com", type: "TXT", value: "v=spf1 include:sendgrid.net ~all" }];
  const plan = { items: [{ title: "SPF", records: [{ action: "Replace", type: "TXT", name: "@", current: "v=spf1 include:mailgun.org ~all", value: "v=spf1 include:_spf.google.com include:mailgun.org ~all" }] }] };
  const r = applyPlan(base, plan, "acme.com");
  assert.equal(r.changes[0].status, "conflict");
  assert.equal(r.blockers.length, 1);
  assert.deepEqual(r.records, base, "records untouched");
});

test("dry run blocks a plan that would remove a sender, add a second SPF, tighten DMARC or touch the website", async () => {
  const { simulatePlan } = await import("../lib/simulate.js");
  const d = "acme.com";
  const base = [
    { name: d, type: "A", value: "192.0.2.1" },
    { name: d, type: "MX", priority: 1, value: "smtp.google.com" },
    { name: d, type: "TXT", value: "v=spf1 include:sendgrid.net include:_spf.google.com ~all" },
    { name: `_dmarc.${d}`, type: "TXT", value: "v=DMARC1; p=none; rua=mailto:me@acme.com" },
  ];
  const deps = fakeDeps({ txt: INCLUDES });
  const { runScan } = await import("../lib/scan.js");
  const before = await runScan(d, { ...deps, resolver: zoneResolver(base, d, deps.resolver), zoneAuthoritative: true });
  const bad = {
    items: [
      { title: "Bad SPF", records: [{ action: "Replace", type: "TXT", name: "@", current: base[2].value, value: "v=spf1 include:_spf.google.com ~all" }, { action: "Add", type: "TXT", name: "@", value: "v=spf1 include:mailgun.org ~all" }] },
      { title: "Bad DMARC", records: [{ action: "Replace", type: "TXT", name: "_dmarc", current: base[3].value, value: "v=DMARC1; p=reject; rua=mailto:dmarc@nwimpm.com" }] },
      { title: "Bad web", records: [{ action: "Delete", type: "A", name: "@", value: "192.0.2.1" }] },
    ],
  };
  const sim = await simulatePlan({ domain: d, base, authoritative: true, plan: bad, before, deps });
  assert.equal(sim.verdict, "blocked");
  const all = sim.blockers.join("\n");
  assert.match(all, /SPF would stop allowing: include:sendgrid\.net/);
  assert.match(all, /more than one SPF record/);
  assert.match(all, /DMARC would stop sending reports to mailto:me@acme\.com/);
  assert.match(all, /DMARC policy would tighten on day one/);
  assert.match(all, /unrelated to email authentication would change: removed acme\.com\|A/);
});

test("dry run without an upload uses public DNS for the records it reads", async () => {
  const d = "pubco.com";
  const deps = fakeDeps({ mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] }, txt: { ...INCLUDES, [d]: ["v=spf1 include:sendgrid.net ~all", "google-site-verification=x"] } });
  const { simulation, zone } = await buildFullPlan(d, null, deps);
  assert.equal(zone, null);
  assert.equal(simulation.mode, "public");
  assert.equal(simulation.verdict, "safe", simulation.blockers.join(" / "));
  assert.equal(simulation.comparisons.find((c) => c.id === "spf").after, "pass");
});

test("export escapes quotes and never claims to be a full zone", () => {
  const out = exportChanges([{ action: "Add", type: "TXT", name: "_dmarc", to: 'v=DMARC1; p=none; x="y"', status: "applied" }], "acme.com");
  assert.match(out.zone, /_dmarc\.acme\.com\. 3600 IN TXT "v=DMARC1; p=none; x=\\"y\\""/);
  assert.match(out.zone, /never replace a zone with it/);
});

/* ---------------- Verify live ---------------- */

test("verify live: ticks off published changes and explains what's still pending", async () => {
  const d = "acme.com";
  const resolver = fakeResolver({ txt: { ...INCLUDES, [d]: ["v=spf1 include:_spf.google.com include:sendgrid.net ~all"], [`_dmarc.${d}`]: ["v=DMARC1; p=none"] } });
  const { results, allDone } = await verifyLive(d, [
    { action: "Replace", type: "TXT", name: "@", from: "v=spf1 include:sendgrid.net ~all", to: "v=spf1 include:_spf.google.com include:sendgrid.net ~all", status: "applied" },
    { action: "Replace", type: "TXT", name: "_dmarc", from: "v=DMARC1; p=none", to: "v=DMARC1; p=none; rua=mailto:dmarc@nwimpm.com; fo=1", status: "applied" },
    { action: "Add", type: "TXT", name: "google._domainkey", to: "x", status: "assumed" },
    { action: "Add", type: "TXT", name: "evil.example.org.", to: "x", status: "applied" },
  ], { resolver });
  assert.deepEqual(results.map((r) => r.live), ["done", "pending", "pending", "skipped"]);
  assert.match(results[1].note, /Live value is different/);
  assert.equal(allDone, false);
});

test("SAFETY: an SPF include that no longer has an SPF record (cancelled service) blocks publishing", async () => {
  const { safetyCheckPlan } = await import("../lib/plan.js");
  const d = "acme.com";
  // oldnewsletter.example was a service the client stopped using; its SPF record is gone.
  const zoneText = `$ORIGIN ${d}.\n@ 3600 IN MX 1 smtp.google.com.\n@ 3600 IN TXT "v=spf1 include:oldnewsletter.example ~all"\n`;
  const deps = fakeDeps({ txt: INCLUDES });
  const { plan, simulation } = await buildFullPlan(d, { text: zoneText }, deps);
  const rec = plan.items.find((i) => i.id === "spf").records[0];
  assert.equal(rec.blocked, true);
  assert.match(rec.note, /oldnewsletter\.example has no SPF record/);
  assert.equal(simulation.verdict, "blocked");
  assert.ok(simulation.changes.some((c) => c.status === "blocked"));
  assert.ok(typeof safetyCheckPlan === "function");
});

test("SAFETY: when live DNS can't be reached, nothing is called safe", async () => {
  const d = "oldoffice.com";
  const offline = fakeDeps(); // no third-party records at all: the reachability probe fails
  const { plan, simulation } = await buildFullPlan(d, { text: fixture("godaddy.txt") }, offline);
  const rec = plan.items.find((i) => i.id === "spf").records.find((r) => r.action === "Replace");
  assert.equal(rec.lookups, null);
  assert.match(rec.note, /couldn't be reached/);
  assert.equal(plan.safety.checked, false);
  assert.equal(simulation.verdict, "check");
  assert.match(simulation.warnings[0], /Live DNS couldn't be reached/);
});

test("verify live refuses to report 'not published' when it can't reach DNS", async () => {
  await assert.rejects(verifyLive("acme.com", [{ action: "Add", type: "TXT", name: "_dmarc", to: "v=DMARC1; p=none", status: "applied" }], { resolver: fakeResolver() }), /couldn't be reached/);
});

test("compare with live DNS says 'couldn't check' instead of 'mismatch' when DNS is unreachable", async () => {
  const z = parseZone(fixture("cloudflare.txt"), "acme.com");
  const diffs = await compareWithLive(z.records, "acme.com", fakeResolver());
  assert.ok(diffs.every((x) => x.match === null));
});
