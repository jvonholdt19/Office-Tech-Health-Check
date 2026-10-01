import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeDomain } from "../lib/domain.js";
import { identifyProvider, parseSpf, countSpfLookups, checkSpf, checkDmarc, checkDkim, parseDmarc } from "../lib/checks/email.js";
import { checkSsl, checkHttpsRedirect, checkDomainRegistration, summarizeRdap } from "../lib/checks/web.js";
import { fetchRdap } from "../lib/net.js";
import { runScan, scoreChecks, gradeFor } from "../lib/scan.js";
import { fakeDeps, fakeResolver, goodTls, rdapData } from "./fakes.js";

const google = { key: "google", name: "Google Workspace" };
const microsoft = { key: "microsoft", name: "Microsoft 365" };

test("normalizeDomain cleans up common inputs", () => {
  assert.deepEqual(normalizeDomain("https://www.Acme-Accounting.com/contact?x=1"), { domain: "acme-accounting.com" });
  assert.deepEqual(normalizeDomain("  jane@acme.co.uk "), { domain: "acme.co.uk" });
  assert.deepEqual(normalizeDomain("acme.com."), { domain: "acme.com" });
  assert.deepEqual(normalizeDomain("acme.com:8080"), { domain: "acme.com" });
});

test("normalizeDomain rejects IPs, single labels and internal names", () => {
  for (const bad of ["", "localhost", "10.0.0.1", "http://192.168.1.1/", "server.local", "printer.corp", "-bad-.com", "a..com", "foo.test"]) {
    assert.ok(normalizeDomain(bad).error, `expected error for ${JSON.stringify(bad)}`);
  }
});

test("identifyProvider recognises the big platforms", () => {
  assert.equal(identifyProvider([{ exchange: "aspmx.l.google.com", priority: 1 }]).key, "google");
  assert.equal(identifyProvider([{ exchange: "smtp.google.com", priority: 1 }]).key, "google");
  assert.equal(identifyProvider([{ exchange: "acme-com.mail.protection.outlook.com", priority: 0 }]).key, "microsoft");
  assert.equal(identifyProvider([{ exchange: "mx1.mail.secureserver.net", priority: 0 }]).key, "godaddy");
  assert.equal(identifyProvider([{ exchange: "mx0a-001.pphosted.com", priority: 0 }]).key, "proofpoint");
  assert.equal(identifyProvider([{ exchange: "mail.acme.com", priority: 0 }]).key, "other");
  assert.equal(identifyProvider([]).key, "none");
});

test("parseSpf extracts the all qualifier and includes", () => {
  const p = parseSpf("v=spf1 include:_spf.google.com include:mailgun.org a mx ~all");
  assert.equal(p.allQualifier, "~");
  assert.deepEqual(p.includes, ["_spf.google.com", "mailgun.org"]);
  assert.equal(p.directLookups, 4);
  assert.equal(parseSpf("v=spf1 all").allQualifier, "+");
});

test("countSpfLookups follows includes recursively", async () => {
  const resolver = fakeResolver({
    txt: {
      "a.example.com": ["v=spf1 include:b.example.com include:c.example.com -all"],
      "b.example.com": ["v=spf1 ip4:1.2.3.4 include:d.example.com -all"],
      "c.example.com": ["v=spf1 a mx -all"],
      "d.example.com": ["v=spf1 ip4:5.6.7.8 -all"],
    },
  });
  assert.equal(await countSpfLookups(resolver, "v=spf1 include:a.example.com -all"), 1 + 2 + 1 + 2 + 0);
});

test("SPF: missing, duplicate, permissive and healthy records", async () => {
  const d = "acme.com";
  let r = await checkSpf(d, fakeDeps({ txt: {} }), google);
  assert.equal(r.status, "fail");

  r = await checkSpf(d, fakeDeps({ txt: { [d]: ["v=spf1 -all", "v=spf1 ~all"] } }), google);
  assert.equal(r.status, "fail");
  assert.match(r.summary, /more than one/);

  r = await checkSpf(d, fakeDeps({ txt: { [d]: ["v=spf1 include:_spf.google.com +all"] } }), google);
  assert.equal(r.status, "fail");

  r = await checkSpf(d, fakeDeps({ txt: { [d]: ["v=spf1 include:sendgrid.net ~all"] } }), google);
  assert.equal(r.status, "warn");
  assert.match(r.summary, /Google Workspace/);

  r = await checkSpf(d, fakeDeps({ txt: { [d]: ["google-site-verification=abc", "v=spf1 include:_spf.google.com ~all"] } }), google);
  assert.equal(r.status, "pass");
});

test("SPF: too many DNS lookups fails", async () => {
  const d = "acme.com";
  const includes = Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`).join(" ");
  const r = await checkSpf(d, fakeDeps({ txt: { [d]: [`v=spf1 ${includes} -all`] } }), { key: "other" });
  assert.equal(r.status, "fail");
  assert.match(r.summary, /limit of 10/);
});

test("DMARC: missing, monitor-only, enforced", async () => {
  const d = "acme.com";
  assert.equal((await checkDmarc(d, fakeDeps())).status, "fail");

  let r = await checkDmarc(d, fakeDeps({ txt: { [`_dmarc.${d}`]: ["v=DMARC1; p=none; rua=mailto:x@acme.com"] } }));
  assert.equal(r.status, "warn");
  assert.match(r.summary, /monitor only/);

  r = await checkDmarc(d, fakeDeps({ txt: { [`_dmarc.${d}`]: ["v=DMARC1; p=reject; rua=mailto:x@acme.com"] } }));
  assert.equal(r.status, "pass");
  assert.equal(r.fix, null);

  r = await checkDmarc(d, fakeDeps({ txt: { [`_dmarc.${d}`]: ["v=DMARC1; p=quarantine; pct=25; rua=mailto:x@acme.com"] } }));
  assert.equal(r.status, "warn");

  assert.deepEqual(parseDmarc("v=DMARC1; p=reject; rua=mailto:a@b.com"), { v: "DMARC1", p: "reject", rua: "mailto:a@b.com" });
});

test("DKIM: finds the provider selector, warns when missing", async () => {
  const d = "acme.com";
  let r = await checkDkim(d, fakeDeps({ txt: { [`google._domainkey.${d}`]: ["v=DKIM1; k=rsa; p=MIIBIjAN"] } }), google);
  assert.equal(r.status, "pass");

  r = await checkDkim(d, fakeDeps({ txt: { [`selector1._domainkey.${d}`]: ["v=DKIM1; k=rsa; p=MIIBIjAN"] } }), microsoft);
  assert.equal(r.status, "pass");

  r = await checkDkim(d, fakeDeps(), microsoft);
  assert.equal(r.status, "warn");

  // Revoked key (empty p=) does not count
  r = await checkDkim(d, fakeDeps({ txt: { [`google._domainkey.${d}`]: ["v=DKIM1; p="] } }), google);
  assert.equal(r.status, "warn");
});

test("SSL: valid, invalid, expiring soon, unreachable", async () => {
  const d = "acme.com";
  let r = await checkSsl(d, fakeDeps({ tls: { [d]: goodTls, [`www.${d}`]: goodTls } }));
  assert.equal(r.status, "pass");

  r = await checkSsl(d, fakeDeps({ tls: { [d]: goodTls, [`www.${d}`]: { ...goodTls, authorized: false, authorizationError: "ERR_TLS_CERT_ALTNAME_INVALID" } } }));
  assert.equal(r.status, "fail");
  assert.match(r.summary, /www\.acme\.com/);

  r = await checkSsl(d, fakeDeps({ tls: { [d]: { ...goodTls, validTo: "2026-10-08T00:00:00Z" } } }));
  assert.equal(r.status, "warn");

  r = await checkSsl(d, fakeDeps());
  assert.equal(r.status, "info");
  assert.equal(r.weight, 0);
});

test("HTTPS redirect", async () => {
  assert.equal((await checkHttpsRedirect("acme.com", fakeDeps({ http: { ok: true, status: 301, location: "https://acme.com/" } }))).status, "pass");
  assert.equal((await checkHttpsRedirect("acme.com", fakeDeps({ http: { ok: true, status: 200 } }))).status, "warn");
  assert.equal((await checkHttpsRedirect("acme.com", fakeDeps({ http: { ok: true, status: 301, location: "http://www.acme.com/" } }))).status, "warn");
});

test("Domain registration: healthy, expiring, unlocked, unavailable", async () => {
  let r = await checkDomainRegistration("acme.com", fakeDeps({ rdap: rdapData() }));
  assert.equal(r.status, "pass");
  assert.match(r.detail, /Example Registrar/);

  r = await checkDomainRegistration("acme.com", fakeDeps({ rdap: rdapData({ expiry: "2026-10-15T00:00:00Z" }) }));
  assert.equal(r.status, "fail");

  r = await checkDomainRegistration("acme.com", fakeDeps({ rdap: rdapData({ locked: false }) }));
  assert.equal(r.status, "warn");

  // Registry unreachable: "couldn't verify", which is excluded from the score but shown
  r = await checkDomainRegistration("acme.com", fakeDeps());
  assert.equal(r.status, "unknown");

  // Extension with no public RDAP service: not applicable
  r = await checkDomainRegistration("acme.co.xx", fakeDeps({ rdap: { ok: false, unsupported: true, error: "no RDAP" } }));
  assert.equal(r.status, "info");
  assert.equal(r.weight, 0);
});

test("scoring and grades", () => {
  assert.equal(scoreChecks([{ weight: 10, status: "pass" }, { weight: 10, status: "fail" }, { weight: 0, status: "info" }]), 50);
  assert.equal(scoreChecks([{ weight: 0, status: "info" }]), null);
  assert.equal(gradeFor(95), "A");
  assert.equal(gradeFor(59), "F");
});

test("runScan: a well-run Google Workspace office gets an A", async () => {
  const d = "acme.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: {
      [d]: ["v=spf1 include:_spf.google.com ~all"],
      [`_dmarc.${d}`]: ["v=DMARC1; p=reject; rua=mailto:dmarc@acme.com"],
      [`google._domainkey.${d}`]: ["v=DKIM1; k=rsa; p=MIIB"],
      "_spf.google.com": ["v=spf1 include:_netblocks.google.com ~all"],
    },
    tls: { [d]: goodTls, [`www.${d}`]: goodTls },
    http: { ok: true, status: 301, location: "https://acme.com/" },
    rdap: rdapData(),
  }));
  assert.equal(report.grade, "A");
  assert.equal(report.score, 100);
  assert.equal(report.provider.name, "Google Workspace");
  assert.equal(report.fixes.length, 0);
  assert.equal(report.checks.length, 7);
  assert.ok(!("provider" in report.checks[0]), "internal fields are stripped");
});

test("runScan: a neglected office gets an F with a fix list", async () => {
  const d = "oldoffice.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "mx1.mail.secureserver.net", priority: 0 }] },
    http: { ok: true, status: 200 },
    tls: { [d]: { ...goodTls, authorized: false, authorizationError: "CERT_HAS_EXPIRED" } },
    rdap: rdapData({ expiry: "2026-10-20T00:00:00Z", locked: false }),
  }));
  assert.equal(report.grade, "F");
  assert.ok(report.fixes.length >= 5);
  assert.ok(report.fixes.some((f) => f.id === "email-platform"), "suggests moving off bundled hosting email");
});

test("runScan: a check that throws becomes a 'couldn't verify' row, not a crash", async () => {
  const d = "acme.com";
  const deps = fakeDeps({ mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] } });
  deps.resolver.resolveTxt = async () => {
    throw Object.assign(new Error("SERVFAIL"), { code: "ESERVFAIL" });
  };
  const report = await runScan(d, deps);
  const spf = report.checks.find((c) => c.id === "spf");
  assert.equal(spf.status, "unknown");
  assert.match(spf.summary, /couldn't be completed/);
  assert.ok(report.unverified.some((u) => u.id === "spf"), "listed as unverified");
  assert.ok(report.coverage < 100);
});

/* ---- Regression tests from the live 20-domain validation run (2026-10-01) ---- */

test("live bug: SPF that authorises Google via _netblocks (vercel.com pattern) is not flagged", async () => {
  const d = "acme.com";
  const r = await checkSpf(d, fakeDeps({ txt: {
    [d]: ["v=spf1 include:_netblocks.google.com include:sendgrid.net ~all"],
    "_netblocks.google.com": ["v=spf1 ip4:74.125.0.0/16 ~all"],
    "sendgrid.net": ["v=spf1 ip4:1.2.3.4 -all"],
  } }), google);
  assert.equal(r.status, "pass");
});

test("live bug: Microsoft 365 authorised through a nested include (microsoft.com / godaddy.com pattern)", async () => {
  const d = "acme.com";
  const r = await checkSpf(d, fakeDeps({ txt: {
    [d]: ["v=spf1 include:_spf-a.acme.com -all"],
    "_spf-a.acme.com": ["v=spf1 include:spf.protection.outlook.com -all"],
    "spf.protection.outlook.com": ["v=spf1 ip4:40.92.0.0/15 -all"],
  } }), microsoft);
  assert.equal(r.status, "pass");
});

test("SPF still warns when the platform is genuinely missing from the whole include tree", async () => {
  const d = "acme.com";
  const r = await checkSpf(d, fakeDeps({ txt: { [d]: ["v=spf1 include:mailgun.org ~all"], "mailgun.org": ["v=spf1 ip4:1.2.3.4 -all"] } }), microsoft);
  assert.equal(r.status, "warn");
});

test("live bug: null MX (example.com) is 'no email', and DKIM is not applicable", async () => {
  const d = "example.com";
  assert.equal(identifyProvider([{ exchange: "", priority: 0 }]).key, "nullmx");
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "", priority: 0 }] },
    txt: { [d]: ["v=spf1 -all"], [`_dmarc.${d}`]: ["v=DMARC1;p=reject;sp=reject"] },
  }));
  const dkim = report.checks.find((c) => c.id === "dkim");
  assert.equal(dkim.status, "info");
  assert.equal(dkim.weight, 0);
  assert.equal(report.provider.key, "nullmx");
});

test("live bug: custom DKIM selector with enforced DMARC (google.com pattern) is 'couldn't verify', not a warning", async () => {
  const d = "acme.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ip4:74.125.0.0/16 ~all"], [`_dmarc.${d}`]: ["v=DMARC1; p=reject; rua=mailto:x@acme.com"] },
  }));
  assert.equal(report.checks.find((c) => c.id === "dkim").status, "unknown");
});

test("missing DKIM with no DMARC enforcement is still a warning", async () => {
  const d = "acme.com";
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], [`_dmarc.${d}`]: ["v=DMARC1; p=none"] },
  }));
  assert.equal(report.checks.find((c) => c.id === "dkim").status, "warn");
});

test("live bug: enterprise email filters are named, not called 'self-hosted'", () => {
  assert.equal(identifyProvider([{ exchange: "mx1.intuit.iphmx.com", priority: 5 }]).key, "cisco");
  assert.equal(identifyProvider([{ exchange: "mxa.global.inbound.cf-emailsecurity.net", priority: 5 }]).key, "cloudflare");
  assert.equal(identifyProvider([{ exchange: "mail.acme.com", priority: 5 }]).name, "Other email provider");
});

test("grade is withheld when less than half the weighted checks could be verified", async () => {
  const d = "acme.com";
  const deps = fakeDeps({ mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] }, tls: { [d]: goodTls }, http: { ok: true, status: 301, location: "https://acme.com/" } });
  deps.resolver.resolveTxt = async () => { throw Object.assign(new Error("SERVFAIL"), { code: "ESERVFAIL" }); };
  const report = await runScan(d, deps);
  assert.equal(report.grade, null);
  assert.ok(report.unverified.length >= 3);
});

test("summarizeRdap parses real registry responses (Verisign .com, PIR .org, captured 2026-10-01)", () => {
  const verisign = {
    events: [
      { eventAction: "registration", eventDate: "1997-09-15T04:00:00Z" },
      { eventAction: "expiration", eventDate: "2028-09-14T04:00:00Z" },
      { eventAction: "last changed", eventDate: "2019-09-09T15:39:04Z" },
    ],
    status: ["client delete prohibited", "client transfer prohibited", "client update prohibited", "server delete prohibited", "server transfer prohibited", "server update prohibited"],
    secureDNS: { delegationSigned: false },
    entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]] }],
  };
  assert.deepEqual(summarizeRdap(verisign), {
    expiry: "2028-09-14T04:00:00Z", registered: "1997-09-15T04:00:00Z", registrar: "MarkMonitor Inc.", transferLocked: true, dnssec: false,
  });
  const pir = {
    events: [
      { eventAction: "transfer", eventDate: "2006-09-12T02:40:41.291Z" },
      { eventAction: "expiration", eventDate: "2027-01-23T05:00:00Z" },
      { eventAction: "registration", eventDate: "1998-01-24T05:00:00.291Z" },
    ],
    status: ["client transfer prohibited", "server transfer prohibited"],
    secureDNS: { delegationSigned: false, maxSigLife: 1 },
    entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]] }],
  };
  const p = summarizeRdap(pir);
  assert.equal(p.expiry, "2027-01-23T05:00:00Z");
  assert.equal(p.registered, "1998-01-24T05:00:00.291Z");
  assert.equal(p.transferLocked, true);
});

test("fetchRdap asks the registry directly, then falls back to rdap.org", async () => {
  const calls = [];
  const fake = (responses) => async (url) => {
    calls.push(url);
    const hit = Object.entries(responses).find(([k]) => url.startsWith(k));
    const [status, body] = hit ? hit[1] : [404, {}];
    return { ok: status < 400, status, json: async () => body };
  };
  let r = await fetchRdap("acme.com", { fetchImpl: fake({ "https://rdap.verisign.com/com/v1/domain/acme.com": [200, { ldhName: "ACME.COM" }] }) });
  assert.equal(r.ok, true);
  assert.equal(calls[0], "https://rdap.verisign.com/com/v1/domain/acme.com");

  calls.length = 0;
  r = await fetchRdap("acme.com", { fetchImpl: fake({ "https://rdap.verisign.com": [503, {}], "https://rdap.org/": [200, { ldhName: "ACME.COM" }] }) });
  assert.equal(r.ok, true);
  assert.deepEqual(calls.map((u) => new URL(u).host), ["rdap.verisign.com", "rdap.org"]);
});
