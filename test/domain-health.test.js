// Domain Health: each check's paths with a fake resolver / RDAP / nameserver probe, the grade caps,
// the DNS wire format, the private endpoint and the fix guides. Offline.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  checkExpiry,
  checkStatus,
  checkDnssec,
  probeNameservers,
  checkNameservers,
  checkSoa,
  checkCaa,
  lookupMx,
  checkMx,
  checkEmailAuth,
  lookupCnames,
  checkDanglingCname,
  TAKEOVER_PATTERNS,
} from "../lib/checks/domain-health.js";
import { runDomainScan, applyDomainCaps, setDomainDepsForTests } from "../lib/domain-scan.js";
import { buildQuery, parseResponse, queryDns, TYPE } from "../lib/dnswire.js";
import { FIX_GUIDES, guideFor, renderGuide } from "../lib/fix-guides.js";
import domainHandler from "../api/domain.js";
import { setStoreForTests, memoryStore } from "../lib/store.js";
import { onAudit } from "../lib/audit.js";
import { encodeSession, newSession } from "../lib/session.js";
import { fakeResolver, NOW } from "./fakes.js";

const D = "example.com";
const now = { now: () => NOW };
const inDays = (n) => new Date(NOW.getTime() + n * 864e5 + 3600e3).toISOString();
const rdap = ({ expiry = inDays(400), status = ["client transfer prohibited"], secureDNS } = {}) => ({
  ok: true,
  data: { events: expiry ? [{ eventAction: "expiration", eventDate: expiry }] : [], status, ...(secureDNS ? { secureDNS } : {}) },
});
const soaAnswer = (serial, { aa = true, rcode = 0 } = {}) => ({ ok: true, aa, rcode, tc: false, answers: aa && rcode === 0 ? [{ type: TYPE.SOA, data: { serial } }] : [] });
const SOA = { nsname: "ns1.host.example.net", hostmaster: "h.host.example.net", serial: 5, refresh: 7200, retry: 900, expire: 1209600, minttl: 3600 };

/* ------------------------------ expiry ------------------------------ */

test("expiry: 61 days pass, 59 warn, 13 fail, expired fail, no date unknown", () => {
  assert.equal(checkExpiry(rdap({ expiry: inDays(61) }), now).status, "pass");
  const w = checkExpiry(rdap({ expiry: inDays(59) }), now);
  assert.equal(w.status, "warn");
  assert.equal(w.data.code, "expiring-soon");
  assert.equal(checkExpiry(rdap({ expiry: inDays(13) }), now).data.code, "expiring-urgent");
  assert.equal(checkExpiry(rdap({ expiry: inDays(13) }), now).status, "fail");
  assert.equal(checkExpiry(rdap({ expiry: inDays(-3) }), now).data.code, "expired");
  assert.equal(checkExpiry(rdap({ expiry: null }), now).status, "unknown");
  assert.equal(checkExpiry({ ok: false, error: "HTTP 500" }, now).status, "unknown");
  assert.equal(checkExpiry({ ok: false, unsupported: true, error: "no RDAP" }, now).weight, 0);
  assert.equal(checkExpiry(rdap(), now).weight, 20);
});

/* ------------------------------ status ------------------------------ */

test("status: transfer lock passes, missing lock warns, redemption / pending delete / hold fail; codes explained", () => {
  const locked = checkStatus(rdap({ status: ["client transfer prohibited", "client delete prohibited"] }));
  assert.equal(locked.status, "pass");
  assert.match(locked.detail, /transfer lock set by the registrar/);
  assert.equal(checkStatus(rdap({ status: ["server transfer prohibited"] })).status, "pass");
  const open = checkStatus(rdap({ status: ["active"] }));
  assert.equal(open.status, "warn");
  assert.equal(open.data.code, "no-transfer-lock");
  assert.equal(checkStatus(rdap({ status: ["redemption period"] })).data.code, "redemption");
  assert.equal(checkStatus(rdap({ status: ["pending delete"] })).data.code, "pending-delete");
  assert.equal(checkStatus(rdap({ status: ["client hold", "client transfer prohibited"] })).data.code, "on-hold");
});

/* ------------------------------ DNSSEC ------------------------------ */

test("DNSSEC: unsigned is info (weight 0); signed with keys passes; signed without DNSKEY fails", () => {
  const unsigned = checkDnssec(rdap({ secureDNS: { delegationSigned: false } }), null);
  assert.equal(unsigned.status, "info");
  assert.equal(unsigned.weight, 0);
  assert.equal(checkDnssec(rdap({ secureDNS: { delegationSigned: true } }), { ok: true, ns: "ns1", count: 2 }).status, "pass");
  const broken = checkDnssec(rdap({ secureDNS: { delegationSigned: true } }), { ok: true, ns: "ns1", count: 0 });
  assert.equal(broken.status, "fail");
  assert.equal(broken.data.code, "broken");
  assert.equal(checkDnssec(rdap({ secureDNS: { delegationSigned: true } }), { ok: false, error: "timeout" }).status, "unknown");
});

/* --------------------------- nameservers --------------------------- */

const nsResolver = (ns, a) => fakeResolver({ ns: { [D]: ns }, a });

test("nameservers: one NS fails", async () => {
  const probe = await probeNameservers(D, { resolver: nsResolver(["ns1.host.example.net"], { "ns1.host.example.net": ["93.184.216.1"] }), querySoa: async () => soaAnswer(5) });
  const r = checkNameservers(probe);
  assert.equal(r.status, "fail");
  assert.equal(r.data.code, "too-few");
});

test("nameservers: a non-resolving NS fails (and caps at D); a lame NS warns; healthy passes with notes", async () => {
  const unres = checkNameservers(await probeNameservers(D, { resolver: nsResolver(["ns1.host.example.net", "ns2.gone.example.net"], { "ns1.host.example.net": ["93.184.216.1"] }), querySoa: async () => soaAnswer(5) }));
  assert.equal(unres.status, "fail");
  assert.equal(unres.data.code, "ns-unresolvable");
  assert.deepEqual(unres.data.nameservers, ["ns2.gone.example.net"]);

  const resolver = nsResolver(["ns1.host.example.net", "ns2.host.example.net"], { "ns1.host.example.net": ["93.184.216.1"], "ns2.host.example.net": ["93.184.216.2"] });
  const lame = checkNameservers(await probeNameservers(D, { resolver, querySoa: async (ip) => (ip.endsWith(".2") ? soaAnswer(5, { aa: false }) : soaAnswer(5)) }));
  assert.equal(lame.status, "warn");
  assert.equal(lame.data.code, "lame");
  const timeout = checkNameservers(await probeNameservers(D, { resolver, querySoa: async (ip) => (ip.endsWith(".2") ? { ok: false, error: "timeout" } : soaAnswer(5)) }));
  assert.equal(timeout.data.code, "lame", "no answer counts as lame");

  const ok = checkNameservers(await probeNameservers(D, { resolver, querySoa: async () => soaAnswer(5) }));
  assert.equal(ok.status, "pass");
  assert.match(ok.detail, /one \/24/);
  assert.match(ok.detail, /run by example\.net/);
});

test("nameservers: private NS addresses are never queried", async () => {
  const asked = [];
  const resolver = nsResolver(["ns1.host.example.net", "ns2.evil.example.net"], { "ns1.host.example.net": ["93.184.216.1"], "ns2.evil.example.net": ["10.0.0.53", "169.254.169.254"] });
  const r = checkNameservers(await probeNameservers(D, { resolver, querySoa: async (ip) => (asked.push(ip), soaAnswer(5)) }));
  assert.deepEqual(asked, ["93.184.216.1"]);
  assert.equal(r.data.code, "ns-unresolvable", "an NS with only private addresses is treated as unusable");
  assert.deepEqual(await queryDns("10.0.0.53", D, TYPE.SOA, { createSocket: () => assert.fail("no socket for a private IP") }), { ok: false, refused: true, error: "non-public address" });
});

/* -------------------------------- SOA ------------------------------- */

test("SOA: serial mismatch warns; out-of-range timers are info only; missing SOA warns", async () => {
  const resolver = nsResolver(["ns1.host.example.net", "ns2.host.example.net"], { "ns1.host.example.net": ["93.184.216.1"], "ns2.host.example.net": ["93.184.216.2"] });
  const probe = await probeNameservers(D, { resolver, querySoa: async (ip) => soaAnswer(ip.endsWith(".1") ? 2026100101 : 2026093001) });
  const mismatch = checkSoa({ ok: true, soa: SOA }, probe);
  assert.equal(mismatch.status, "warn");
  assert.equal(mismatch.data.code, "serial-mismatch");
  const same = await probeNameservers(D, { resolver, querySoa: async () => soaAnswer(7) });
  assert.equal(checkSoa({ ok: true, soa: SOA }, same).status, "pass");
  const odd = checkSoa({ ok: true, soa: { ...SOA, refresh: 300, expire: 60, minttl: 5 } }, same);
  assert.equal(odd.status, "info", "providers vary: never warn or fail for timers");
  assert.equal(checkSoa({ ok: false, notFound: true, error: "ENODATA" }, same).data.code, "missing");
});

/* -------------------------------- CAA ------------------------------- */

test("CAA: none is info, present passes and lists issuers", () => {
  assert.equal(checkCaa({ ok: false, notFound: true }).status, "info");
  const r = checkCaa({ ok: true, records: [{ critical: 0, issue: "letsencrypt.org" }, { critical: 0, iodef: "mailto:x@example.com" }] });
  assert.equal(r.status, "pass");
  assert.match(r.summary, /letsencrypt\.org/);
});

/* -------------------------------- MX -------------------------------- */

test("MX: null MX is info; MX to a private IP fails; unresolvable MX fails; healthy passes; no MX is info", async () => {
  const nullMx = await lookupMx(D, { resolver: fakeResolver({ mx: { [D]: [{ exchange: "", priority: 0 }] } }) });
  assert.equal(checkMx(nullMx).data.code, "null-mx");
  assert.equal(checkMx(nullMx).status, "info");
  const priv = checkMx(await lookupMx(D, { resolver: fakeResolver({ mx: { [D]: [{ exchange: "mail.example.com", priority: 10 }] }, a: { "mail.example.com": ["192.168.1.20"] } }) }));
  assert.equal(priv.status, "fail");
  assert.equal(priv.data.code, "mx-private");
  const gone = checkMx(await lookupMx(D, { resolver: fakeResolver({ mx: { [D]: [{ exchange: "old.mailhost.example.net", priority: 10 }] } }) }));
  assert.equal(gone.data.code, "mx-unresolvable");
  const ok = checkMx(await lookupMx(D, { resolver: fakeResolver({ mx: { [D]: [{ exchange: "aspmx.l.google.com", priority: 1 }] }, a: { "aspmx.l.google.com": ["142.250.1.26"] } }) }));
  assert.equal(ok.status, "pass");
  assert.equal(checkMx(await lookupMx(D, { resolver: fakeResolver() })).data.code, "no-mx");
});

/* --------------------------- email auth ---------------------------- */

test("email authentication: presence only, with a link to the full Email Security Check", () => {
  const ok = checkEmailAuth(D, { ok: true, spf: true, dmarc: true });
  assert.equal(ok.status, "pass");
  assert.equal(ok.data.link.href, "/tools/email?d=example.com");
  assert.equal(checkEmailAuth(D, { ok: true, spf: false, dmarc: true }).data.code, "missing-spf");
  assert.equal(checkEmailAuth(D, { ok: true, spf: true, dmarc: false }).data.code, "missing-dmarc");
  assert.equal(checkEmailAuth(D, { ok: true, spf: false, dmarc: false }).data.code, "missing-both");
  assert.equal(ok.weight, 10);
});

/* -------------------------- dangling CNAME -------------------------- */

test("dangling CNAME: azurewebsites.net target with NXDOMAIN fails; a non-matching CNAME that resolves is fine", async () => {
  const takeover = checkDanglingCname(await lookupCnames(D, { resolver: fakeResolver({ cname: { "www.example.com": ["example-old.azurewebsites.net"] } }) }));
  assert.equal(takeover.status, "fail");
  assert.equal(takeover.data.code, "possible-takeover");
  assert.match(takeover.summary, /possible takeover/);
  const fine = checkDanglingCname(await lookupCnames(D, { resolver: fakeResolver({ cname: { "www.example.com": ["sites.wixdns.net"] }, a: { "sites.wixdns.net": ["34.149.87.45"] } }) }));
  assert.equal(fine.status, "pass");
  const alive = checkDanglingCname(await lookupCnames(D, { resolver: fakeResolver({ cname: { "shop.example.com": ["example.azurewebsites.net"] }, a: { "example.azurewebsites.net": ["20.1.2.3"] } }) }));
  assert.equal(alive.status, "pass", "a takeover-prone service that still exists is fine");
  const broken = checkDanglingCname(await lookupCnames(D, { resolver: fakeResolver({ cname: { "blog.example.com": ["old-blog.example.net"] } }) }));
  assert.equal(broken.data.code, "dangling");
  assert.equal(checkDanglingCname(await lookupCnames(D, { resolver: fakeResolver() })).status, "pass");
});

/* --------------------------- caps + scan ---------------------------- */

const scanDeps = (over = {}) => ({
  resolver: fakeResolver({
    ns: { [D]: ["ns1.host.example.net", "ns2.host.example.net"] },
    a: { "ns1.host.example.net": ["93.184.216.1"], "ns2.host.example.net": ["93.184.216.2"], "aspmx.l.google.com": ["142.250.1.26"] },
    mx: { [D]: [{ exchange: "aspmx.l.google.com", priority: 1 }] },
    soa: { [D]: SOA },
    caa: { [D]: [{ critical: 0, issue: "letsencrypt.org" }] },
    txt: { [D]: ["v=spf1 include:_spf.google.com ~all"], [`_dmarc.${D}`]: ["v=DMARC1; p=reject"] },
    ...over.dns,
  }),
  fetchRdap: async () => over.rdap || rdap(),
  querySoa: async () => soaAnswer(5),
  queryDnskey: async () => ({ ok: true, aa: true, rcode: 0, answers: [{ type: TYPE.DNSKEY, data: {} }] }),
  now: () => NOW,
});

test("a healthy domain gets an A; redemption caps at F; an unresolvable NS caps at D", async () => {
  const good = await runDomainScan(D, scanDeps());
  assert.equal(good.grade, "A");
  assert.equal(good.data.cappedBy, null);
  assert.equal(good.checks.find((c) => c.id === "dnssec").status, "info");

  const red = await runDomainScan(D, scanDeps({ rdap: rdap({ status: ["redemption period"] }) }));
  assert.equal(red.grade, "F");
  assert.equal(red.data.cappedBy[0].check, "domain-status");
  assert.notEqual(red.data.uncappedGrade, "F", "the cap, not the score, made it F");

  const ns = await runDomainScan(D, scanDeps({ dns: { ns: { [D]: ["ns1.host.example.net", "ns2.gone.example.net"] } } }));
  assert.equal(ns.data.cappedBy[0].maxGrade, "D");
  assert.ok(["D", "F"].includes(ns.grade));
  assert.equal(applyDomainCaps("A", [{ id: "domain-expiry", data: { code: "expired" } }]).grade, "F");
  assert.equal(applyDomainCaps("F", [{ id: "nameservers", data: { code: "ns-unresolvable" } }]).grade, "F", "a cap never improves a grade");
});

test("a domain that isn't in DNS or at the registry gets a clear error instead of a graded report", async () => {
  const r = await runDomainScan("missing.example.net", { ...scanDeps(), fetchRdap: async () => ({ ok: false, error: "HTTP 404", status: 404 }) });
  assert.equal(r.notFound, true);
  assert.match(r.error, /couldn't find missing\.example\.net/);
});

test("the report carries guides only for warn/fail checks", async () => {
  const r = await runDomainScan(D, scanDeps({ rdap: rdap({ expiry: inDays(30), status: ["active"] }), dns: { txt: {} } }));
  for (const c of r.checks) assert.equal(Boolean(c.guide), c.status === "warn" || c.status === "fail", c.id);
  assert.ok(r.checks.find((c) => c.id === "domain-expiry").guide.message.includes("example.com"));
});

/* ---------------------------- DNS wire ------------------------------ */

test("DNS wire format: query has RD off and EDNS; SOA answers with name compression are parsed", () => {
  const { id, packet } = buildQuery("example.com", TYPE.SOA, 0x1234);
  assert.equal(packet.readUInt16BE(0), 0x1234);
  assert.equal(packet.readUInt16BE(2) & 0x0100, 0, "recursion desired is off");
  assert.equal(packet.readUInt16BE(10), 1, "EDNS OPT record");
  // Response: header (QR|AA), the question, then one SOA answer using compression pointers.
  const q = packet.subarray(12, packet.length - 11);
  const header = Buffer.from([0x12, 0x34, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0]);
  const rdata = Buffer.concat([
    Buffer.from([3, ...Buffer.from("ns1"), 0xc0, 0x0c]), // ns1.<question name>
    Buffer.from([4, ...Buffer.from("host"), 0xc0, 0x0c]),
    Buffer.from([0x78, 0xc1, 0x0e, 0x51]), // serial 2026966609
    Buffer.from([0, 0, 0x1c, 0x20, 0, 0, 0x03, 0x84, 0, 0x12, 0x75, 0x00, 0, 0, 0x0e, 0x10]),
  ]);
  const rr = Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0x0e, 0x10]), Buffer.from([rdata.length >> 8, rdata.length & 255]), rdata]);
  const r = parseResponse(Buffer.concat([header, q, rr]));
  assert.equal(r.id, id);
  assert.equal(r.aa, true);
  assert.equal(r.rcode, 0);
  assert.equal(r.answers[0].data.mname, "ns1.example.com");
  assert.equal(r.answers[0].data.serial, 0x78c10e51);
  assert.equal(r.answers[0].data.refresh, 7200);
  assert.equal(r.answers[0].data.minimum, 3600);
  const loop = Buffer.concat([header, Buffer.from([0xc0, 0x0c])]);
  assert.throws(() => parseResponse(loop), /loop|truncated/);
});

/* ----------------------------- endpoint ----------------------------- */

const SECRET = "test-session-secret-0123456789-abcdefgh";
let saved;
let store;
let events;
let stop;
beforeEach(() => {
  saved = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = SECRET;
  store = memoryStore();
  setStoreForTests(store);
  events = [];
  stop = onAudit((e) => events.push(e));
  setDomainDepsForTests(scanDeps());
});
afterEach(() => {
  stop();
  setStoreForTests(undefined);
  setDomainDepsForTests(null);
  if (saved === undefined) delete process.env.SESSION_SECRET;
  else process.env.SESSION_SECRET = saved;
});
async function callDomain(domain, cookie) {
  const res = { statusCode: 0, headers: {}, body: "", setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(b) { this.body = b; } };
  await domainHandler({ method: "GET", url: `/api/domain?domain=${encodeURIComponent(domain)}&consent=true`, headers: { host: "officetech.nwimpm.com", "x-real-ip": "203.0.113.9", "user-agent": "t", ...(cookie ? { cookie } : {}) }, socket: {} }, res);
  return { status: res.statusCode, headers: res.headers, json: res.body ? JSON.parse(res.body) : null };
}
const cookie = () => `ohc_tech=${encodeSession(newSession(), SECRET)}`;

test("/api/domain: 401 without a session; audited as domain_scan with a summary; 429 after 3 a minute", async () => {
  assert.equal((await callDomain(D)).status, 401);
  const c = cookie();
  const r = await callDomain(D, c);
  assert.equal(r.status, 200);
  assert.equal(r.json.domain, D);
  const e = events.find((x) => x.event === "domain_scan");
  assert.ok(e && e.sid && e.domain === D);
  assert.deepEqual(Object.keys(e.data).sort(), ["consent", "counts", "durationMs", "grade", "score"]);
  assert.equal(e.data.consent, true);
  await callDomain(D, c);
  await callDomain(D, c);
  const limited = await callDomain(D, cookie());
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers["retry-after"]) > 0);
  assert.equal((await callDomain("localhost", c)).status, 400);
});

/* ------------------------------ guides ------------------------------ */

const FLAGGABLE = {
  "domain-expiry": ["expired", "expiring-urgent", "expiring-soon"],
  "domain-status": ["no-transfer-lock", "redemption", "pending-delete", "on-hold"],
  nameservers: ["too-few", "ns-unresolvable", "lame"],
  soa: ["missing", "serial-mismatch"],
  dnssec: ["broken"],
  mx: ["mx-unresolvable", "mx-private"],
  "email-auth": ["missing-spf", "missing-dmarc", "missing-both"],
  "dangling-cname": ["possible-takeover", "dangling"],
};

test("registrar and DNS-host steps match the official help pages they cite", () => {
  const steps = (id, platform) => FIX_GUIDES[id].platforms.find((p) => p.id === platform).steps.join(" ");
  const srcs = (id) => FIX_GUIDES[id].sources.join(" ");
  // GoDaddy help 41085 / 410 / 664
  assert.match(steps("domain-expiry", "godaddy"), /Renew section, switch Auto-renew on/);
  assert.match(steps("domain-status", "godaddy"), /Transfer section, switch the toggle On/);
  assert.match(steps("nameservers", "godaddy"), /DNS, then Nameservers/);
  assert.match(srcs("domain-status"), /godaddy\.com\/help\/unlock-or-lock-my-domain-410/);
  assert.match(srcs("nameservers"), /godaddy\.com\/help\/change-my-domain-nameservers-664/);
  // Namecheap KB 373 / 380 / 767
  assert.match(steps("domain-expiry", "namecheap"), /Actions → Auto-Renew/);
  assert.match(steps("domain-status", "namecheap"), /Sharing & Transfer.*Domain Lock/);
  assert.match(steps("nameservers", "namecheap"), /green checkmark/);
  assert.match(srcs("nameservers"), /knowledgebase\/article\.aspx\/767/);
  // Cloudflare docs
  assert.match(steps("domain-expiry", "cloudflare-registrar"), /Renew\/Extend Domain/);
  assert.match(steps("domain-status", "cloudflare-registrar"), /Manage Domains page.*Configuration/);
  assert.match(steps("nameservers", "dns-cloudflare"), /Overview page/);
  assert.match(FIX_GUIDES.nameservers.risk, /turn it off at the registrar before replacing nameservers/);
  assert.match(steps("mx", "dns-cloudflare"), /Edit, then Delete/);
  // Microsoft Learn / Google Workspace Admin Help
  assert.match(steps("mx", "microsoft-365"), /Settings → Domains.*Manage DNS/);
  assert.match(steps("mx", "microsoft-365"), /mail\.protection\.outlook\.com/);
  assert.match(steps("mx", "google-workspace"), /smtp\.google\.com, priority 1/);
  assert.ok(!FIX_GUIDES["email-auth"].platforms.some((p) => ["microsoft-365", "google-workspace"].includes(p.id)), "unverified SPF steps dropped");
});

test("takeover patterns are exactly the can-i-take-over-xyz entries detectable by NXDOMAIN", () => {
  for (const p of ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "blob.core.windows.net", "azure-api.net", "elasticbeanstalk.com", "trydiscourse.com"]) assert.ok(TAKEOVER_PATTERNS.includes(p), p);
  for (const p of ["trafficmanager.net", "s3.amazonaws.com", "herokuapp.com", "github.io", "netlify.app", "wpengine.com", "elb.amazonaws.com"]) assert.ok(!TAKEOVER_PATTERNS.includes(p), `${p} not listed (HTTP fingerprint, not in the table, or not vulnerable)`);
});

test("every flaggable Domain Health check + code has a complete guide", () => {
  for (const [id, codes] of Object.entries(FLAGGABLE)) {
    assert.equal(FIX_GUIDES[id].tool, "domain", id);
    for (const code of codes) {
      const g = guideFor(id, code);
      for (const k of ["why", "message", "verify"]) assert.ok(typeof g[k] === "string" && g[k].length > 20, `${id}/${code}.${k}`);
      assert.ok(["easy", "moderate", "advanced"].includes(g.difficulty), `${id}/${code} difficulty`);
      assert.ok(g.time, `${id}/${code} time`);
      assert.ok(g.sources.length && g.sources.every((u) => /^https:\/\//.test(u)), `${id} sources`);
      assert.ok(g.platforms.length >= 2 && g.platforms.every((p) => p.label && p.steps.length), `${id}/${code} platforms`);
      const rendered = renderGuide({ id, status: "warn", summary: "s", detail: "d", data: { code } }, D);
      assert.ok(!/\{(domain|finding|detail)\}/.test(rendered.message + rendered.verify), `${id}/${code} placeholders filled`);
      assert.match(rendered.message, /our IT provider/i);
    }
  }
  const registrars = ["godaddy", "namecheap", "cloudflare-registrar"];
  for (const id of ["domain-expiry", "domain-status"]) assert.deepEqual(FIX_GUIDES[id].platforms.map((p) => p.id), registrars, id);
  for (const id of ["mx", "dangling-cname"]) assert.ok(FIX_GUIDES[id].platforms.some((p) => p.id === "dns-cloudflare"), id);
  for (const id of ["mx"]) for (const p of ["microsoft-365", "google-workspace"]) assert.ok(FIX_GUIDES[id].platforms.some((x) => x.id === p), `${id}/${p}`);
  for (const id of ["domain-expiry", "nameservers", "dnssec", "mx", "email-auth", "dangling-cname"]) assert.ok(FIX_GUIDES[id].risk, `${id} risk`);
  // Only steps confirmed on the vendors' own help pages remain: nothing hedged or guessed.
  for (const id of Object.keys(FLAGGABLE)) {
    for (const p of FIX_GUIDES[id].platforms) {
      assert.ok(!["squarespace-domains", "dns-registrar"].includes(p.id), `${id}: ${p.id} was dropped (no official page)`);
      for (const step of p.steps) assert.ok(!/not confirmed/i.test(step), `${id}/${p.id}: "${step}"`);
    }
  }
});
