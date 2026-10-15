// Domain Health: composes lib/checks/domain-health.js into one scored report with the shared
// safely / summarizeChecks / gradeFor from lib/scan.js, plus Domain-Health-only grade caps.
import { defaultDeps, withTimeout, isNotFound } from "./net.js";
import { normalizeDomain } from "./domain.js";
import { safely, summarizeChecks } from "./scan.js";
import { queryDns, TYPE } from "./dnswire.js";
import { renderGuide } from "./fix-guides.js";
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
  lookupEmailAuth,
  checkEmailAuth,
  lookupCnames,
  checkDanglingCname,
} from "./checks/domain-health.js";

const GRADE_ORDER = ["A", "B", "C", "D", "F"];

/**
 * Hard caps on top of the weighted score (the score itself is unchanged):
 *   expired, in the redemption period or pending delete → F (the domain is lost or about to be);
 *   a nameserver that doesn't resolve → at most D (lookups that pick it fail).
 */
export function applyDomainCaps(grade, checks) {
  const by = Object.fromEntries(checks.map((c) => [c.id, c]));
  const code = (id) => by[id]?.data?.code;
  const caps = [];
  if (code("domain-expiry") === "expired") caps.push({ check: "domain-expiry", maxGrade: "F", reason: "the domain has expired" });
  if (code("domain-status") === "redemption") caps.push({ check: "domain-status", maxGrade: "F", reason: "the domain is in its redemption period" });
  if (code("domain-status") === "pending-delete") caps.push({ check: "domain-status", maxGrade: "F", reason: "the domain is pending deletion" });
  if (code("nameservers") === "ns-unresolvable") caps.push({ check: "nameservers", maxGrade: "D", reason: "a nameserver doesn't resolve" });
  caps.sort((a, b) => GRADE_ORDER.indexOf(b.maxGrade) - GRADE_ORDER.indexOf(a.maxGrade));
  if (!grade || !caps.length) return { grade, cappedBy: caps };
  const worst = caps[0].maxGrade;
  return { grade: GRADE_ORDER.indexOf(grade) < GRADE_ORDER.indexOf(worst) ? worst : grade, cappedBy: caps };
}

const querySoa = (ip, domain) => queryDns(ip, domain, TYPE.SOA);
const queryDnskey = (ip, domain) => queryDns(ip, domain, TYPE.DNSKEY);

async function lookupSoa(domain, resolver) {
  try {
    return { ok: true, soa: await withTimeout(resolver.resolveSoa(domain), 5000, `SOA ${domain}`) };
  } catch (err) {
    return { ok: false, notFound: isNotFound(err), error: err.code || err.message };
  }
}

async function lookupCaa(domain, resolver) {
  try {
    return { ok: true, records: await withTimeout(resolver.resolveCaa(domain), 5000, `CAA ${domain}`) };
  } catch (err) {
    return { ok: false, notFound: isNotFound(err), error: err.code || err.message };
  }
}

/** DNSKEY from the first nameserver that answered authoritatively (only when the registry says signed). */
async function probeDnskey(domain, rdap, probe, deps) {
  if (!(rdap?.ok && rdap.data?.secureDNS?.delegationSigned === true)) return null;
  const server = (probe?.servers || []).find((s) => s.authoritative && s.ip);
  if (!server) return { ok: false, error: "no authoritative nameserver answered" };
  const r = await deps.queryDnskey(server.ip, domain);
  if (!r.ok) return { ok: false, ns: server.ns, error: r.error };
  return { ok: true, ns: server.ns, count: r.answers.filter((a) => a.type === TYPE.DNSKEY).length + (r.tc ? 1 : 0) };
}

export async function runDomainScan(input, overrides = {}) {
  const parsed = normalizeDomain(typeof input === "string" ? input : "");
  if (parsed.error) return { error: parsed.error };
  const domain = parsed.domain;
  const deps = { ...defaultDeps, querySoa, queryDnskey, ...testDeps, ...overrides };
  const started = Date.now();

  const [rdap, probe, soa, caa, mx, auth, cnames] = await Promise.all([
    deps.fetchRdap(domain).catch((err) => ({ ok: false, error: err.message })),
    probeNameservers(domain, deps).catch((err) => ({ ok: false, error: err.message })),
    lookupSoa(domain, deps.resolver),
    lookupCaa(domain, deps.resolver),
    lookupMx(domain, deps).catch((err) => ({ ok: false, error: err.message })),
    lookupEmailAuth(domain, deps),
    lookupCnames(domain, deps).catch((err) => ({ ok: false, error: err.message })),
  ]);
  const dnskey = await probeDnskey(domain, rdap, probe, deps).catch((err) => ({ ok: false, error: err.message }));

  const meta = (id, title, category, weight) => ({ id, title, category, weight });
  const checks = [
    await safely(meta("domain-expiry", "Domain renewal date", "Registration", 20), () => checkExpiry(rdap, deps)),
    await safely(meta("domain-status", "Transfer lock and domain status", "Registration", 10), () => checkStatus(rdap)),
    await safely(meta("nameservers", "Nameservers", "DNS", 15), () => checkNameservers(probe)),
    await safely(meta("soa", "SOA record", "DNS", 5), () => checkSoa(soa, probe)),
    await safely(meta("dnssec", "DNSSEC", "DNS", 0), () => checkDnssec(rdap, dnskey)),
    await safely(meta("caa", "CAA", "DNS", 3), () => checkCaa(caa)),
    await safely(meta("dangling-cname", "Dangling CNAME records (subdomain takeover)", "DNS", 10), () => checkDanglingCname(cnames)),
    await safely(meta("mx", "Mail servers (MX)", "Email", 10), () => checkMx(mx)),
    await safely(meta("email-auth", "Email authentication (SPF and DMARC)", "Email", 10), () => checkEmailAuth(domain, auth)),
  ];

  for (const c of checks) {
    if (c.status === "warn" || c.status === "fail") {
      const guide = renderGuide(c, domain);
      if (guide) c.guide = guide;
    }
  }

  const summary = summarizeChecks(checks);
  const { grade, cappedBy } = applyDomainCaps(summary.grade, checks);
  const fixes = checks.filter((c) => c.fix && (c.status === "fail" || c.status === "warn"));
  return {
    domain,
    target: domain,
    scannedAt: deps.now().toISOString(),
    durationMs: Date.now() - started,
    ...summary,
    grade,
    data: { cappedBy: cappedBy.length ? cappedBy : null, uncappedGrade: summary.grade },
    checks,
    fixes: fixes.map((c) => ({ id: c.id, title: c.title, status: c.status, fix: c.fix })),
  };
}

let testDeps = {};
/** Tests (and only tests) replace the network layer here. */
export function setDomainDepsForTests(deps) {
  testDeps = deps || {};
}
