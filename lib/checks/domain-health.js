// Domain Health (technician tool). Passive only: DNS lookups through the resolver, the RDAP lookup
// lib/net.js already does, and SOA/DNSKEY questions sent to the domain's own nameservers (UDP 53,
// public IPs only, see lib/dnswire.js). No HTTP to the target, no port scans, no zone transfers.
//
// Weights (our judgment): renewal 20 · nameservers 15 · transfer lock/status 10 · MX 10 ·
// email authentication 10 · dangling CNAME 10 · SOA 5 · CAA 3 · DNSSEC 0 (info).
// Caps (lib/domain-scan.js): expired, redemption period or pending delete → F; a nameserver that
// doesn't resolve → at most D.

import { withTimeout, isNotFound, isNonPublicAddress, txtRecords } from "../net.js";

const CAT_REG = "Registration";
const CAT_DNS = "DNS";
const CAT_MAIL = "Email";
const DAY = 24 * 60 * 60 * 1000;
const fmtDate = (iso) => new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
const MAX_NS = 6;
const MAX_MX = 6;

/** Resolve A and AAAA for a host. Returns { ok, addresses, notFound, error }. */
export async function resolveHost(host, resolver) {
  const addresses = [];
  let notFound = 0;
  let error = null;
  for (const fn of ["resolve4", "resolve6"]) {
    try {
      addresses.push(...(await withTimeout(resolver[fn](host), 5000, `${fn} ${host}`)));
    } catch (err) {
      if (isNotFound(err)) notFound++;
      else error = err.code || err.message;
    }
  }
  return { ok: addresses.length > 0, addresses, notFound: notFound === 2, error };
}

/* ------------------------------------------------------------------ */
/* 1. Registration expiry (RDAP)                                       */
/* ------------------------------------------------------------------ */

/**
 * Website-tool thresholds, stricter than the email scanner's 30/90-day registration check (which is
 * unchanged): fail under 14 days or expired, warn under 60. ICANN's ERRP has registrars send reminders
 * about one month and one week before expiry, so 60 days gives time to act before those.
 */
export function checkExpiry(rdap, { now }) {
  const base = { id: "domain-expiry", category: CAT_REG, title: "Domain renewal date", weight: 20 };
  if (!rdap?.ok && rdap?.unsupported) return { ...base, status: "info", weight: 0, summary: "This domain's registry doesn't publish registration details, so check the renewal date at the registrar.", detail: rdap.error, fix: null };
  if (!rdap?.ok) return { ...base, status: "unknown", summary: "We couldn't reach the registry to read the renewal date. Try again shortly.", detail: `RDAP lookup failed: ${rdap?.error || "unknown error"}`, fix: null };
  const events = Array.isArray(rdap.data?.events) ? rdap.data.events : [];
  const expiry = events.find((e) => /expiration/i.test(e.eventAction))?.eventDate;
  if (!expiry) return { ...base, status: "unknown", summary: "The registry doesn't publish an expiry date for this domain. Check it at the registrar.", detail: "No expiration event in RDAP.", fix: null };
  const days = Math.floor((new Date(expiry).getTime() - now().getTime()) / DAY);
  const detail = `Expires ${fmtDate(expiry)} (${days} days)`;
  const fix = "Renew now, turn on auto-renew, and check the payment card and the registrar account owner.";
  if (days < 0) return { ...base, status: "fail", summary: `The domain expired ${-days} day${days === -1 ? "" : "s"} ago. The website and email stop working, and the name can be lost.`, detail, data: { code: "expired", days }, fix: "Renew it at the registrar today. Recently expired domains can usually be renewed during a grace period; later it costs more or is lost." };
  if (days < 14) return { ...base, status: "fail", summary: `The domain expires in ${days} day${days === 1 ? "" : "s"}. If it isn't renewed, the website and every email address on it stop working.`, detail, data: { code: "expiring-urgent", days }, fix };
  if (days < 60) return { ...base, status: "warn", summary: `The domain expires in ${days} days. Make sure auto-renew is on and the card on file is current.`, detail, data: { code: "expiring-soon", days }, fix };
  return { ...base, status: "pass", summary: `The domain is registered until ${fmtDate(expiry)}.`, detail, data: { days }, fix: null };
}

/* ------------------------------------------------------------------ */
/* 2. Registrar lock and status codes (RDAP / EPP, RFC 5731, RFC 8056) */
/* ------------------------------------------------------------------ */

// RDAP status values (RFC 8056 mapping of EPP codes) in plain English.
const STATUS_TEXT = {
  active: "active (normal)",
  ok: "active (normal)",
  inactive: "not delegated (no nameservers)",
  "client transfer prohibited": "transfer lock set by the registrar (good)",
  "server transfer prohibited": "transfer lock set by the registry (good)",
  "client delete prohibited": "delete lock set by the registrar",
  "server delete prohibited": "delete lock set by the registry",
  "client update prohibited": "change lock set by the registrar",
  "server update prohibited": "change lock set by the registry",
  "client renew prohibited": "renewal blocked by the registrar",
  "server renew prohibited": "renewal blocked by the registry",
  "client hold": "on hold by the registrar: the domain doesn't work",
  "server hold": "on hold by the registry: the domain doesn't work",
  "redemption period": "expired and deleted: can only be restored for a fee",
  "pending delete": "about to be deleted and released",
  "pending transfer": "a transfer to another registrar is in progress",
  "pending update": "a change is in progress",
  "pending renew": "a renewal is in progress",
  "pending restore": "a restore is in progress",
  "pending create": "registration is in progress",
  "add period": "newly registered",
  "auto renew period": "just auto-renewed",
  "renew period": "just renewed",
  "transfer period": "just transferred",
};

export function checkStatus(rdap) {
  const base = { id: "domain-status", category: CAT_REG, title: "Transfer lock and domain status", weight: 10 };
  if (!rdap?.ok) return { ...base, status: rdap?.unsupported ? "info" : "unknown", ...(rdap?.unsupported ? { weight: 0 } : {}), summary: "We couldn't read the domain's status codes from the registry.", detail: rdap?.error || "RDAP unavailable", fix: null };
  const statuses = (Array.isArray(rdap.data?.status) ? rdap.data.status : []).map((s) => String(s).toLowerCase().trim());
  if (!statuses.length) return { ...base, status: "unknown", summary: "The registry didn't list any status codes for this domain.", detail: "No status in RDAP.", fix: null };
  const detail = statuses.map((s) => `${s}: ${STATUS_TEXT[s] || "see icann.org/epp"}`).join("; ");
  const data = { statuses };
  if (statuses.includes("redemption period")) return { ...base, status: "fail", summary: "The domain has expired and been deleted by the registrar. It can only be restored for a fee, for a short time.", detail, data: { ...data, code: "redemption" }, fix: "Contact the registrar today to restore (redeem) the domain." };
  if (statuses.includes("pending delete")) return { ...base, status: "fail", summary: "The domain is about to be deleted and released for anyone to register.", detail, data: { ...data, code: "pending-delete" }, fix: "Contact the registrar immediately; it may be too late to restore it." };
  if (statuses.includes("client hold") || statuses.includes("server hold")) return { ...base, status: "fail", summary: "The domain is on hold, so the website and email don't work.", detail, data: { ...data, code: "on-hold" }, fix: "Ask the registrar why the domain is on hold (often unpaid renewal or unverified contact details) and get it released." };
  if (statuses.some((s) => /(client|server) transfer prohibited/.test(s))) return { ...base, status: "pass", summary: "The domain is locked against unauthorized transfers.", detail, data, fix: null };
  return { ...base, status: "warn", summary: "The domain isn't locked against transfers, which makes it easier to hijack.", detail, data: { ...data, code: "no-transfer-lock" }, fix: "Turn on the registrar's transfer lock (sometimes called domain lock)." };
}

/* ------------------------------------------------------------------ */
/* 3. DNSSEC (RFC 4033)                                                */
/* ------------------------------------------------------------------ */

/** Unsigned is info (fair for small offices); signed at the registry but no DNSKEY served is a fail. */
export function checkDnssec(rdap, dnskey) {
  const base = { id: "dnssec", category: CAT_DNS, title: "DNSSEC", weight: 0 };
  const signed = rdap?.ok ? rdap.data?.secureDNS?.delegationSigned : undefined;
  if (signed !== true) {
    return {
      ...base,
      status: "info",
      summary: signed === false ? "DNSSEC isn't turned on. That's common for small offices; it adds protection against forged DNS answers if the DNS host supports it." : "The registry didn't say whether DNSSEC is on.",
      detail: signed === false ? "RDAP secureDNS.delegationSigned = false" : "No secureDNS data in RDAP.",
      data: { code: signed === false ? "unsigned" : "unknown" },
      fix: null,
    };
  }
  if (!dnskey || !dnskey.ok) return { ...base, status: "unknown", summary: "DNSSEC is on at the registry, but we couldn't ask the nameservers for the signing keys.", detail: dnskey?.error || "No nameserver answered.", fix: null };
  if (dnskey.count > 0) return { ...base, status: "pass", summary: "DNSSEC is on: the registry publishes the domain's key fingerprint and the nameservers serve the keys.", detail: `${dnskey.count} DNSKEY record(s) from ${dnskey.ns}`, fix: null };
  return {
    ...base,
    status: "fail",
    summary: "DNSSEC is switched on at the registry, but the DNS host isn't serving the signing keys. Validating resolvers may refuse to look the domain up at all.",
    detail: `RDAP delegationSigned = true, but ${dnskey.ns} returned no DNSKEY records.`,
    data: { code: "broken" },
    fix: "Either turn DNSSEC on at the DNS host and publish its DS record at the registrar, or remove the DS record at the registrar.",
  };
}

/* ------------------------------------------------------------------ */
/* 4. Nameservers and lame delegation (RFC 1034 §4.1, RFC 2182, RFC 1912 §2.8, RFC 8499) */
/* ------------------------------------------------------------------ */

/**
 * Look up the NS set, resolve each nameserver, and ask each one (first public IP, at most 6 NS)
 * for the domain's SOA with recursion off. Private/loopback addresses are never queried.
 */
export async function probeNameservers(domain, { resolver, querySoa }) {
  let names;
  try {
    names = (await withTimeout(resolver.resolveNs(domain), 5000, `NS ${domain}`)).map((n) => n.toLowerCase().replace(/\.$/, ""));
  } catch (err) {
    if (isNotFound(err)) return { ok: true, names: [], servers: [] };
    return { ok: false, error: err.code || err.message };
  }
  const servers = await Promise.all(
    names.slice(0, MAX_NS).map(async (ns) => {
      const r = await resolveHost(ns, resolver);
      const publicIps = r.addresses.filter((ip) => !isNonPublicAddress(ip));
      const entry = { ns, resolved: r.ok, lookupError: r.ok ? null : r.notFound ? "NXDOMAIN" : r.error, addresses: r.addresses, privateOnly: r.ok && publicIps.length === 0 };
      if (!publicIps.length) return entry;
      const ip = publicIps.find((a) => !a.includes(":")) || publicIps[0];
      const soa = await querySoa(ip, domain);
      const answer = soa.ok ? soa.answers.find((a) => a.type === 6) : null;
      return { ...entry, ip, answered: soa.ok, authoritative: Boolean(soa.ok && soa.aa && soa.rcode === 0 && answer), rcode: soa.ok ? soa.rcode : null, queryError: soa.ok ? null : soa.error, soa: answer ? answer.data : null };
    }),
  );
  return { ok: true, names, servers };
}

export function checkNameservers(probe) {
  const base = { id: "nameservers", category: CAT_DNS, title: "Nameservers", weight: 15 };
  if (!probe?.ok) return { ...base, status: "unknown", summary: "We couldn't look up the domain's nameservers right now.", detail: probe?.error || "lookup failed", fix: null };
  const { names, servers } = probe;
  const list = servers.map((s) => `${s.ns}${s.ip ? ` (${s.ip})` : ""}: ${!s.resolved ? `doesn't resolve (${s.lookupError})` : s.privateOnly ? "private address only (not queried)" : !s.answered ? `no answer (${s.queryError})` : s.authoritative ? "authoritative" : `not authoritative (rcode ${s.rcode})`}`);
  const detail = `${names.length} nameserver(s)${names.length > MAX_NS ? `, first ${MAX_NS} checked` : ""}. ${list.join("; ")}`;
  if (names.length < 2) {
    return { ...base, status: "fail", summary: names.length ? "The domain has only one nameserver. If it goes down, the website and email go with it." : "The domain has no nameservers, so nothing on it works.", detail, data: { code: "too-few" }, fix: "Use at least two nameservers (DNS hosts provide them in pairs or sets)." };
  }
  const unresolved = servers.filter((s) => !s.resolved || s.privateOnly);
  if (unresolved.length) {
    return { ...base, status: "fail", summary: `${unresolved.map((s) => s.ns).join(", ")} ${unresolved.length === 1 ? "doesn't" : "don't"} resolve to a public address, so lookups that pick ${unresolved.length === 1 ? "it" : "them"} fail.`, detail, data: { code: "ns-unresolvable", nameservers: unresolved.map((s) => s.ns) }, fix: "Remove or correct the broken nameserver at the registrar." };
  }
  const lame = servers.filter((s) => !s.authoritative);
  if (lame.length) {
    return { ...base, status: "warn", summary: `${lame.map((s) => s.ns).join(", ")} ${lame.length === 1 ? "isn't" : "aren't"} answering for this domain (lame delegation). Lookups that land there fail or slow down.`, detail, data: { code: "lame", nameservers: lame.map((s) => s.ns) }, fix: "Either add the domain to that DNS server or remove it from the nameserver list at the registrar." };
  }
  // Same /24 or same provider is common (anycast) and only noted.
  const notes = [];
  const v4 = servers.map((s) => s.ip).filter((ip) => ip && !ip.includes(":"));
  if (v4.length >= 2 && new Set(v4.map((ip) => ip.split(".").slice(0, 3).join("."))).size === 1) notes.push("all nameservers are in one /24 network");
  const providers = new Set(names.map((n) => n.split(".").slice(-2).join(".")));
  if (providers.size === 1) notes.push(`all nameservers are run by ${[...providers][0]} (normal; most providers use anycast)`);
  return { ...base, status: "pass", summary: `${names.length} nameservers, all answering for the domain.`, detail: notes.length ? `${detail}. Note: ${notes.join("; ")}.` : detail, data: { notes }, fix: null };
}

/* ------------------------------------------------------------------ */
/* 5. SOA (RFC 1912 §2.2, RFC 2308)                                    */
/* ------------------------------------------------------------------ */

const SOA_GUIDE = { refresh: [1200, 43200], expire: [1209600, 2419200], minimum: [300, 86400] };

export function checkSoa(soaLookup, probe) {
  const base = { id: "soa", category: CAT_DNS, title: "SOA record", weight: 5 };
  if (!soaLookup?.ok) {
    if (soaLookup?.notFound) return { ...base, status: "warn", summary: "The domain has no SOA record, which every DNS zone should have.", detail: soaLookup.error || "no SOA", data: { code: "missing" }, fix: "Ask the DNS host to check the zone; the SOA record is created automatically by DNS hosts." };
    return { ...base, status: "unknown", summary: "We couldn't look up the SOA record right now.", detail: soaLookup?.error || "lookup failed", fix: null };
  }
  const soa = soaLookup.soa;
  const serials = (probe?.servers || []).filter((s) => s.soa).map((s) => ({ ns: s.ns, serial: s.soa.serial }));
  const detail = `Primary ${soa.nsname}, serial ${soa.serial}, refresh ${soa.refresh}, retry ${soa.retry}, expire ${soa.expire}, minimum ${soa.minttl}${serials.length ? `. Serials by nameserver: ${serials.map((s) => `${s.ns} ${s.serial}`).join(", ")}` : ""}`;
  if (new Set(serials.map((s) => s.serial)).size > 1) {
    return { ...base, status: "warn", summary: "The nameservers hand out different versions of the zone (SOA serials differ), so visitors may see old records.", detail, data: { code: "serial-mismatch", serials }, fix: "Ask the DNS host to check zone transfers between its nameservers, or remove an old nameserver." };
  }
  const notes = [];
  if (soa.refresh < SOA_GUIDE.refresh[0] || soa.refresh > SOA_GUIDE.refresh[1]) notes.push(`refresh ${soa.refresh}s (common guidance 1200–43200)`);
  if (soa.retry >= soa.refresh) notes.push(`retry ${soa.retry}s isn't less than refresh`);
  if (soa.expire < SOA_GUIDE.expire[0] || soa.expire > SOA_GUIDE.expire[1]) notes.push(`expire ${soa.expire}s (common guidance 2–4 weeks)`);
  if (soa.minttl < SOA_GUIDE.minimum[0] || soa.minttl > SOA_GUIDE.minimum[1]) notes.push(`minimum/negative TTL ${soa.minttl}s (common guidance 300–86400)`);
  if (notes.length) {
    // Providers set these themselves and vary widely, so outside the usual range is information only.
    return { ...base, status: "info", summary: "The SOA record is fine, but some timers are outside the usual guidance. DNS hosts set these, so this is information only.", detail: `${detail}. ${notes.join("; ")}.`, data: { code: "timers", notes }, fix: null };
  }
  return { ...base, status: "pass", summary: "The SOA record is present and consistent across the nameservers.", detail, fix: null };
}

/* ------------------------------------------------------------------ */
/* 6. CAA (RFC 8659)                                                   */
/* ------------------------------------------------------------------ */

export function checkCaa(caaLookup) {
  const base = { id: "caa", category: CAT_DNS, title: "CAA (which certificate authorities may issue)", weight: 3 };
  if (!caaLookup?.ok && caaLookup?.notFound) return { ...base, status: "info", summary: "No CAA record. Any certificate authority may issue certificates for this domain. Optional: a CAA record limits that to the ones you use.", detail: "No CAA records.", data: { code: "none" }, fix: null };
  if (!caaLookup?.ok) return { ...base, status: "unknown", summary: "We couldn't look up CAA records right now.", detail: caaLookup?.error || "lookup failed", fix: null };
  const issuers = caaLookup.records.flatMap((r) => [r.issue, r.issuewild].filter((v) => v !== undefined));
  return { ...base, status: "pass", summary: `Only the listed certificate authorities may issue certificates${issuers.length ? `: ${[...new Set(issuers.map((i) => i || "(none)"))].join(", ")}` : ""}.`, detail: caaLookup.records.map((r) => JSON.stringify(r)).join("; "), data: { issuers }, fix: null };
}

/* ------------------------------------------------------------------ */
/* 7. MX (RFC 5321 §5, RFC 7505)                                       */
/* ------------------------------------------------------------------ */

export async function lookupMx(domain, { resolver }) {
  let mx;
  try {
    mx = await withTimeout(resolver.resolveMx(domain), 5000, `MX ${domain}`);
  } catch (err) {
    if (!isNotFound(err)) return { ok: false, error: err.code || err.message };
    mx = [];
  }
  mx = mx.sort((a, b) => a.priority - b.priority);
  const nullMx = mx.length === 1 && (mx[0].exchange === "" || mx[0].exchange === ".");
  if (!mx.length) {
    const apex = await resolveHost(domain, resolver);
    return { ok: true, records: [], nullMx: false, apexHasAddress: apex.ok };
  }
  if (nullMx) return { ok: true, records: mx, nullMx: true, hosts: [] };
  const hosts = await Promise.all(
    mx.slice(0, MAX_MX).map(async (r) => {
      const host = r.exchange.toLowerCase().replace(/\.$/, "");
      const res = await resolveHost(host, resolver);
      return { host, priority: r.priority, resolved: res.ok, addresses: res.addresses, private: res.addresses.filter((a) => isNonPublicAddress(a)), error: res.ok ? null : res.notFound ? "NXDOMAIN" : res.error };
    }),
  );
  return { ok: true, records: mx, nullMx: false, hosts };
}

export function checkMx(mx) {
  const base = { id: "mx", category: CAT_MAIL, title: "Mail servers (MX)", weight: 10 };
  if (!mx?.ok) return { ...base, status: "unknown", summary: "We couldn't look up the mail servers right now.", detail: mx?.error || "lookup failed", fix: null };
  if (mx.nullMx) return { ...base, status: "info", summary: "This domain doesn't receive email (it publishes a \"null MX\" record).", detail: "MX 0 .", data: { code: "null-mx" }, fix: null };
  if (!mx.records.length) return { ...base, status: "info", summary: mx.apexHasAddress ? "No MX record. Mail servers may try the website's address instead; if the domain should receive email, add MX records." : "No MX record and no address: this domain doesn't receive email.", detail: "No MX records.", data: { code: "no-mx" }, fix: null };
  const detail = mx.hosts.map((h) => `${h.priority} ${h.host}: ${h.resolved ? h.addresses.join(", ") : `doesn't resolve (${h.error})`}`).join("; ");
  const broken = mx.hosts.filter((h) => !h.resolved);
  if (broken.length) return { ...base, status: "fail", summary: `Mail server ${broken.map((h) => h.host).join(", ")} doesn't exist, so some incoming email can't be delivered.`, detail, data: { code: "mx-unresolvable", hosts: broken.map((h) => h.host) }, fix: "Correct or remove the broken MX record at the DNS host." };
  const priv = mx.hosts.filter((h) => h.private.length);
  if (priv.length) return { ...base, status: "fail", summary: `Mail server ${priv.map((h) => h.host).join(", ")} points at a private network address, which the internet can't reach.`, detail, data: { code: "mx-private", hosts: priv.map((h) => h.host) }, fix: "Point the MX record at the mail service's public server name." };
  return { ...base, status: "pass", summary: `${mx.hosts.length} mail server${mx.hosts.length === 1 ? "" : "s"}, all with public addresses.`, detail, fix: null };
}

/* ------------------------------------------------------------------ */
/* 8. Email authentication summary (presence only)                     */
/* ------------------------------------------------------------------ */

export async function lookupEmailAuth(domain, { resolver }) {
  try {
    const [spf, dmarc] = await Promise.all([txtRecords(resolver, domain), txtRecords(resolver, `_dmarc.${domain}`)]);
    return { ok: true, spf: spf.some((t) => /^v=spf1(\s|$)/i.test(t.trim())), dmarc: dmarc.some((t) => /^v=DMARC1(\s*;|$)/i.test(t.trim())) };
  } catch (err) {
    return { ok: false, error: err.code || err.message };
  }
}

export function checkEmailAuth(domain, auth) {
  const base = { id: "email-auth", category: CAT_MAIL, title: "Email authentication (SPF and DMARC)", weight: 10 };
  const link = { href: `/tools/email?d=${encodeURIComponent(domain)}`, text: "Run the full Email Security Check" };
  if (!auth?.ok) return { ...base, status: "unknown", summary: "We couldn't look up SPF and DMARC right now.", detail: auth?.error || "lookup failed", data: { link }, fix: null };
  const detail = `SPF: ${auth.spf ? "present" : "missing"}; DMARC: ${auth.dmarc ? "present" : "missing"}. Presence only; the Email Security Check grades the content.`;
  if (auth.spf && auth.dmarc) return { ...base, status: "pass", summary: "SPF and DMARC records are published.", detail, data: { link }, fix: null };
  const code = !auth.spf && !auth.dmarc ? "missing-both" : !auth.spf ? "missing-spf" : "missing-dmarc";
  const missing = { "missing-both": "SPF and DMARC are", "missing-spf": "SPF is", "missing-dmarc": "DMARC is" }[code];
  return { ...base, status: "warn", summary: `${missing} missing, so it's easier for someone to send email that looks like it came from this domain.`, detail, data: { code, link }, fix: "Publish SPF and DMARC records. The Email Security Check shows the exact records to add." };
}

/* ------------------------------------------------------------------ */
/* 9. Dangling CNAME / subdomain takeover hints                        */
/* ------------------------------------------------------------------ */

// Services where a CNAME to a deleted resource can be claimed by someone else. From the
// can-i-take-over-xyz project (github.com/EdOverflow/can-i-take-over-xyz). Azure and AWS Elastic
// Beanstalk are fingerprinted there by NXDOMAIN, which DNS alone can see. GitHub Pages, Heroku,
// Netlify and S3 are fingerprinted by an HTTP response we don't fetch, so for those an NXDOMAIN
// target is a best-effort hint. WP Engine is listed "Not vulnerable" there and is left out.
export const TAKEOVER_PATTERNS = [
  "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azure-api.net", "azureedge.net", "azurecontainer.io",
  "elasticbeanstalk.com", "s3.amazonaws.com", "herokuapp.com", "github.io", "netlify.app",
];
export const CNAME_NAMES = ["", "www", "mail", "shop", "blog"];
const matchesTakeover = (target) => TAKEOVER_PATTERNS.find((p) => target === p || target.endsWith(`.${p}`)) || null;

export async function lookupCnames(domain, { resolver }) {
  const out = [];
  for (const label of CNAME_NAMES) {
    const name = label ? `${label}.${domain}` : domain;
    let targets;
    try {
      targets = await withTimeout(resolver.resolveCname(name), 5000, `CNAME ${name}`);
    } catch {
      continue; // no CNAME (or no such name): nothing to check
    }
    for (const raw of targets.slice(0, 2)) {
      const target = raw.toLowerCase().replace(/\.$/, "");
      const r = await resolveHost(target, resolver);
      out.push({ name, target, pattern: matchesTakeover(target), nxdomain: r.notFound, resolved: r.ok });
    }
  }
  return { ok: true, cnames: out };
}

export function checkDanglingCname(lookup) {
  const base = { id: "dangling-cname", category: CAT_DNS, title: "Dangling CNAME records (subdomain takeover)", weight: 10 };
  if (!lookup?.ok) return { ...base, status: "unknown", summary: "We couldn't check the CNAME records right now.", detail: lookup?.error || "lookup failed", fix: null };
  const checked = `Checked: ${CNAME_NAMES.map((l) => l || "(apex)").join(", ")}.`;
  if (!lookup.cnames.length) return { ...base, status: "pass", summary: "None of the common names point elsewhere with a CNAME, so there's nothing left dangling.", detail: checked, fix: null };
  const detail = `${lookup.cnames.map((c) => `${c.name} → ${c.target}${c.nxdomain ? " (target doesn't exist)" : ""}`).join("; ")}. ${checked}`;
  const takeover = lookup.cnames.filter((c) => c.pattern && c.nxdomain);
  if (takeover.length) {
    return { ...base, status: "fail", summary: `${takeover.map((c) => c.name).join(", ")} point${takeover.length === 1 ? "s" : ""} at a resource on ${takeover[0].pattern} that no longer exists. Someone else could create it and take over the name (possible takeover).`, detail, data: { code: "possible-takeover", names: takeover.map((c) => c.name) }, fix: "Delete the CNAME record (or recreate the resource it points to) at the DNS host today." };
  }
  const dangling = lookup.cnames.filter((c) => c.nxdomain);
  if (dangling.length) {
    return { ...base, status: "warn", summary: `${dangling.map((c) => c.name).join(", ")} point${dangling.length === 1 ? "s" : ""} at a name that doesn't exist. Not a known takeover service, but the record is broken.`, detail, data: { code: "dangling", names: dangling.map((c) => c.name) }, fix: "Delete or correct the CNAME record at the DNS host." };
  }
  return { ...base, status: "pass", summary: "Every CNAME found points at a name that exists.", detail, fix: null };
}
