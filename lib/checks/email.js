import { mxRecords, txtRecords, withTimeout } from "../net.js";
import { countSpfLookups, validateSpfSyntax, describeLookupCount, isSpfRecord, SPF_LOOKUP_LIMIT, SPF_VOID_LIMIT } from "./spf.js";

export { countSpfLookups, validateSpfSyntax, describeLookupCount, splitTxt, parseTerm, spfTerms } from "./spf.js";

/* ------------------------------------------------------------------ */
/* Email platform (from MX records)                                    */
/* ------------------------------------------------------------------ */

const PROVIDERS = [
  { key: "google", name: "Google Workspace", match: /(^|\.)(aspmx\.l\.google\.com|googlemail\.com|smtp\.google\.com|google\.com)$/ },
  { key: "microsoft", name: "Microsoft 365", match: /\.mail\.protection\.outlook\.com$|\.mx\.microsoft$/ },
  { key: "zoho", name: "Zoho Mail", match: /(^|\.)zoho(mail)?\.(com|eu|in)$/ },
  { key: "godaddy", name: "GoDaddy email", match: /(^|\.)secureserver\.net$/ },
  { key: "proofpoint", name: "Proofpoint (email filter)", match: /pphosted\.com$|ppe-hosted\.com$/ },
  { key: "mimecast", name: "Mimecast (email filter)", match: /mimecast\.com$/ },
  { key: "barracuda", name: "Barracuda (email filter)", match: /barracudanetworks\.com$/ },
  { key: "cisco", name: "Cisco Secure Email (email filter)", match: /iphmx\.com$/ },
  { key: "cloudflare", name: "Cloudflare Email Security (email filter)", match: /cf-emailsecurity\.net$/ },
  { key: "fastmail", name: "Fastmail", match: /messagingengine\.com$/ },
  { key: "yahoo", name: "Yahoo Small Business", match: /yahoodns\.net$/ },
  { key: "ionos", name: "IONOS email", match: /(ionos|1and1|kundenserver)\./ },
];

/** RFC 7505 "null MX": a single MX of "." means the domain never receives email. */
export function isNullMx(mx) {
  return mx.length === 1 && ["", "."].includes(String(mx[0].exchange).trim());
}

export function identifyProvider(mx) {
  if (isNullMx(mx)) return { key: "nullmx", name: "No email (declared)" };
  for (const rec of mx) {
    const host = rec.exchange.toLowerCase().replace(/\.$/, "");
    const p = PROVIDERS.find((prov) => prov.match.test(host));
    if (p) return { key: p.key, name: p.name };
  }
  return mx.length ? { key: "other", name: "Other email provider" } : { key: "none", name: "No email" };
}

export async function checkEmailPlatform(domain, { resolver }) {
  const mx = await mxRecords(resolver, domain);
  const provider = identifyProvider(mx);
  const hosts = mx.map((r) => `${r.priority} ${r.exchange}`).join(", ");
  const base = { id: "email-platform", category: "Email platform", title: "Email platform", weight: 0 };

  if (provider.key === "none") {
    return {
      ...base,
      status: "warn",
      weight: 5,
      summary: "We couldn't find any mail servers for this domain, so email sent to it may bounce.",
      detail: "No MX records found.",
      fix: "Confirm which address the business actually uses for email and set up proper mail routing.",
      provider,
      data: { code: "no-mx", mx: [] },
    };
  }
  if (provider.key === "nullmx") {
    return {
      ...base,
      status: "info",
      summary: "This domain is deliberately set up to never send or receive email.",
      detail: "Null MX record (RFC 7505).",
      fix: null,
      provider,
      data: { code: "null-mx", mx: [] },
    };
  }
  const isFilter = ["proofpoint", "mimecast", "barracuda", "cisco", "cloudflare"].includes(provider.key);
  return {
    ...base,
    status: "info",
    summary: isFilter
      ? `Incoming mail passes through ${provider.name} before reaching the mailbox. The mailbox platform behind it isn't visible publicly.`
      : provider.key === "other"
        ? "Email runs on something other than Google Workspace or Microsoft 365, such as a web host, another provider or the company's own servers."
        : `This business uses ${provider.name} for email.`,
    detail: `MX: ${hosts}`,
    fix:
      provider.key === "godaddy" || provider.key === "ionos"
        ? "Bundled hosting email often lacks modern security and admin controls. A move to Google Workspace or Microsoft 365 is worth discussing."
        : provider.key === "other"
          ? "Confirm who manages the email server and that it's kept patched and backed up."
          : null,
    provider,
    data: {
      code: provider.key === "godaddy" || provider.key === "ionos" ? "hosting-email" : provider.key === "other" ? "other-email" : "ok",
      mx: mx.map((r) => r.exchange),
    },
  };
}

/* ------------------------------------------------------------------ */
/* SPF                                                                 */
/* ------------------------------------------------------------------ */

const LOOKUP_MECHANISMS = /^[+\-~?]?(include:|a(:|\/|$)|mx(:|\/|$)|ptr(:|$)|exists:)/i;

export function parseSpf(record) {
  const terms = record.trim().split(/\s+/).slice(1);
  const all = terms.find((t) => /^[+\-~?]?all$/i.test(t)) || null;
  const includes = terms.filter((t) => /^[+\-~?]?include:/i.test(t)).map((t) => t.replace(/^[+\-~?]?include:/i, "").toLowerCase());
  const redirect = (terms.find((t) => /^redirect=/i.test(t)) || "").replace(/^redirect=/i, "").toLowerCase() || null;
  const directLookups = terms.filter((t) => LOOKUP_MECHANISMS.test(t)).length + (redirect ? 1 : 0);
  return { all, allQualifier: all ? (/^[+\-~?]/.test(all) ? all[0] : "+") : null, includes, redirect, directLookups };
}

/** Live DNS sanity check: Google's SPF record always exists, so if it can't be read, live DNS is unreachable. */
export async function dnsReachable(resolver) {
  try {
    const txt = await withTimeout(resolver.resolveTxt("_spf.google.com"), 5000, "DNS reachability");
    return txt.some((c) => /^v=spf1/i.test(c.join("")));
  } catch {
    return false;
  }
}

/**
 * Includes (and a redirect) in an SPF record that point at a name with no SPF record. Receivers treat
 * that as a permanent error, which breaks SPF for the whole domain (RFC 7208 section 5.2).
 */
export async function deadSpfIncludes(resolver, record) {
  const parsed = parseSpf(record);
  const targets = [...parsed.includes, ...(parsed.redirect ? [parsed.redirect] : [])].filter((t) => !t.includes("%{"));
  const dead = [];
  for (const t of targets) {
    let txt = [];
    try {
      txt = await txtRecords(resolver, t);
    } catch {
      continue; // a lookup error isn't proof the include is gone
    }
    if (!txt.some((v) => /^v=spf1(\s|$)/i.test(v))) dead.push(t);
  }
  return dead;
}

// Any of these appearing anywhere in the SPF include tree means the platform is authorised.
const PROVIDER_SPF = {
  google: { match: /(^|\.)(_spf|_netblocks\d*)\.google\.com$/, name: "Google Workspace" },
  microsoft: { match: /(^|\.)spf\.protection\.outlook\.com$/, name: "Microsoft 365" },
  zoho: { match: /zoho/, name: "Zoho" },
};

export async function checkSpf(domain, { resolver }, provider) {
  const base = { id: "spf", category: "Email security", title: "SPF (approved senders list)", weight: 20 };
  const records = (await txtRecords(resolver, domain)).filter(isSpfRecord);

  if (records.length === 0) {
    return {
      ...base,
      status: "fail",
      summary: "There's no list of servers allowed to send email for this domain, so anyone can send email that claims to be from it, and real messages are more likely to land in spam.",
      detail: "No SPF (v=spf1) TXT record found.",
      data: { codes: ["missing"], records: [] },
      fix: "Publish an SPF record listing the business's email platform and any other services that send on its behalf (invoicing, newsletters, website forms).",
    };
  }
  if (records.length > 1) {
    return {
      ...base,
      status: "fail",
      summary: "The domain has more than one SPF record. Mail servers treat that as an error, so the protection is effectively switched off.",
      detail: records.join("  |  "),
      data: { codes: ["multiple"], records },
      fix: "Merge the records into a single SPF record.",
    };
  }

  const record = records[0];
  const parsed = parseSpf(record);
  let walk = null;
  try {
    walk = await withTimeout(countSpfLookups(resolver, record, { domain }), 8000, "SPF lookup count");
  } catch {
    /* timed out: the count stays unknown */
  }
  const issues = [];
  const codes = [];
  let status = "pass";
  const worsen = (s) => {
    if (s === "fail" || (s === "warn" && status === "pass")) status = s;
  };

  if (parsed.allQualifier === "+") {
    worsen("fail");
    codes.push("permissive");
    issues.push(`The record ends in "${parsed.all}", which tells mail servers to accept email from anywhere, so it gives no protection.`);
  } else if (parsed.allQualifier === "?") {
    worsen("warn");
    codes.push("neutral-all");
    issues.push(`The record ends in "${parsed.all}" (neutral), which tells mail servers nothing about unapproved senders.`);
  } else if (!parsed.all && !parsed.redirect) {
    worsen("warn");
    codes.push("no-all");
    issues.push("The record doesn't end with an \"all\" rule, so it doesn't say what to do with unapproved senders.");
  }
  for (const issue of validateSpfSyntax(record)) {
    worsen(issue.severity === "permerror" ? "fail" : "warn");
    codes.push(issue.code);
    issues.push(issue.message);
  }

  const lookupText = walk ? describeLookupCount(walk) : null;
  if (walk && (walk.exceeded || walk.count > SPF_LOOKUP_LIMIT)) {
    worsen("fail");
    codes.push("too-many-lookups");
    issues.push(`It needs ${lookupText} DNS lookups, over the limit of 10. Many mail servers will treat the record as broken.`);
  }
  if (walk && walk.voids > SPF_VOID_LIMIT) {
    worsen("fail");
    codes.push("too-many-void-lookups");
    issues.push(`${walk.voids} of its lookups return nothing (limit 2), which receivers may treat as a permanent error.`);
  }
  for (const e of walk?.errors || []) {
    // Dead include targets are reported (and block any proposed record in the safety check), but the
    // scan grade keeps its earlier behaviour for them.
    if (e.code === "loop" || e.code === "mx-too-many") {
      worsen("fail");
      codes.push(e.code === "loop" ? "include-loop" : "mx-too-many");
      issues.push(e.message);
    }
  }
  const expected = PROVIDER_SPF[provider?.key];
  const names = [...parsed.includes, ...(parsed.redirect ? [parsed.redirect] : []), ...(walk?.names || [])];
  // Only judge this when the include tree was fully walked; otherwise we might just not have seen it.
  if (expected && walk?.complete && !walk.exceeded && !names.some((n) => expected.match.test(n))) {
    worsen("warn");
    codes.push("missing-provider");
    issues.push(`It doesn't appear to include ${expected.name}, the email platform this business uses.`);
  }

  return {
    ...base,
    status,
    summary:
      status === "pass"
        ? "An approved-senders list is in place and looks healthy."
        : `An approved-senders list exists but has problems: ${issues.join(" ")}`,
    detail: `${record}${lookupText ? `  (${lookupText} DNS lookups${walk.complete ? "" : "; some couldn't be resolved"}, ${walk.voids} void)` : ""}`,
    data: {
      codes,
      records: [record],
      // Exact count only when every lookup was resolved; otherwise null and lookupsAtLeast is set.
      lookups: walk && walk.complete && !walk.exceeded ? walk.count : null,
      lookupsAtLeast: walk && (!walk.complete || walk.exceeded) ? walk.count : null,
      lookupsComplete: walk ? walk.complete && !walk.exceeded : false,
      voids: walk ? walk.voids : null,
      errors: walk?.errors || [],
    },
    fix: status === "pass" ? null : "Clean up the SPF record so it covers every legitimate sender, stays under 10 lookups and ends in ~all or -all.",
  };
}

/* ------------------------------------------------------------------ */
/* DMARC                                                               */
/* ------------------------------------------------------------------ */

export function parseDmarc(record) {
  const tags = {};
  for (const part of record.split(";")) {
    const [k, ...rest] = part.split("=");
    if (!k || !rest.length) continue;
    tags[k.trim().toLowerCase()] = rest.join("=").trim();
  }
  return tags;
}

const DMARC_POLICIES = new Set(["none", "quarantine", "reject"]);
const MAILTO = /^mailto:([^@\s,!]+)@([a-z0-9.-]+\.[a-z]{2,63})(![0-9]+[kmgt]?)?$/i;

/** Parse a rua/ruf value: comma-separated mailto: URIs, each with an optional !size suffix. */
export function parseReportUris(value) {
  return String(value || "")
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean)
    .map((uri) => {
      const m = uri.match(MAILTO);
      return m ? { uri, valid: true, address: `${m[1]}@${m[2].toLowerCase()}`, domain: m[2].toLowerCase().replace(/\.$/, ""), size: m[3] || null } : { uri, valid: false };
    });
}

/**
 * Validate a DMARC record against RFC 7489 §6.3–6.4. errors make the record invalid (receivers
 * ignore it); warnings are tags receivers will ignore or fall back on.
 */
export function validateDmarc(record) {
  const tags = parseDmarc(record);
  const errors = [];
  const warnings = [];
  if (!/^v=DMARC1\s*(;|$)/.test(String(record).trim())) {
    errors.push({ code: "bad-version", message: 'The record must start with exactly "v=DMARC1" (RFC 7489 §6.4).' });
  }
  const policy = (tags.p || "").toLowerCase();
  if (!tags.p) errors.push({ code: "missing-policy", message: "The required p= tag (the policy) is missing." });
  else if (!DMARC_POLICIES.has(policy)) errors.push({ code: "invalid-policy", message: `p=${tags.p} isn't a valid policy (none, quarantine or reject).` });
  if (tags.sp !== undefined && !DMARC_POLICIES.has(tags.sp.toLowerCase())) warnings.push({ code: "invalid-sp", message: `sp=${tags.sp} isn't a valid subdomain policy (none, quarantine or reject).` });
  for (const k of ["adkim", "aspf"]) {
    if (tags[k] !== undefined && !["r", "s"].includes(tags[k].toLowerCase())) warnings.push({ code: `invalid-${k}`, message: `${k}=${tags[k]} must be r (relaxed) or s (strict).` });
  }
  let pct = 100;
  if (tags.pct !== undefined) {
    if (/^\d{1,3}$/.test(tags.pct) && Number(tags.pct) <= 100) pct = Number(tags.pct);
    else warnings.push({ code: "invalid-pct", message: `pct=${tags.pct} isn't a whole number from 0 to 100, so receivers apply the policy to all mail (RFC 7489 §6.6.3).` });
  }
  const uris = {};
  for (const k of ["rua", "ruf"]) {
    uris[k] = parseReportUris(tags[k]);
    const bad = uris[k].filter((u) => !u.valid);
    if (bad.length) warnings.push({ code: `invalid-${k}`, message: `${k}= must be a comma-separated list of mailto: addresses; ${bad.map((u) => `"${u.uri}"`).join(", ")} ${bad.length > 1 ? "aren't" : "isn't"}, so those reports go nowhere.` });
  }
  return { tags, policy: DMARC_POLICIES.has(policy) ? policy : null, pct, uris, errors, warnings };
}

/** Rough organizational-domain match without the public suffix list: same name, or one is a subdomain of the other. */
export function sameOrgDomain(a, b) {
  const x = String(a).toLowerCase().replace(/\.$/, "");
  const y = String(b).toLowerCase().replace(/\.$/, "");
  return x === y || x.endsWith(`.${y}`) || y.endsWith(`.${x}`);
}

/**
 * RFC 7489 §7.1: a report destination outside the domain must publish
 * <domain>._report._dmarc.<destination> with "v=DMARC1", or receivers won't send it reports.
 * Returns true, false, or null when the lookup failed.
 */
export async function reportDestinationAuthorized(resolver, domain, destDomain) {
  if (sameOrgDomain(domain, destDomain)) return true;
  try {
    const txt = await txtRecords(resolver, `${domain}._report._dmarc.${destDomain}`);
    return txt.some((t) => /^v=DMARC1\s*(;|$)/i.test(t.trim()));
  } catch {
    return null;
  }
}

export async function checkDmarc(domain, { resolver }) {
  const base = { id: "dmarc", category: "Email security", title: "DMARC (anti-impersonation policy)", weight: 25 };
  const records = (await txtRecords(resolver, `_dmarc.${domain}`)).filter((t) => /^v=DMARC1/i.test(t.trim()));

  if (records.length === 0) {
    return {
      ...base,
      status: "fail",
      summary:
        "There's no policy telling mail servers what to do with email that fakes this domain. Scammers can impersonate the business (fake invoices, payment-change requests), and Gmail, Yahoo and Microsoft increasingly filter or reject mail from domains without one.",
      detail: `No DMARC record at _dmarc.${domain}.`,
      data: { code: "missing", records: [] },
      fix: "Publish a DMARC record in monitoring mode, review the reports for a few weeks, then move to quarantine or reject.",
    };
  }
  if (records.length > 1) {
    return {
      ...base,
      status: "fail",
      summary: "There are multiple DMARC records, which makes the policy invalid.",
      detail: records.join("  |  "),
      data: { code: "multiple", records },
      fix: "Keep a single DMARC record.",
    };
  }

  const v = validateDmarc(records[0]);
  const { tags } = v;
  const policy = v.policy || (tags.p || "").toLowerCase();
  const pct = v.pct;
  const hasReports = v.uris.rua.some((u) => u.valid);

  // External report destinations must authorize this domain (RFC 7489 §7.1).
  const reportAuthorization = [];
  const warnings = [...v.warnings];
  for (const k of ["rua", "ruf"]) {
    for (const u of v.uris[k].filter((x) => x.valid && !sameOrgDomain(domain, x.domain))) {
      const authorized = await reportDestinationAuthorized(resolver, domain, u.domain);
      reportAuthorization.push({ tag: k, address: u.address, domain: u.domain, authorized });
      if (authorized === false) {
        warnings.push({
          code: "external-rua-unauthorized",
          message: `${u.address} is outside ${domain} and ${u.domain} doesn't publish ${domain}._report._dmarc.${u.domain} with "v=DMARC1", so receivers won't send it ${k === "rua" ? "aggregate" : "failure"} reports (RFC 7489 §7.1).`,
        });
      }
    }
  }

  let status;
  let summary;
  if (v.errors.length) {
    status = "fail";
    summary = `The DMARC record is invalid, so it isn't being applied: ${v.errors.map((e) => e.message).join(" ")}`;
  } else if (policy === "reject" || policy === "quarantine") {
    status = pct < 100 ? "warn" : "pass";
    summary =
      policy === "reject"
        ? "Strong protection: mail servers are told to reject email that fakes this domain."
        : "Good protection: mail servers are told to send email that fakes this domain to spam.";
    if (pct < 100) summary += ` It only applies to ${pct}% of messages, though.`;
  } else {
    status = "warn";
    summary =
      "A DMARC record exists but is set to monitor only (p=none), so fake email that claims to be from this business is still delivered. It's a good first step that usually never gets finished.";
  }
  if (status !== "fail" && warnings.length) {
    if (status === "pass") status = "warn";
    summary += ` ${warnings.map((w) => w.message).join(" ")}`;
  }
  if (!hasReports && status !== "fail") summary += " No report address is set, so nobody can see who is sending as this domain.";

  const code =
    status === "fail"
      ? "invalid"
      : policy === "none"
        ? "monitor-only"
        : pct < 100
          ? "partial"
          : warnings.length
            ? warnings[0].code
            : !hasReports
              ? "no-reports"
              : "ok";
  return {
    ...base,
    status,
    summary,
    detail: records[0],
    data: {
      code,
      codes: [...v.errors.map((e) => e.code), ...warnings.map((w) => w.code)],
      records: [records[0]],
      policy: policy || null,
      pct,
      hasReports,
      tags,
      reportAuthorization,
    },
    fix: status === "pass" && hasReports ? null : "Add reporting, check that legitimate senders pass, then move the policy to quarantine or reject.",
  };
}

/* ------------------------------------------------------------------ */
/* DKIM (best-effort: selectors are not discoverable from DNS)         */
/* ------------------------------------------------------------------ */

const SELECTORS_BY_PROVIDER = {
  google: ["google"],
  microsoft: ["selector1", "selector2"],
  zoho: ["zoho", "zmail"],
  godaddy: ["default"],
};
const COMMON_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "s1", "s2", "dkim", "mail", "smtp", "mxvault"];

// dkimSelectors / zoneAuthoritative are set when checking an uploaded zone file: every key name is
// known, so custom names are found and "not found" really means missing.
export async function checkDkim(domain, { resolver, dkimSelectors = [], zoneAuthoritative = false }, provider, { dmarcEnforced = false } = {}) {
  const base = { id: "dkim", category: "Email security", title: "DKIM (email signing)", weight: 15 };
  if (provider?.key === "nullmx" || provider?.key === "none") {
    return { ...base, status: "info", weight: 0, summary: "Not applicable: this domain doesn't handle email.", detail: "", fix: null };
  }
  const preferred = SELECTORS_BY_PROVIDER[provider?.key] || [];
  const selectors = [...new Set([...preferred, ...dkimSelectors, ...COMMON_SELECTORS])];
  const otherProviders = Object.entries(SELECTORS_BY_PROVIDER).filter(([k]) => k !== provider?.key).flatMap(([, v]) => v);

  const results = await Promise.all(
    selectors.map(async (sel) => {
      try {
        const txt = await txtRecords(resolver, `${sel}._domainkey.${domain}`);
        const rec = txt.find((t) => /(^|;)\s*(v=DKIM1|k=|p=)/i.test(t));
        return rec ? { selector: sel, record: rec } : null;
      } catch {
        return null;
      }
    }),
  );
  const found = results.filter(Boolean);
  const usable = found.filter((f) => !/(^|;)\s*p=\s*(;|$)/i.test(f.record));
  // From a zone file, a key under a custom name (not another platform's standard one) is most likely
  // the main platform's, e.g. a Google key with a custom prefix. The test email in the checklist confirms it.
  const customKey = zoneAuthoritative && usable.some((f) => dkimSelectors.includes(f.selector) && !preferred.includes(f.selector) && !otherProviders.includes(f.selector));
  const providerSigned = usable.some((f) => preferred.includes(f.selector)) || customKey;

  if (usable.length === 0 && dmarcEnforced && !zoneAuthoritative) {
    // An enforced DMARC policy only works if mail is authenticated, so signing very
    // likely exists under a custom selector name we can't guess. Don't penalise it.
    return {
      ...base,
      status: "unknown",
      summary: "We couldn't see the email signing key from outside, probably because it uses a custom name. This domain enforces DMARC, which strongly suggests email authentication is working. A one-minute check in the admin console confirms it.",
      detail: `Checked selectors: ${selectors.join(", ")}`,
      data: { code: "unverified", found: [] },
      fix: null,
    };
  }
  if (usable.length === 0) {
    return {
      ...base,
      status: "warn",
      summary:
        preferred.length > 0
          ? `We couldn't find the email signing key that ${provider.name} normally uses, so outgoing email may not be digitally signed. That hurts deliverability and makes spoofing easier.`
          : "We couldn't find an email signing (DKIM) key at the usual locations. It may use a custom name, so this needs a quick manual check.",
      detail: `Checked selectors: ${selectors.join(", ")}`,
      data: { code: "missing", found: [] },
      fix: "Turn on DKIM signing in the email platform's admin console and publish the key in DNS.",
    };
  }
  return {
    ...base,
    status: preferred.length && !providerSigned ? "warn" : "pass",
    summary:
      preferred.length && !providerSigned
        ? `Some email signing is set up, but not for ${provider.name}, the main platform.`
        : "Outgoing email is digitally signed (DKIM), which helps it reach the inbox and proves it's genuine.",
    detail: `Found selectors: ${usable.map((f) => f.selector).join(", ")}`,
    data: { code: preferred.length && !providerSigned ? "not-provider" : "ok", found: usable.map((f) => f.selector) },
    fix: preferred.length && !providerSigned ? `Enable DKIM in the ${provider.name} admin console.` : null,
  };
}
