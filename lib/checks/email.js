import { mxRecords, txtRecords, withTimeout } from "../net.js";

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

/** Count DNS lookups SPF evaluation would need (RFC 7208 caps this at 10). */
export async function countSpfLookups(resolver, record, depth = 0, seen = new Set()) {
  const parsed = parseSpf(record);
  let total = parsed.directLookups;
  if (depth >= 5) return total;
  const children = [...parsed.includes, ...(parsed.redirect ? [parsed.redirect] : [])];
  for (const child of children) {
    if (seen.has(child) || child.includes("%{")) continue;
    seen.add(child);
    let txt = [];
    try {
      txt = await txtRecords(resolver, child);
    } catch {
      continue;
    }
    const spf = txt.find((t) => /^v=spf1(\s|$)/i.test(t));
    if (spf) total += await countSpfLookups(resolver, spf, depth + 1, seen);
    if (total > 20) break;
  }
  return total;
}

// Any of these appearing anywhere in the SPF include tree means the platform is authorised.
const PROVIDER_SPF = {
  google: { match: /(^|\.)(_spf|_netblocks\d*)\.google\.com$/, name: "Google Workspace" },
  microsoft: { match: /(^|\.)spf\.protection\.outlook\.com$/, name: "Microsoft 365" },
  zoho: { match: /zoho/, name: "Zoho" },
};

export async function checkSpf(domain, { resolver }, provider) {
  const base = { id: "spf", category: "Email security", title: "SPF (approved senders list)", weight: 20 };
  const records = (await txtRecords(resolver, domain)).filter((t) => /^v=spf1(\s|$)/i.test(t));

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
  let lookups = null;
  const included = new Set();
  try {
    lookups = await withTimeout(countSpfLookups(resolver, record, 0, included), 8000, "SPF lookup count");
  } catch {
    /* lookup count is best-effort */
  }
  const issues = [];
  const codes = [];
  let status = "pass";

  if (parsed.allQualifier === "+" || parsed.allQualifier === "?") {
    status = "fail";
    codes.push("permissive");
    issues.push(`The record ends in "${parsed.all}", which tells mail servers to accept email from anywhere, so it gives no protection.`);
  } else if (!parsed.all && !parsed.redirect) {
    status = "warn";
    codes.push("no-all");
    issues.push("The record doesn't end with an \"all\" rule, so it doesn't say what to do with unapproved senders.");
  }
  if (lookups !== null && lookups > 10) {
    status = "fail";
    codes.push("too-many-lookups");
    issues.push(`It needs about ${lookups} DNS lookups, over the limit of 10. Many mail servers will treat the record as broken.`);
  }
  const expected = PROVIDER_SPF[provider?.key];
  const names = [...parsed.includes, ...(parsed.redirect ? [parsed.redirect] : []), ...included];
  // Only judge this when the include tree was fully walked; otherwise we might just not have seen it.
  if (expected && lookups !== null && !names.some((n) => expected.match.test(n))) {
    if (status === "pass") status = "warn";
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
    detail: `${record}${lookups !== null ? `  (≈${lookups} DNS lookups)` : ""}`,
    data: { codes, records: [record], lookups },
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

export async function checkDmarc(domain, { resolver }) {
  const base = { id: "dmarc", category: "Email security", title: "DMARC (anti-impersonation policy)", weight: 25 };
  const records = (await txtRecords(resolver, `_dmarc.${domain}`)).filter((t) => /^v=DMARC1/i.test(t));

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

  const tags = parseDmarc(records[0]);
  const policy = (tags.p || "").toLowerCase();
  const pct = tags.pct ? Number(tags.pct) : 100;
  const hasReports = Boolean(tags.rua);
  let status;
  let summary;

  if (policy === "reject" || policy === "quarantine") {
    status = pct < 100 ? "warn" : "pass";
    summary =
      policy === "reject"
        ? "Strong protection: mail servers are told to reject email that fakes this domain."
        : "Good protection: mail servers are told to send email that fakes this domain to spam.";
    if (pct < 100) summary += ` It only applies to ${pct}% of messages, though.`;
  } else if (policy === "none") {
    status = "warn";
    summary =
      "A DMARC record exists but is set to monitor only (p=none), so fake email that claims to be from this business is still delivered. It's a good first step that usually never gets finished.";
  } else {
    status = "fail";
    summary = "The DMARC record is missing a valid policy, so it isn't being applied.";
  }
  if (!hasReports && status !== "fail") summary += " No report address is set, so nobody can see who is sending as this domain.";

  return {
    ...base,
    status,
    summary,
    detail: records[0],
    data: {
      code: status === "fail" ? "invalid" : policy === "none" ? "monitor-only" : pct < 100 ? "partial" : !hasReports ? "no-reports" : "ok",
      records: [records[0]],
      policy: policy || null,
      pct,
      hasReports,
      tags,
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

export async function checkDkim(domain, { resolver }, provider, { dmarcEnforced = false } = {}) {
  const base = { id: "dkim", category: "Email security", title: "DKIM (email signing)", weight: 15 };
  if (provider?.key === "nullmx" || provider?.key === "none") {
    return { ...base, status: "info", weight: 0, summary: "Not applicable: this domain doesn't handle email.", detail: "", fix: null };
  }
  const preferred = SELECTORS_BY_PROVIDER[provider?.key] || [];
  const selectors = [...new Set([...preferred, ...COMMON_SELECTORS])];

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
  const providerSigned = usable.some((f) => preferred.includes(f.selector));

  if (usable.length === 0 && dmarcEnforced) {
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
