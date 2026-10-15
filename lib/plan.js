// Turns a scan report into a fix plan with two views:
//  - client: plain-English "what we'll fix and why", timeline, the fix package and ongoing options
//  - tech:   ordered checklist with exact DNS records, click paths and verification
//
// Every item traces back to a specific finding in the report, so the plan only ever
// proposes fixing what the assessment actually said was wrong.

import { BUSINESS, PACKAGES, QUOTE_ITEMS, RECURRING_OPTIONS, FOUNDING_OFFER } from "./config.js";
import { countSpfLookups, dnsReachable, deadSpfIncludes, reportDestinationAuthorized } from "./checks/email.js";
import { isSpfRecord, spfTerms, splitTxt, describeLookupCount, SPF_LOOKUP_LIMIT, SPF_VOID_LIMIT } from "./checks/spf.js";
import { withTimeout } from "./net.js";
import { scoreChecks, gradeFor } from "./scan.js";

// Each platform's documented SPF include. Google: https://support.google.com/a/answer/10685031
const PROVIDER_SPF_INCLUDE = {
  google: "include:_spf.google.com",
  microsoft: "include:spf.protection.outlook.com",
  zoho: "include:zohomail.com",
  godaddy: "include:secureserver.net",
  fastmail: "include:spf.messagingengine.com",
};

const PHASES = [
  { id: 1, name: "Secure access", when: "Day 1" },
  { id: 2, name: "Authenticate your email", when: "Day 1" },
  { id: 3, name: "Turn on impersonation protection", when: "Day 1, enforced after 2–4 weeks of monitoring" },
  { id: 4, name: "Secure your website", when: "Day 1–2" },
];

/* ------------------------------------------------------------------ */
/* Record builders                                                     */
/* ------------------------------------------------------------------ */

// Names that mean a redirect target already authorizes the platform (no extra include needed).
const PROVIDER_SPF_TARGET = {
  google: /(^|\.)(_spf|_netblocks\d*)\.google\.com$/,
  microsoft: /(^|\.)spf\.protection\.outlook\.com$/,
  zoho: /zoho/,
  godaddy: /secureserver\.net$/,
  fastmail: /messagingengine\.com$/,
};

/**
 * Build the one SPF record to publish, merge-safe:
 *  - exactly one output record; every existing mechanism is kept, in its original order
 *  - the platform include goes just before the "all" term (never in front of the client's senders)
 *  - exp= and other modifiers are kept; redirect= is kept where it still works
 *  - only ptr (RFC 7208 §5.5) and true duplicates are removed, each with a reason
 *  - an existing -all is kept; otherwise the record ends in ~all
 * Returns { value, strings, changes: [{ op: "add"|"remove"|"keep"|"convert", term, reason }], warnings }
 * or null when there are no senders to authorize (refuse to guess).
 */
export function recommendSpf(existingRecords, providerKey) {
  const records = (existingRecords || []).filter((r) => isSpfRecord(r));
  const changes = [];
  const warnings = [];
  const mechanisms = []; // { term, norm }
  const seen = new Set();
  const allQualifiers = [];
  const modifiers = new Map(); // name → { term, record }
  const redirects = []; // { target, recordHasAll }

  for (const rec of records) {
    const terms = spfTerms(rec);
    const recordHasAll = terms.some((t) => t.kind === "mechanism" && t.name === "all");
    let afterAll = false;
    for (const t of terms) {
      if (t.kind === "mechanism" && t.name === "all") {
        if (!afterAll) allQualifiers.push(t.qualifier);
        afterAll = true;
        continue;
      }
      if (t.kind === "modifier") {
        if (t.name === "redirect") {
          redirects.push({ target: t.value.toLowerCase(), recordHasAll, raw: t.raw });
          continue;
        }
        const key = t.name;
        const prev = modifiers.get(key);
        if (!prev) {
          modifiers.set(key, { term: t.raw });
          changes.push({ op: "keep", term: t.raw, reason: key === "exp" ? "Explanation modifier kept as is" : "Modifier kept as is" });
        } else if (prev.term.toLowerCase() === t.raw.toLowerCase()) {
          changes.push({ op: "remove", term: t.raw, reason: "Duplicate of a modifier already in the record" });
        } else {
          // A second, different exp= would make the record invalid (RFC 7208 §6); keep the first.
          changes.push({ op: "remove", term: t.raw, reason: `Duplicate ${key}= modifier: only one is allowed (RFC 7208 §6), so the first one (${prev.term}) is kept` });
          warnings.push(`Two different ${key}= values were found; kept ${prev.term}. Confirm with the client.`);
        }
        continue;
      }
      if (t.kind === "mechanism" && t.name === "ptr") {
        changes.push({ op: "remove", term: t.raw, reason: "RFC 7208 §5.5: ptr SHOULD NOT be used. Replace it with the sender's ip4:/ip6:/a: terms if it's still needed" });
        continue;
      }
      // "+" is the default qualifier, so "+include:x" and "include:x" are the same term.
      const term = t.kind === "mechanism" && t.raw.startsWith("+") ? t.raw.slice(1) : t.raw;
      const norm = term.toLowerCase();
      if (seen.has(norm)) {
        changes.push({ op: "remove", term: t.raw, reason: "Duplicate of a term already in the record" });
        continue;
      }
      seen.add(norm);
      mechanisms.push(term);
      if (t.kind === "unknown") {
        changes.push({ op: "keep", term, reason: "Not a valid SPF term: it makes the record invalid (permerror). Fix or remove it by hand after checking with the client" });
        warnings.push(`"${t.raw}" isn't a valid SPF term. It was kept so nothing is dropped silently, but the record stays invalid until it's fixed by hand.`);
      } else if (afterAll) {
        changes.push({ op: "keep", term, reason: "Was listed after \"all\", so receivers ignored it; it is now checked. Confirm this sender is still used" });
        warnings.push(`${term} was after "all" (ignored by receivers) and now takes effect. Confirm the client still uses it.`);
      } else {
        changes.push({ op: "keep", term, reason: "Already in the record" });
      }
    }
  }

  // redirect handling
  const anyAll = allQualifiers.length > 0;
  let keptRedirect = null;
  const uniqueRedirects = [...new Map(redirects.map((r) => [r.target, r])).values()];
  if (uniqueRedirects.length === 1 && !anyAll) {
    keptRedirect = uniqueRedirects[0];
    changes.push({ op: "keep", term: keptRedirect.raw, reason: "Redirect kept: the record has no \"all\", so the redirect still applies" });
  } else {
    for (const r of uniqueRedirects) {
      if (r.recordHasAll && records.length === 1) {
        // Already ignored by receivers (RFC 7208 §6.1): keep it exactly as it was, no behaviour change.
        keptRedirect = r;
        changes.push({ op: "keep", term: r.raw, reason: "Kept as is. Receivers ignore it because the record has an \"all\" mechanism (RFC 7208 §6.1)" });
        continue;
      }
      const inc = `include:${r.target}`;
      if (seen.has(inc)) {
        changes.push({ op: "remove", term: r.raw, reason: `Duplicate: ${inc} is already in the record` });
        continue;
      }
      seen.add(inc);
      mechanisms.push(inc);
      changes.push({ op: "convert", term: `${r.raw} → ${inc}`, reason: "Records were merged into one that ends in \"all\", where a redirect would be ignored, so it becomes an include" });
      warnings.push(`redirect=${r.target} became include:${r.target}. An include doesn't use ${r.target}'s own "all" rule; this record's ending applies instead. Check this is intended.`);
    }
  }
  for (let i = 1; i < redirects.length; i++) {
    if (redirects.slice(0, i).some((p) => p.target === redirects[i].target)) changes.push({ op: "remove", term: redirects[i].raw, reason: "Duplicate redirect" });
  }

  const providerInclude = PROVIDER_SPF_INCLUDE[providerKey];
  const coveredByRedirect = keptRedirect && !anyAll && PROVIDER_SPF_TARGET[providerKey]?.test(keptRedirect.target);
  if (providerInclude && !seen.has(providerInclude) && !coveredByRedirect) {
    mechanisms.push(providerInclude);
    changes.push({ op: "add", term: providerInclude, reason: "Authorizes the email platform this domain uses" });
  }
  // A record that authorizes nobody would send all of this domain's real mail to spam once
  // DMARC is enforced. Refuse to guess: the technician has to find the senders first.
  if (mechanisms.length === 0 && !keptRedirect) return null;

  const parts = ["v=spf1", ...mechanisms];
  // With a working redirect (no "all" anywhere), adding "all" would switch the redirect off.
  if (!(keptRedirect && !anyAll)) {
    const ending = anyAll && allQualifiers.every((q) => q === "-") ? "-all" : "~all";
    parts.push(ending);
    const original = allQualifiers.length ? allQualifiers.map((q) => `${q === "+" ? "" : q}all`) : [];
    if (!original.length) changes.push({ op: "add", term: ending, reason: "Says what to do with unapproved senders (soft fail until DMARC reports confirm every sender)" });
    else if (original.every((o) => o === ending)) changes.push({ op: "keep", term: ending, reason: "The client's existing ending" });
    else changes.push({ op: "convert", term: `${[...new Set(original)].join(", ")} → ${ending}`, reason: ending === "~all" ? "+all/?all/mixed endings give no protection; ~all soft-fails unapproved senders" : "Kept the client's strict ending" });
  }
  if (keptRedirect) parts.push(keptRedirect.raw);
  for (const [, m] of modifiers) parts.push(m.term);
  const value = parts.join(" ");
  const strings = splitTxt(value);
  if (value.length > 450) warnings.push(`The record is ${value.length} characters. Some DNS hosts struggle with TXT values over 450 characters; it's provided as ${strings.length} strings of up to 255 bytes.`);
  return { value, strings, changes, warnings };
}

/**
 * Build a DMARC record. When the domain already has one, keep every one of the client's tags
 * (rua, ruf, sp, adkim, aspf, ri, rf, fo, np and anything else) in their original order, change
 * only p, add our report address alongside theirs, and drop pct only when moving to an enforcing
 * policy (so it applies to all mail). Returns { value, changes } like recommendSpf.
 */
export function recommendDmarc(policy, reportAddress, existingTags = null) {
  const t = existingTags || {};
  const changes = [];
  const ours = `mailto:${reportAddress}`;
  const parts = ["v=DMARC1", `p=${policy}`];
  if (!t.p) changes.push({ op: "add", term: `p=${policy}`, reason: "The policy" });
  else if (t.p.toLowerCase() === policy) changes.push({ op: "keep", term: `p=${policy}`, reason: "The client's current policy" });
  else changes.push({ op: "convert", term: `p=${t.p} → p=${policy}`, reason: policy === "none" ? "Monitor first" : "Next enforcement stage" });
  let ruaDone = false;
  for (const [k, v] of Object.entries(t)) {
    if (k === "v" || k === "p") continue;
    if (k === "pct") {
      if (policy !== "none") {
        changes.push({ op: "remove", term: `pct=${v}`, reason: "The enforcing policy should apply to all mail (pct defaults to 100)" });
        continue;
      }
      parts.push(`pct=${v}`);
      changes.push({ op: "keep", term: `pct=${v}`, reason: "The client's setting" });
      continue;
    }
    if (k === "rua") {
      const list = v.split(",").map((a) => a.trim()).filter(Boolean);
      const has = list.some((a) => a.replace(/!.*$/, "").toLowerCase() === ours.toLowerCase());
      for (const a of list) changes.push({ op: "keep", term: `rua ${a}`, reason: "The client's report address" });
      if (!has) changes.push({ op: "add", term: `rua ${ours}`, reason: "Reports to us so we can watch who sends as this domain" });
      parts.push(`rua=${[...list, ...(has ? [] : [ours])].join(",")}`);
      ruaDone = true;
      continue;
    }
    parts.push(`${k}=${v}`);
    changes.push({ op: "keep", term: `${k}=${v}`, reason: "The client's setting" });
  }
  if (!ruaDone) {
    parts.push(`rua=${ours}`);
    changes.push({ op: "add", term: `rua ${ours}`, reason: "Aggregate reports, so we can see who sends as this domain" });
  }
  if (!t.fo) {
    parts.push("fo=1");
    changes.push({ op: "add", term: "fo=1", reason: "Failure reports when either SPF or DKIM fails" });
  }
  return { value: parts.join("; "), changes };
}

const record = (type, name, value, { action = "Add", current = null, note = null, generated = false, zone = null, later = false, changes = null, strings = null } = {}) => ({
  type, name, value, ttl: "Auto / 3600", action, current, note, generated, zone, later, changes, strings,
});
const txt = (name, value, note, opts = {}) => record("TXT", name, value, { note, ...opts });

// Common SPF includes, so the checklist can say which services a record already allows.
const KNOWN_SENDERS = [
  [/^_spf\.google\.com$|^_netblocks\d*\.google\.com$/, "Google Workspace"],
  [/spf\.protection\.outlook\.com$/, "Microsoft 365"],
  [/secureserver\.net$/, "GoDaddy email"],
  [/zoho/, "Zoho Mail"],
  [/servers\.mcsv\.net$|mcsv\.net$/, "Mailchimp"],
  [/spf\.mandrillapp\.com$/, "Mailchimp Transactional (Mandrill)"],
  [/sendgrid\.net$/, "SendGrid"],
  [/mailgun\.org$/, "Mailgun"],
  [/amazonses\.com$/, "Amazon SES"],
  [/spf\.constantcontact\.com$/, "Constant Contact"],
  [/_spf\.intuit\.com$|intuit/, "QuickBooks / Intuit"],
  [/_spf\.salesforce\.com$/, "Salesforce"],
  [/hubspotemail\.net$|hubspot/, "HubSpot"],
  [/mail\.zendesk\.com$/, "Zendesk"],
  [/helpscoutemail\.com$/, "Help Scout"],
  [/sparkpostmail\.com$/, "SparkPost"],
  [/spf\.mtasv\.net$/, "Postmark"],
  [/mktomail\.com$/, "Marketo"],
  [/_spf\.squarespace\.com$|squarespace/, "Squarespace"],
  [/wixdns\.net$|wix/, "Wix"],
  [/messagingengine\.com$/, "Fastmail"],
  [/emsd1\.com$/, "Klaviyo"],
];

/** "include:sendgrid.net" → "include:sendgrid.net (SendGrid)", for every sender term in an SPF record. */
export function describeSpfSenders(spfRecord) {
  const out = [];
  for (const term of String(spfRecord).trim().split(/\s+/).slice(1)) {
    if (/^[+\-~?]?all$/i.test(term) || /^exp=/i.test(term)) continue;
    const t = term.replace(/^[+\-~?]/, "");
    const target = t.replace(/^(include:|redirect=)/i, "").toLowerCase();
    const known = /^(include:|redirect=)/i.test(t) ? KNOWN_SENDERS.find(([re]) => re.test(target))?.[1] : null;
    out.push(known ? `${t} (${known})` : /^ip[46]:/i.test(t) ? `${t} (a specific server address)` : /^(a|mx)$/i.test(t) ? `${t} (this domain's own ${t.toLowerCase() === "mx" ? "mail" : "web"} servers)` : t);
  }
  return out;
}

const CERT_ERRORS = {
  CERT_HAS_EXPIRED: "Expired",
  ERR_TLS_CERT_ALTNAME_INVALID: "Certificate doesn't cover this name",
  DEPTH_ZERO_SELF_SIGNED_CERT: "Self-signed (not trusted by browsers)",
  SELF_SIGNED_CERT_IN_CHAIN: "Untrusted (self-signed in chain)",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "Missing intermediate certificate",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "Missing intermediate certificate",
  CERT_NOT_YET_VALID: "Not valid yet (check the server clock)",
};
const friendlyCertError = (code) => (CERT_ERRORS[code] ? `${CERT_ERRORS[code]} (${code})` : code || "Invalid");

const fmtDate = (iso) => (iso ? new Date(iso).toISOString().slice(0, 10) : "unknown");

/* ------------------------------------------------------------------ */
/* Provider-specific DKIM steps                                         */
/* ------------------------------------------------------------------ */

function dkimSteps(provider, domain, where) {
  switch (provider.key) {
    case "google":
      // https://support.google.com/a/answer/174124 (default prefix "google", 2048-bit recommended)
      return [
        "Sign in to the Google Admin console (admin.google.com) with a super-admin account.",
        "Go to Apps → Google Workspace → Gmail → Authenticate email.",
        `Select ${domain}, click Generate new record (2048-bit, prefix "google").`,
        `Add the TXT record it shows (host "google._domainkey") at: ${where}.`,
        "If the DNS host rejects or cuts off the long 2048-bit value, go back and generate a 1024-bit key instead. A truncated key fails silently.",
        "Wait 15–60 minutes for DNS to update, then return and click Start authentication. Google checks the record first and won't start signing if it's wrong.",
      ];
    case "microsoft":
      return [
        "Sign in to the Microsoft Defender portal (security.microsoft.com) as a global or security admin.",
        "Go to Email & collaboration → Policies & rules → Threat policies → Email authentication settings → DKIM.",
        `Select ${domain}. Microsoft shows two CNAME records (selector1._domainkey and selector2._domainkey). Copy both exactly.`,
        `Add both CNAME records at: ${where}.`,
        "Wait 15–60 minutes, return to the DKIM page and switch \"Sign messages for this domain with DKIM signatures\" to Enabled.",
      ];
    case "zoho":
      return [
        "Sign in to the Zoho Mail Admin Console → Domains → select the domain → Email Configuration → DKIM.",
        "Add a selector (e.g. \"zmail\") and copy the TXT record Zoho generates.",
        `Add the TXT record at: ${where}, then click Verify in Zoho.`,
      ];
    default:
      return [
        `Find where ${domain}'s email is hosted (MX points to ${provider.name}) and open its admin panel.`,
        "Look for DKIM, email authentication or domain keys, and generate a key for this domain.",
        `Publish the record it gives you at: ${where}, then enable signing in the email admin panel.`,
      ];
  }
}

/** The DNS records each platform asks for. Values are generated by the platform, so they're placeholders. */
function dkimRecords(provider) {
  const opts = { generated: true };
  switch (provider.key) {
    case "google":
      return [txt("google._domainkey", "Copy from Google Admin → Gmail → Authenticate email (starts \"v=DKIM1; k=rsa; p=\")", "Generated by Google", opts)];
    case "microsoft":
      return [
        record("CNAME", "selector1._domainkey", "Copy the selector1 target exactly as shown on the Defender DKIM page", { ...opts, note: "Generated by Microsoft" }),
        record("CNAME", "selector2._domainkey", "Copy the selector2 target exactly as shown on the Defender DKIM page", { ...opts, note: "Generated by Microsoft" }),
      ];
    case "zoho":
      return [txt("<selector>._domainkey", "Copy from Zoho Mail Admin → Domains → Email Configuration → DKIM", "Generated by Zoho", opts)];
    default:
      return [];
  }
}

/* ------------------------------------------------------------------ */
/* Plan builder                                                         */
/* ------------------------------------------------------------------ */

/**
 * Which one-time package fits. Plus when the business sends email through services besides its
 * email provider (other include:/redirect= senders in SPF, or mail split across providers), or its
 * records are messy (more than one SPF or DMARC record, SPF over the lookup limits, a broken or
 * looping include). Otherwise Standard. Returns { id: "standard" | "plus", reasons: [plain English] }.
 */
export function packageFit(report, provider = report.provider || { key: "unknown" }) {
  const byId = Object.fromEntries((report.checks || []).map((c) => [c.id, c]));
  const reasons = [];
  const spf = byId.spf;
  const own = PROVIDER_SPF_INCLUDE[provider.key];
  const senders = new Set();
  for (const record of spf?.data?.records || []) {
    for (const term of String(record).trim().split(/\s+/).slice(1)) {
      const t = term.replace(/^[+\-~?]/, "").toLowerCase();
      if (!/^(include:|redirect=)/.test(t)) continue;
      const inc = `include:${t.replace(/^(include:|redirect=)/, "")}`;
      if (inc !== own) senders.add(inc.slice("include:".length));
    }
  }
  if (senders.size) {
    const names = [...senders].map((target) => KNOWN_SENDERS.find(([re]) => re.test(target))?.[1] || target);
    reasons.push(`Email is also sent through ${names.join(", ")}, besides ${provider.name || "the email provider"}.`);
  }
  if (byId["email-platform"]?.data?.code === "mixed-mx") reasons.push("Incoming email is split across more than one mail provider.");
  const spfCodes = spf?.data?.codes || [];
  if (spfCodes.includes("multiple")) reasons.push("There's more than one approved-senders (SPF) record.");
  if (spfCodes.some((c) => ["too-many-lookups", "too-many-void-lookups", "include-loop", "mx-too-many"].includes(c))) reasons.push("The approved-senders (SPF) record is over its limits or has broken entries.");
  if (byId.dmarc?.data?.code === "multiple" || (byId.dmarc?.data?.codes || []).includes("multiple")) reasons.push("There's more than one impersonation-protection (DMARC) record.");
  return { id: reasons.length ? "plus" : "standard", reasons };
}

/** "$1,500". */
export const formatPrice = (n) => `$${Number(n).toLocaleString("en-US")}`;

/** A recurring price with its period: "$150/year", "$35/month". Unknown periods are refused, never guessed. */
export function periodLabel(price, period) {
  const per = { year: "/year", month: "/month" }[period];
  if (!per) throw new Error(`Unknown billing period "${period}" (use "year" or "month").`);
  return `${formatPrice(price)}${per}`;
}

export function buildPlan(report, { business = BUSINESS, packages = PACKAGES, quotes = QUOTE_ITEMS, recurring = RECURRING_OPTIONS, founding = FOUNDING_OFFER } = {}) {
  const domain = report.domain;
  const provider = report.provider || { key: "unknown", name: "Unknown" };
  const dnsHost = report.dnsHost || { key: "unknown", name: "Unknown", where: "the domain's DNS provider", nameservers: [] };
  const where = dnsHost.where;
  const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));
  const items = [];
  const verifyItems = [];
  const quoteItems = [];
  const accessNeeded = new Set();
  const sendsEmail = !["nullmx", "none"].includes(provider.key);

  const add = (item) => items.push(item);

  /* ---- Domain registration ---- */
  const reg = byId["domain-registration"];
  if (reg && (reg.status === "fail" || reg.status === "warn")) {
    const codes = reg.data?.codes || [];
    const urgent = codes.includes("expiring-urgent");
    const registrar = reg.data?.registrar || report.registrar || "the domain registrar";
    accessNeeded.add(`Access to the ${registrar} account that holds ${domain} (or add us as a delegate/user)`);
    add({
      id: "domain-security",
      fixes: ["domain-registration"],
      phase: 1,
      title: urgent ? "Renew and secure your domain (urgent)" : "Secure your domain name",
      clientWhy: urgent
        ? `${domain} expires in ${Math.max(reg.data.days, 0)} days. If it lapses, your website and every email address on it stop working, and someone else can register it.`
        : [
            codes.includes("expiring-soon") ? `${domain} expires in ${reg.data.days} days.` : null,
            codes.includes("unlocked") ? "It isn't locked against transfers, which makes it easier for someone to hijack." : null,
          ].filter(Boolean).join(" "),
      clientChange: "Nothing changes day to day. Your domain renews automatically and can't be moved without your approval.",
      minutes: urgent ? 30 : 20,
      found: [
        `Registrar: ${registrar}`,
        `Expires: ${fmtDate(reg.data?.expiry)} (${reg.data?.days} days from the scan)`,
        `Transfer lock: ${reg.data?.transferLocked ? "On" : "Off"}`,
        `DNSSEC: ${reg.data?.dnssec ? "On" : "Off"}`,
      ],
      settings: [
        { what: "Registrar account owner email", now: "Not public: check", to: "An address the business owner reads (not a former employee or web designer)" },
        { what: "Registrar account 2-step verification", now: "Not public: check", to: "On" },
        ...(urgent ? [{ what: "Expiry date", now: `${fmtDate(reg.data?.expiry)} (${Math.max(reg.data?.days ?? 0, 0)} days)`, to: "Renewed for 2+ years" }] : []),
        { what: "Auto-renew", now: "Not public: check", to: "On, with a current payment card" },
        ...(codes.includes("unlocked") ? [{ what: "Transfer lock (Domain/Registrar Lock)", now: "Off", to: "On" }] : []),
      ],
      steps: [
        `Log in to ${registrar}. Confirm the account belongs to the business (not a former employee or web designer) and that the account email is one the owner reads.`,
        "Turn on two-factor authentication for the registrar account.",
        ...(urgent ? [`Renew ${domain} now (recommend 2+ years) and confirm the new expiry date.`] : []),
        "Turn on auto-renew and confirm the payment card on file is current.",
        ...(codes.includes("unlocked") ? ["Turn on the transfer lock (sometimes called Domain Lock / Registrar Lock)."] : ["Confirm the transfer lock is on."]),
        "Record the registrar, account owner and renewal date in the client's runbook.",
      ],
      records: [],
      verify: "Re-run the health check: Domain registration should show transfer lock on and an expiry more than 90 days out.",
      rollback: "Nothing here touches DNS or email. Each registrar setting can be switched back on the same screen.",
    });
  } else if (reg && reg.status === "unknown") {
    verifyItems.push({ title: "Confirm domain renewal and lock status", steps: ["Registry data wasn't available during the scan. Log in to the registrar and check auto-renew, transfer lock and the expiry date."] });
  }

  /* ---- SPF ---- */
  const spf = byId.spf;
  if (spf && (spf.status === "fail" || spf.status === "warn") && sendsEmail) {
    const codes = spf.data?.codes || [];
    const currentSpf = spf.data?.records || [];
    const newSpf = recommendSpf(currentSpf, provider.key);
    const tooMany = codes.includes("too-many-lookups");
    accessNeeded.add(`Access to the DNS for ${domain} (${dnsHost.name})`);
    const problem = codes.includes("missing")
      ? "There's no list of servers allowed to send email as you, so anyone can send email that looks like it's from your business, and your real email is more likely to land in spam."
      : codes.includes("multiple")
        ? "You have more than one approved-senders (SPF) record. Mail servers treat that as broken, so the protection is effectively off."
        : codes.includes("permissive")
          ? "Your approved-senders record currently allows anyone to send as you, so it provides no protection."
          : tooMany
            ? "Your approved-senders record has grown too long for mail servers to check fully, so many treat it as broken."
            : codes.includes("missing-provider")
              ? `Your approved-senders record doesn't include ${provider.name}, the system your email actually comes from, which can push your own messages into spam.`
              : "Your approved-senders record needs a cleanup so mail servers can rely on it.";
    add({
      id: "spf",
      fixes: ["spf"],
      phase: 2,
      title: "Fix your approved-senders list (SPF)",
      clientWhy: problem,
      clientChange: "Nothing changes for your team. We'll confirm with you which services send email on your behalf (invoicing, newsletters, website forms) so none of them get blocked.",
      minutes: tooMany ? 60 : 30,
      found: currentSpf.length
        ? [
            ...currentSpf.map((r, i) => `${currentSpf.length > 1 ? `SPF record ${i + 1}` : "Current SPF record"} (TXT @): ${r}`),
            ...(spf.data?.lookups != null
              ? [`DNS lookups: ${spf.data.lookups} (limit 10)`]
              : spf.data?.lookupsAtLeast != null
                ? [`DNS lookups: ${spf.data.lookupsAtLeast > 10 ? "more than 10" : `at least ${spf.data.lookupsAtLeast}`} (limit 10; not every lookup could be resolved)`]
                : []),
            ...(spf.data?.voids != null ? [`Void lookups (no answer): ${spf.data.voids} (limit 2)`] : []),
            ...(codes.includes("permissive") ? ["Ends in +all, which allows any server in the world"] : []),
            ...(codes.includes("neutral-all") ? ["Ends in ?all (neutral), which gives no protection"] : []),
            ...(codes.includes("ptr-deprecated") ? ["Uses ptr, which RFC 7208 §5.5 says SHOULD NOT be used"] : []),
            ...(codes.includes("missing-provider") ? [`${provider.name} (where this domain's email comes from) is not in the record`] : []),
            `Senders it currently allows: ${[...new Set(currentSpf.flatMap(describeSpfSenders))].join(", ") || "none"}`,
          ]
        : [`No SPF record: there is no TXT record starting "v=spf1" on ${domain}`],
      settings: [],
      steps: [
        "Before changing anything, send a test email from every system that sends as this domain (the mailbox, plus any invoicing, newsletter, website form or CRM tools) to a Gmail address. In Gmail: ⋮ → Show original. Note which ones show SPF: PASS today, so you can compare afterwards.",
        "Ask the client which services send email as their domain: invoicing/accounting (QuickBooks, Xero), newsletters (Mailchimp, Constant Contact), website contact forms, CRM, scheduling tools, scanners/copiers. Add each service's documented SPF include before the final all.",
        ...(currentSpf.length ? [`Save the current record(s) exactly as they are (screenshot or copy) before changing anything: ${currentSpf.join("  |  ")}`] : []),
        ...(!newSpf
          ? [`STOP: the scan can't tell which servers send ${domain}'s mail (${provider.name}), so there is no safe record to publish yet. Find the sending servers first (the email provider's SPF documentation, or the "Received" headers of a sent message), then build the record from them.`]
          : []),
        ...(codes.includes("multiple") ? ["Edit the first SPF record to the merged value below, then delete the other SPF record(s). Editing in place avoids a gap with no SPF at all."] : []),
        ...(tooMany
          ? ["The record exceeds the 10-lookup limit. Remove services the client no longer uses; replace small senders with their ip4:/ip6: ranges; only use an SPF-flattening service as a last resort. The record below is a merged starting point and must be reviewed before publishing."]
          : []),
        ...(newSpf ? [`${currentSpf.length ? "Replace" : "Add"} the TXT record below at: ${where}.`] : []),
        ...(newSpf?.warnings || []).map((w) => `CHECK: ${w}`),
        ...(newSpf?.changes || []).filter((c) => c.op === "remove" || c.op === "convert").map((c) => `${c.op === "remove" ? "Removed" : "Converted"} ${c.term}: ${c.reason}.`),
        "Do not tighten to -all as part of this job. That only happens after DMARC reports show every legitimate sender passing.",
        "Re-send the test emails. Every system that passed before must still pass. If any fails, roll back (below) and investigate before going further.",
      ],
      records: !newSpf
        ? [txt("@", "Not built: the sending servers must be identified first (see STOP step)", "Unknown sender", { generated: true })]
        : [
            txt("@", newSpf.value, tooMany ? "Review before publishing: lookup count must be 10 or fewer" : "Add any extra senders the client names before the final all", {
              action: currentSpf.length ? "Replace" : "Add",
              current: currentSpf[0] || null,
              changes: newSpf.changes,
              strings: newSpf.strings,
            }),
            ...(codes.includes("multiple") ? currentSpf.slice(1).map((r) => txt("@", r, "Delete: a domain may have only one SPF record", { action: "Delete" })) : []),
          ],
      rollback: currentSpf.length
        ? `Set the TXT @ record back to exactly: ${currentSpf[0]}${currentSpf.length > 1 ? ` (and re-add: ${currentSpf.slice(1).join("  |  ")})` : ""}. Changes take effect within the record's TTL, usually minutes.`
        : "Delete the SPF TXT record you added. The domain goes back to having no SPF, as before.",
      verify: "Re-run the health check: SPF should pass with 10 or fewer DNS lookups.",
    });
  }

  /* ---- DKIM ---- */
  const dkim = byId.dkim;
  const weakKey = ["weak-key", "key-warning"].includes(dkim?.data?.code);
  if (dkim && weakKey && sendsEmail) {
    accessNeeded.add(`Admin access to the email platform (${provider.name})`);
    accessNeeded.add(`Access to the DNS for ${domain} (${dnsHost.name})`);
    const weak = (dkim.data.keys || []).filter((k) => !k.revoked && k.status !== "pass");
    add({
      id: "dkim",
      fixes: ["dkim"],
      phase: 2,
      title: "Strengthen your email signing key (DKIM)",
      clientWhy: "Your email is signed, but the signing key is weaker than current standards (or still in test mode), which makes it easier to forge and can hurt deliverability.",
      clientChange: "Nothing changes for your team. It's a setting in your email system.",
      minutes: 30,
      found: weak.map((k) => `${k.selector}._domainkey: ${k.bits ? `${k.type === "ed25519" ? "Ed25519" : `${k.bits}-bit RSA`}` : "unreadable key"}${k.testing ? ", testing mode (t=y)" : ""}. ${k.issues.join(" ")}`),
      settings: weak.map((k) => ({ what: `DKIM key "${k.selector}"`, now: k.bits ? `${k.bits}-bit${k.testing ? ", t=y" : ""}` : "Unreadable", to: "2048-bit, not in testing mode" })),
      steps: [
        "Generate a new 2048-bit key in the email platform under a NEW selector name, publish it, and wait for it to verify. Never delete or overwrite the old selector's record: mail signed with it is still in flight and being re-checked.",
        ...dkimSteps(provider, domain, where),
        "Once the platform signs with the new key (check a test email's DKIM: PASS and the s= selector in the headers), leave the old record in place for at least a week before the client decides whether to retire it.",
      ],
      // A new selector, never the existing one: overwriting a live key breaks mail signed with it.
      records: [txt("<new selector>._domainkey", `Copy the new 2048-bit key from ${provider.name} (use a new prefix, e.g. "google2" for Google)`, `Generated by ${provider.name}`, { generated: true })],
      verify: "Send a test email to a Gmail address → ⋮ → Show original: DKIM: PASS with the new selector. Then re-run the health check.",
      rollback: "Switch signing back to the old key in the platform. The old selector's DNS record was never touched, so it still verifies.",
    });
  } else if (dkim && dkim.status === "warn" && sendsEmail) {
    accessNeeded.add(`Admin access to the email platform (${provider.name})`);
    accessNeeded.add(`Access to the DNS for ${domain} (${dnsHost.name})`);
    add({
      id: "dkim",
      fixes: ["dkim"],
      phase: 2,
      title: "Turn on email signing (DKIM)",
      clientWhy: "Your outgoing email isn't being digitally signed. Signing proves a message really came from you, which helps it reach the inbox and is required before full impersonation protection can be switched on.",
      clientChange: "Nothing changes for your team. It's a setting in your email system.",
      minutes: 30,
      found: dkim.data?.found?.length
        ? [`Signing keys found at: ${dkim.data.found.map((s) => `${s}._domainkey`).join(", ")}`, `None of them is ${provider.name}'s own key, so mail sent from ${provider.name} isn't signed`]
        : [`No signing key published for ${provider.name}. Checked: ${(dkim.detail || "").replace(/^Checked selectors:\s*/i, "") || "the usual selector names"}`],
      settings: [{ what: `DKIM signing in ${provider.name}`, now: "Not set up", to: "On (2048-bit key where offered)" }],
      steps: dkimSteps(provider, domain, where),
      records: dkimRecords(provider),
      verify: "Send a test email to a Gmail address, open it, click ⋮ → Show original and confirm DKIM: PASS. Then re-run the health check.",
      rollback: "Turn signing back off in the email platform's DKIM settings, then delete the record(s) you added. Mail keeps flowing either way: a missing or wrong DKIM key only matters once DMARC is enforced.",
    });
  } else if (dkim && dkim.status === "unknown") {
    verifyItems.push({
      title: "Confirm email signing (DKIM) is on",
      steps: [
        "The signing key uses a custom name the scan couldn't guess. Send a test email to a Gmail address → ⋮ → Show original → confirm DKIM: PASS.",
        "If it doesn't pass, follow the DKIM steps for the email platform and add it to the plan.",
      ],
    });
  }

  /* ---- DMARC ---- */
  const dmarc = byId.dmarc;
  if (dmarc && (dmarc.status === "fail" || dmarc.status === "warn") && sendsEmail) {
    const code = dmarc.data?.code;
    const existingPolicy = dmarc.data?.policy;
    const report_ = business.dmarcReportAddress;
    const externalReports = !report_.toLowerCase().endsWith(`@${domain}`);
    accessNeeded.add(`Access to the DNS for ${domain} (${dnsHost.name})`);
    const startPolicy = existingPolicy === "quarantine" || existingPolicy === "reject" ? existingPolicy : "none";
    const currentDmarc = dmarc.data?.records || [];
    // Keep the client's own DMARC settings when there's a single valid record to build on.
    const keptTags = currentDmarc.length === 1 && code !== "invalid" && code !== "multiple" ? dmarc.data?.tags || null : null;
    const reportDomain = report_.split("@")[1];
    const stages =
      startPolicy === "none"
        ? [
            { policy: "none", note: "Stage 1: monitor (publish now)" },
            { policy: "quarantine", note: "Stage 2: after 2–4 weeks of clean reports" },
            { policy: "reject", note: "Stage 3: final" },
          ]
        : startPolicy === "quarantine"
          ? [
              { policy: "quarantine", note: "Stage 1: full coverage with reports (publish now)" },
              { policy: "reject", note: "Stage 2: final, after about a week of clean reports" },
            ]
          : [{ policy: "reject", note: "Publish now: adds reporting to your existing protection" }];
    add({
      id: "dmarc",
      fixes: ["dmarc"],
      phase: 3,
      title: "Turn on impersonation protection (DMARC)",
      clientWhy:
        code === "missing"
          ? "Right now nothing stops a scammer from sending email that looks exactly like it came from you, like fake invoices or payment-change requests to your clients. Gmail, Yahoo and Microsoft also increasingly filter mail from domains without this protection."
          : code === "monitor-only"
            ? "Your impersonation protection is in watch-only mode, so fake email using your name is still delivered. This finishes the job."
            : code === "partial"
              ? "Your impersonation protection only applies to some messages. This extends it to all of them."
              : code === "no-reports"
                ? "Your protection is on, but nobody receives the reports that show who's sending as you, so problems go unnoticed."
                : code === "invalid" || code === "multiple"
                  ? "Your impersonation-protection record is broken and isn't being applied."
                  : "Your impersonation-protection record has settings mail servers ignore (for example a report address that isn't authorized to receive reports). This corrects them.",
      clientChange: "We'll watch reports for 2–4 weeks to make sure all your real email passes, then switch protection fully on. Your team won't notice anything, but scammers will.",
      minutes: 45,
      steps: [
        "Finish the SPF and DKIM items first. DMARC enforcement only works once legitimate mail passes them.",
        ...(currentDmarc.length ? [`Save the current record(s) exactly as they are before changing anything: ${currentDmarc.join("  |  ")}`] : []),
        ...(keptTags ? ["The new record keeps the client's own settings (their report addresses, subdomain policy and alignment) and adds ours alongside."] : []),
        ...(code === "multiple" ? ["Edit the first _dmarc record to the Stage 1 value below, then delete the other _dmarc record(s)."] : []),
        `Stage 1 (now): ${currentDmarc.length ? "replace" : "add"} the _dmarc TXT record below at: ${where}.`,
        ...(externalReports
          ? [`One-time setup (if not done already): reports go to ${report_}, so the ${reportDomain} DNS must authorize them with TXT "*._report._dmarc" = "v=DMARC1" (listed below). One wildcard record covers every client.`]
          : []),
        ...(startPolicy === "reject"
          ? []
          : [
              `Before EVERY later stage, all of these must be true: (1) reports have been arriving at ${report_} for at least 2 weeks; (2) every service the client uses to send email (mailbox, invoicing, newsletters, website forms) appears in the reports and passes SPF or DKIM aligned with ${domain}; (3) nothing legitimate is failing. If reports aren't arriving, or anything legitimate fails, do NOT advance: fix that sender first.`,
              "Advance one stage at a time (none → quarantine → reject), with at least a week of clean reports between stages.",
            ]),
      ],
      found: currentDmarc.length
        ? [
            ...currentDmarc.map((r, i) => `${currentDmarc.length > 1 ? `DMARC record ${i + 1}` : "Current DMARC record"} (TXT _dmarc): ${r}`),
            ...(code === "multiple" || code === "invalid"
              ? [code === "multiple" ? "More than one DMARC record, so mail servers ignore all of them" : "The record is malformed, so mail servers ignore it"]
              : [
                  `Policy: p=${existingPolicy || "none"}${existingPolicy === "none" || !existingPolicy ? " (monitor only: fake mail is still delivered)" : ""}`,
                  `Applies to: ${dmarc.data?.pct ?? 100}% of mail`,
                  `Reports sent to: ${dmarc.data?.hasReports ? (dmarc.data?.tags?.rua || "set") : "nobody (no rua= tag)"}`,
                ]),
          ]
        : [`No DMARC record: nothing at _dmarc.${domain}`],
      settings: [],
      records: [
        ...stages.slice(0, 1).map((st) =>
          txt("_dmarc", recommendDmarc(st.policy, report_, keptTags).value, st.note, { action: currentDmarc.length ? "Replace" : "Add", current: currentDmarc[0] || null, changes: recommendDmarc(st.policy, report_, keptTags).changes }),
        ),
        ...(code === "multiple" ? currentDmarc.slice(1).map((r) => txt("_dmarc", r, "Delete: a domain may have only one DMARC record", { action: "Delete" })) : []),
        ...stages.slice(1).map((st, i) =>
          txt("_dmarc", recommendDmarc(st.policy, report_, keptTags).value, st.note, { action: "Replace", current: recommendDmarc(stages[i].policy, report_, keptTags).value, later: true }),
        ),
        ...(externalReports
          ? [txt("*._report._dmarc", "v=DMARC1", `One time only, on ${reportDomain} (not on ${domain}). Skip if it already exists.`, { zone: reportDomain })]
          : []),
      ],
      rollback: currentDmarc.length
        ? `Set the _dmarc TXT record back to exactly: ${currentDmarc[0]}${currentDmarc.length > 1 ? ` (and re-add: ${currentDmarc.slice(1).join("  |  ")})` : ""}. If a later stage blocks legitimate mail, step back one stage immediately (reject → quarantine → none).`
        : "Delete the _dmarc TXT record you added. If a later stage blocks legitimate mail, step back one stage immediately (reject → quarantine → none).",
      verify: "Re-run the health check after each stage. The final state is DMARC: Good (p=reject, with reports).",
      followUp: "Schedule a reminder 2–4 weeks out to review reports and advance the policy.",
    });
  }

  /* ---- SSL ---- */
  const ssl = byId.ssl;
  if (ssl && (ssl.status === "fail" || ssl.status === "warn")) {
    const bad = ssl.data?.badHosts?.map((b) => `${b.host} (${b.error})`).join(", ");
    accessNeeded.add("Access to the website hosting account (or the web designer's contact)");
    add({
      id: "ssl",
      fixes: ["ssl"],
      phase: 4,
      title: "Fix your website's security certificate",
      clientWhy:
        ssl.data?.code === "expiring"
          ? `Your website's security certificate expires in ${Math.max(ssl.data.days, 0)} days. When it does, visitors see a "Not secure" warning and many will leave.`
          : "Some visitors to your website currently see a browser security warning, which scares off customers and makes the business look unsafe.",
      clientChange: "Your site keeps working the same, minus the warning, and the certificate renews itself from now on.",
      minutes: 30,
      found: (ssl.detail || "").split("; ").filter(Boolean).map((line) => `Certificate on ${line}`),
      settings: ssl.data?.badHosts?.length
        ? ssl.data.badHosts.map((b) => ({ what: `Certificate for ${b.host}`, now: friendlyCertError(b.error), to: "Valid, auto-renewing certificate covering both the main domain and www" }))
        : [{ what: `Certificate for ${ssl.data?.host}`, now: `Expires in ${Math.max(ssl.data?.days ?? 0, 0)} days`, to: "Auto-renewing certificate (renews well before expiry)" }],
      steps: [
        ...(bad ? [`Problem hosts: ${bad}.`] : [`Certificate on ${ssl.data?.host} expires in ${ssl.data?.days} days.`]),
        "Identify the website host (ask the client or check the A/CNAME records for @ and www).",
        "Enable the host's free auto-renewing certificate (Let's Encrypt or equivalent), making sure it covers both the main domain and www.",
        "If www isn't used, either add it to the certificate or point www at the main site with a redirect.",
      ],
      records: [],
      verify: "Re-run the health check: the website certificate should be valid for both the main domain and www.",
      rollback: "Certificate changes don't affect email. If the site misbehaves, switch the host's certificate setting back and contact the host's support.",
    });
  }

  /* ---- HTTPS redirect ---- */
  const redirect = byId["https-redirect"];
  if (redirect && redirect.status === "warn") {
    accessNeeded.add("Access to the website hosting account (or the web designer's contact)");
    add({
      id: "https-redirect",
      fixes: ["https-redirect"],
      phase: 4,
      title: "Force secure connections on your website",
      clientWhy: "Your site still loads without encryption if someone types the address without https://, so contact-form details can travel unprotected.",
      clientChange: "Visitors are automatically moved to the secure version. Nothing else changes.",
      minutes: 15,
      found: [
        `http://${domain} answers with HTTP ${redirect.data?.status}${redirect.data?.location ? ` and sends visitors to ${redirect.data.location}` : ", serving the page without encryption"}`,
      ],
      settings: [
        {
          what: "HTTP → HTTPS redirect",
          now: redirect.data?.location ? `HTTP ${redirect.data.status} → ${redirect.data.location}` : `Off (HTTP ${redirect.data?.status})`,
          to: `On: permanent (301/308) redirect to https://${domain}/`,
        },
      ],
      steps: [
        "In the website host's settings, turn on \"Force HTTPS\" or \"Redirect HTTP to HTTPS\".",
        ...(dnsHost.key === "cloudflare" ? ["If the site is proxied through Cloudflare (orange cloud), you can instead turn on SSL/TLS → Edge Certificates → Always Use HTTPS."] : []),
        "Confirm the redirect is permanent (301 or 308) and goes straight to https://.",
      ],
      records: [],
      verify: "Re-run the health check: Forces secure connections should show Good.",
      rollback: "Turn the redirect setting back off. This doesn't affect email.",
    });
  }

  /* ---- Email platform (quote / verify) ---- */
  const platform = byId["email-platform"];
  const pcode = platform?.data?.code;
  if (pcode === "hosting-email") {
    const q = quotes["email-migration"];
    if (q) {
      quoteItems.push({
        id: "email-migration",
        title: q.title,
        from: q.from,
        clientWhy: `Your email currently runs on ${provider.name}'s bundled hosting email, which lacks the security, admin controls and reliability of a business email platform. Moving also makes it much easier to keep the fixes above in place.`,
      });
    }
  } else if (pcode === "mixed-mx") {
    // MX records are never changed by this tool: the client decides where their mail goes.
    verifyItems.push({
      title: "Confirm where email should be delivered (Google mixed with other mail servers)",
      steps: [
        `Current MX records: ${(platform.data.mx || []).join(", ")}. Keep every one of them as it is.`,
        "Ask the client whether the non-Google servers are still in use. If an MX change is ever needed, it is a separate, confirmed job listing every current MX record first; this plan never deletes MX records.",
      ],
    });
  } else if (pcode === "no-mx") {
    verifyItems.push({ title: "Confirm how the business receives email", steps: [`${domain} has no mail servers. Find out which address the business actually uses. If it should receive email at ${domain}, scope an email setup project.`] });
  }

  /* ---- Anything else the scan couldn't verify ---- */
  for (const u of report.unverified || []) {
    if (["dkim", "domain-registration"].includes(u.id)) continue; // handled above
    verifyItems.push({ title: `Re-check: ${u.title}`, steps: ["This check couldn't be completed during the scan. Re-run the health check at kickoff; if it fails, add the matching fix."] });
  }

  /* ---- Ordering, pricing, projection ---- */
  items.sort((a, b) => a.phase - b.phase);
  items.forEach((it, i) => (it.step = i + 1));

  // One flat package for the whole fix (no per-fix prices): Standard, or Plus when packageFit says so.
  const fit = packageFit(report, provider);
  const recommended = items.length ? packages.find((p) => p.id === fit.id) || packages[0] || null : null;
  const foundingPackage = founding ? packages.find((p) => p.id === founding.packageId) : null;
  const foundingBonus = founding ? (recurring || []).find((r) => r.id === founding.bonusRecurringId) : null;

  const fixedIds = new Set(items.flatMap((it) => it.fixes));
  const projectedChecks = report.checks.map((c) => (fixedIds.has(c.id) ? { ...c, status: "pass" } : c));
  const projectedScore = scoreChecks(projectedChecks);

  const totalMinutes = items.reduce((s, it) => s + it.minutes, 0);

  return {
    domain,
    preparedAt: report.scannedAt,
    business,
    provider,
    dnsHost,
    registrar: report.registrar || null,
    current: { grade: report.grade, score: report.score, coverage: report.coverage },
    projected: { grade: projectedScore === null ? null : gradeFor(projectedScore), score: projectedScore },
    phases: PHASES.filter((p) => items.some((it) => it.phase === p.id)).map((p) => ({ ...p, items: items.filter((it) => it.phase === p.id).map((it) => it.id) })),
    items,
    verifyItems,
    quoteItems,
    accessNeeded: [...accessNeeded],
    pricing: {
      // Both one-time packages, the recommended one marked; none when there's nothing to fix.
      packages: recommended ? packages.map((p) => ({ id: p.id, name: p.name, price: p.price, label: formatPrice(p.price), scope: p.scope, blurb: p.blurb, recommended: p.id === recommended.id })) : [],
      recommended: recommended ? { id: recommended.id, name: recommended.name, price: recommended.price, label: formatPrice(recommended.price), reasons: fit.reasons } : null,
      recommendedTotal: recommended ? recommended.price : 0,
      // Ongoing care: flat fee per business, each with its own period ("year" or "month").
      recurring: (recurring || []).map((r) => ({ id: r.id, name: r.name, price: r.price, period: r.period, label: periodLabel(r.price, r.period), blurb: r.blurb })),
      // Founding offer: always sent, shown only when the technician turns it on for this plan.
      founding:
        recommended && founding && foundingPackage
          ? {
              name: founding.name,
              limit: founding.limit,
              price: founding.price,
              label: formatPrice(founding.price),
              packageName: foundingPackage.name,
              regularLabel: formatPrice(foundingPackage.price),
              bonus: foundingBonus ? { name: foundingBonus.name, regularLabel: periodLabel(foundingBonus.price, foundingBonus.period) } : null,
              terms: founding.terms,
            }
          : null,
    },
    effort: { totalMinutes, hours: Math.round((totalMinutes / 60) * 10) / 10 },
    nothingToFix: items.length === 0,
  };
}

/* ------------------------------------------------------------------ */
/* Live safety check                                                    */
/* ------------------------------------------------------------------ */

/**
 * Before a technician sees the plan, resolve every SPF record we're proposing against live DNS
 * and count the lookups it would really need (RFC 7208 §4.6.4). The record is blocked (no copy
 * button) when it needs more than 10 lookups, has more than 2 void lookups or includes a name with
 * no SPF record. When the count couldn't be completed it is blocked: "unverified", which the
 * technician can only override after checking it by hand. Never throws.
 */
export async function safetyCheckPlan(plan, { resolver }) {
  const problems = [];
  const live = await dnsReachable(resolver);
  for (const it of plan.items) {
    for (const r of it.records || []) {
      if (r.generated || r.action === "Delete" || !isSpfRecord(r.value)) continue;
      r.lookups = null;
      r.lookupsAtLeast = null;
      r.voids = null;
      if (!live) {
        r.blocked = "unverified";
        r.note = "Live DNS couldn't be reached, so this record wasn't checked. Run it through an SPF checker (10 or fewer lookups, 2 or fewer void lookups, every include valid) and confirm by hand before publishing.";
        problems.push(`${it.title}: couldn't check against live DNS`);
        continue;
      }
      let walk = null;
      try {
        walk = await withTimeout(countSpfLookups(resolver, r.value, { domain: plan.domain }), 8000, "SPF safety check");
      } catch {
        walk = null;
      }
      if (walk) {
        r.voids = walk.voids;
        if (walk.complete && !walk.exceeded) r.lookups = walk.count;
        else if (walk.exceeded) r.lookups = walk.count; // stopped as soon as it went over 10
        else r.lookupsAtLeast = walk.count;
        r.lookupText = describeLookupCount(walk);
      }
      const dead = await deadSpfIncludes(resolver, r.value);
      if (dead.length) {
        r.blocked = true;
        r.note = `DO NOT PUBLISH: ${dead.join(", ")} ${dead.length > 1 ? "have" : "has"} no SPF record. Receivers would treat SPF as broken.`;
        problems.push(`${it.title}: ${dead.join(", ")} has no SPF record (probably a service the client stopped using)`);
        it.steps.unshift(`STOP: ${dead.map((x) => `include:${x}`).join(", ")} no longer has an SPF record, which breaks SPF for the whole domain. Confirm with the client the service is no longer used, remove it from the record, then re-run the plan.`);
      } else if (walk && (walk.exceeded || walk.count > SPF_LOOKUP_LIMIT)) {
        r.blocked = true;
        r.note = `DO NOT PUBLISH: needs ${r.lookupText} DNS lookups (limit 10). Receivers would treat SPF as broken.`;
        problems.push(`${it.title}: proposed SPF needs ${r.lookupText} lookups`);
        it.steps.unshift(`STOP: the proposed record needs ${r.lookupText} DNS lookups, over the limit of 10. Publishing it would break SPF. Remove senders the client no longer uses or replace small ones with their ip4:/ip6: ranges, then re-run the plan.`);
      } else if (walk && walk.voids > SPF_VOID_LIMIT) {
        r.blocked = true;
        r.note = `DO NOT PUBLISH: ${walk.voids} lookups return no answer (limit 2). Receivers may treat SPF as broken.`;
        problems.push(`${it.title}: proposed SPF has ${walk.voids} void lookups`);
        it.steps.unshift(`STOP: ${walk.voids} of the record's lookups return nothing (limit 2, RFC 7208 §4.6.4). Remove a:/mx:/exists:/include: terms that point at names that no longer exist, then re-run the plan.`);
      } else if (walk && walk.errors.some((e) => e.severity === "permerror")) {
        r.blocked = true;
        const msg = walk.errors.filter((e) => e.severity === "permerror").map((e) => e.message).join(" ");
        r.note = `DO NOT PUBLISH: ${msg}`;
        problems.push(`${it.title}: ${msg}`);
      } else if (!walk || !walk.complete) {
        r.blocked = "unverified";
        r.note = `Couldn't confirm the lookup count${walk ? ` (${r.lookupText} so far)` : ""}. Run it through an SPF checker (10 or fewer lookups) and confirm by hand before publishing.`;
        problems.push(`${it.title}: SPF lookup count unconfirmed`);
      }
    }
  }
  // RFC 7489 §7.1: our own report address only receives reports if its domain authorizes this one.
  const dm = plan.items.find((it) => it.id === "dmarc");
  const address = plan.business?.dmarcReportAddress;
  if (dm && address && live) {
    const destDomain = address.split("@")[1];
    const authorized = await reportDestinationAuthorized(resolver, plan.domain, destDomain);
    plan.reportAuthorization = { address, domain: destDomain, record: `${plan.domain}._report._dmarc.${destDomain}`, authorized };
    if (authorized === false) {
      dm.steps.unshift(`BEFORE PUBLISHING: ${destDomain} doesn't authorize reports for ${plan.domain} yet (no "v=DMARC1" TXT at ${plan.domain}._report._dmarc.${destDomain}), so receivers would not send reports to ${address}. Add the one-time *._report._dmarc record on ${destDomain} first.`);
    }
  } else if (dm && address) {
    plan.reportAuthorization = { address, domain: address.split("@")[1], authorized: null };
  }
  plan.safety = { checked: live, problems };
  return plan;
}
