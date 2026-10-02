// Turns a scan report into a fix plan with two views:
//  - client: plain-English "what we'll fix and why", timeline, price
//  - tech:   ordered checklist with exact DNS records, click paths and verification
//
// Every item traces back to a specific finding in the report, so the plan only ever
// proposes fixing what the assessment actually said was wrong.

import { BUSINESS, ITEM_PRICES, PACKAGES, QUOTE_ITEMS, MONTHLY_OFFER } from "./config.js";
import { parseSpf } from "./checks/email.js";
import { scoreChecks, gradeFor } from "./scan.js";

const PROVIDER_SPF_INCLUDE = {
  google: "include:_spf.google.com",
  microsoft: "include:spf.protection.outlook.com",
  zoho: "include:zohomail.com",
  godaddy: "include:secureserver.net",
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

/**
 * Build the SPF record to publish. Keeps every existing sender, merges duplicate
 * records into one, adds the email platform if it's missing, and ends in ~all.
 */
export function recommendSpf(existingRecords, providerKey) {
  const keep = [];
  const seen = new Set();
  for (const rec of existingRecords) {
    for (const term of rec.trim().split(/\s+/).slice(1)) {
      if (/^[+\-~?]?all$/i.test(term) || /^redirect=/i.test(term) || /^exp=/i.test(term)) continue;
      const norm = term.replace(/^\+/, "").toLowerCase();
      if (!seen.has(norm)) {
        seen.add(norm);
        keep.push(term.replace(/^\+/, ""));
      }
    }
    const redirect = parseSpf(rec).redirect;
    if (redirect && !seen.has(`include:${redirect}`)) {
      seen.add(`include:${redirect}`);
      keep.push(`include:${redirect}`);
    }
  }
  const providerInclude = PROVIDER_SPF_INCLUDE[providerKey];
  if (providerInclude && !seen.has(providerInclude)) keep.unshift(providerInclude);
  return ["v=spf1", ...keep, "~all"].join(" ");
}

export function recommendDmarc(policy, reportAddress) {
  return `v=DMARC1; p=${policy}; rua=mailto:${reportAddress}; fo=1`;
}

/**
 * A DNS record change for the technician. `action` is Add, Replace or Delete; `current` is the
 * value being replaced; `generated` marks values only the email platform can produce (so the UI
 * shows them as instructions, not copyable text); `zone` is set when the record goes on another domain.
 */
const record = (type, name, value, { action = "Add", current = null, note = null, generated = false, zone = null } = {}) => ({
  type, name, value, ttl: "Auto / 3600", action, current, note, generated, zone,
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
      return [
        "Sign in to the Google Admin console (admin.google.com) with a super-admin account.",
        "Go to Apps → Google Workspace → Gmail → Authenticate email.",
        `Select ${domain}, click Generate new record (2048-bit, prefix "google").`,
        `Add the TXT record it shows (host "google._domainkey") at: ${where}.`,
        "Wait 15–60 minutes for DNS to update, then return and click Start authentication.",
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

export function buildPlan(report, { business = BUSINESS, prices = ITEM_PRICES, packages = PACKAGES, quotes = QUOTE_ITEMS, monthly = MONTHLY_OFFER } = {}) {
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

  const add = (item) => items.push({ price: 0, priceKeys: [], ...item, price: item.priceKeys.reduce((s, k) => s + (prices[k] || 0), 0) });

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
      priceKeys: urgent ? ["domain-security", "domain-renewal"] : ["domain-security"],
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
      priceKeys: ["spf"],
      minutes: tooMany ? 60 : 30,
      found: currentSpf.length
        ? [
            ...currentSpf.map((r, i) => `${currentSpf.length > 1 ? `SPF record ${i + 1}` : "Current SPF record"} (TXT @): ${r}`),
            ...(spf.data?.lookups != null ? [`DNS lookups: about ${spf.data.lookups} (limit 10)`] : []),
            ...(codes.includes("permissive") ? ["Ends in +all or ?all, which allows any server in the world"] : []),
            ...(codes.includes("missing-provider") ? [`${provider.name} (where this domain's email comes from) is not in the record`] : []),
            `Senders it currently allows: ${[...new Set(currentSpf.flatMap(describeSpfSenders))].join(", ") || "none"}`,
          ]
        : [`No SPF record: there is no TXT record starting "v=spf1" on ${domain}`],
      settings: [],
      steps: [
        "Ask the client which services send email as their domain: invoicing/accounting (QuickBooks, Xero), newsletters (Mailchimp, Constant Contact), website contact forms, CRM, scheduling tools, scanners/copiers. Add each service's documented SPF include.",
        ...(spf.data?.records?.length ? [`Copy the current record(s) somewhere safe before changing anything: ${spf.data.records.join("  |  ")}`] : []),
        ...(codes.includes("multiple") ? ["Delete ALL existing SPF records (TXT values starting v=spf1), then add the single merged record below."] : []),
        ...(tooMany
          ? ["The record exceeds the 10-lookup limit. Remove services the client no longer uses; replace small senders with their ip4:/ip6: ranges; only use an SPF-flattening service as a last resort. The record below is a merged starting point and must be reviewed before publishing."]
          : []),
        `${spf.data?.records?.length && !codes.includes("multiple") ? "Replace" : "Add"} the TXT record below at: ${where}.`,
        "Keep ~all (soft fail) for now. Tighten to -all only after DMARC reports confirm every legitimate sender passes.",
      ],
      records: [
        ...(codes.includes("multiple") ? currentSpf.map((r) => txt("@", r, "Delete: a domain may have only one SPF record", { action: "Delete" })) : []),
        txt("@", newSpf, tooMany ? "Review before publishing: lookup count must be 10 or fewer" : "Add any extra senders the client names before the ~all", {
          action: currentSpf.length && !codes.includes("multiple") ? "Replace" : "Add",
          current: currentSpf.length && !codes.includes("multiple") ? currentSpf[0] : null,
        }),
      ],
      verify: "Re-run the health check: SPF should pass with 10 or fewer DNS lookups.",
    });
  }

  /* ---- DKIM ---- */
  const dkim = byId.dkim;
  if (dkim && dkim.status === "warn" && sendsEmail) {
    accessNeeded.add(`Admin access to the email platform (${provider.name})`);
    accessNeeded.add(`Access to the DNS for ${domain} (${dnsHost.name})`);
    add({
      id: "dkim",
      fixes: ["dkim"],
      phase: 2,
      title: "Turn on email signing (DKIM)",
      clientWhy: "Your outgoing email isn't being digitally signed. Signing proves a message really came from you, which helps it reach the inbox and is required before full impersonation protection can be switched on.",
      clientChange: "Nothing changes for your team. It's a setting in your email system.",
      priceKeys: ["dkim"],
      minutes: 30,
      found: dkim.data?.found?.length
        ? [`Signing keys found at: ${dkim.data.found.map((s) => `${s}._domainkey`).join(", ")}`, `None of them is ${provider.name}'s own key, so mail sent from ${provider.name} isn't signed`]
        : [`No signing key published for ${provider.name}. Checked: ${(dkim.detail || "").replace(/^Checked selectors:\s*/i, "") || "the usual selector names"}`],
      settings: [{ what: `DKIM signing in ${provider.name}`, now: "Not set up", to: "On (2048-bit key where offered)" }],
      steps: dkimSteps(provider, domain, where),
      records: dkimRecords(provider),
      verify: "Send a test email to a Gmail address, open it, click ⋮ → Show original and confirm DKIM: PASS. Then re-run the health check.",
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
    const replaceable = currentDmarc.length > 0 && code !== "multiple";
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
                : "Your impersonation-protection record is broken and isn't being applied.",
      clientChange: "We'll watch reports for 2–4 weeks to make sure all your real email passes, then switch protection fully on. Your team won't notice anything, but scammers will.",
      priceKeys: ["dmarc"],
      minutes: 45,
      steps: [
        "Finish the SPF and DKIM items first. DMARC enforcement only works once legitimate mail passes them.",
        ...(dmarc.data?.records?.length ? [`Save the current record(s): ${dmarc.data.records.join("  |  ")}`] : []),
        ...(code === "multiple" ? ["Delete ALL existing _dmarc TXT records; keep only the one below."] : []),
        `Stage 1 (now): ${dmarc.data?.records?.length ? "replace" : "add"} the _dmarc TXT record below at: ${where}.`,
        ...(externalReports
          ? [`One-time setup (if not done already): reports go to ${report_}, so the ${reportDomain} DNS must authorize them with TXT "*._report._dmarc" = "v=DMARC1" (listed below). One wildcard record covers every client.`]
          : []),
        ...(startPolicy === "reject"
          ? []
          : ["Later stages: review the aggregate reports. When all legitimate sources pass SPF or DKIM, advance the policy one stage (none → quarantine → reject), allowing about a week of clean reports between stages."]),
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
        ...(code === "multiple" ? currentDmarc.map((r) => txt("_dmarc", r, "Delete: a domain may have only one DMARC record", { action: "Delete" })) : []),
        ...stages.map((st, i) =>
          txt("_dmarc", recommendDmarc(st.policy, report_), st.note, {
            action: i === 0 ? (replaceable ? "Replace" : "Add") : "Replace",
            current: i === 0 ? (replaceable ? currentDmarc[0] : null) : recommendDmarc(stages[i - 1].policy, report_),
          }),
        ),
        ...(externalReports
          ? [txt("*._report._dmarc", "v=DMARC1", `One time only, on ${reportDomain} (not on ${domain}). Skip if it already exists.`, { zone: reportDomain })]
          : []),
      ],
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
      priceKeys: ["ssl"],
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
      priceKeys: ["https-redirect"],
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

  const itemsTotal = items.reduce((s, it) => s + it.price, 0);
  const coveredKeys = new Set(items.flatMap((it) => it.priceKeys));
  const pkg = packages
    .filter((p) => [...coveredKeys].every((k) => p.covers.includes(k)) && coveredKeys.size > 0)
    .sort((a, b) => a.price - b.price)[0];
  const usePackage = Boolean(pkg && pkg.price < itemsTotal);

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
      itemsTotal,
      package: usePackage ? { id: pkg.id, name: pkg.name, price: pkg.price, blurb: pkg.blurb, savings: itemsTotal - pkg.price } : null,
      recommendedTotal: usePackage ? pkg.price : itemsTotal,
      monthly: monthly || null,
    },
    effort: { totalMinutes, hours: Math.round((totalMinutes / 60) * 10) / 10 },
    nothingToFix: items.length === 0,
  };
}
