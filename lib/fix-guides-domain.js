// "How to fix" guides for the Domain Health tool. Same structure as lib/fix-guides.js (which merges
// these in), but the platforms are registrars and DNS hosts instead of web servers.
//
// Verified against official pages:
//   Cloudflare Registrar (cloudflare/cloudflare-docs registrar/account-options/renew-domains,
//     domain-management, faq) and Cloudflare DNS (dns/manage-dns-records/how-to/create-dns-records,
//     dns/dnssec: remove the DS at the registrar first, mismatched DS → SERVFAIL).
//   GoDaddy help 41085 (auto-renew: Domain Portfolio → domain settings → Renew → Auto-renew).
//   Namecheap knowledgebase 380 (Domain List → Manage → Sharing & Transfer → Domain Lock → Lock) and
//     373 (Domain List → select → Actions → Auto-Renew).
//   ICANN ERRP (renewal reminders about 1 month and 1 week before expiry; a notice within 5 days after).
// Not confirmed from an official page, so written as "ask your registrar": the GoDaddy lock setting,
// everything for Squarespace Domains, the Cloudflare Registrar lock, and Microsoft 365 / Google admin paths.

const S = {
  icannErrp: "https://www.icann.org/en/contracted-parties/consensus-policies/expired-registration-recovery-policy/expired-registration-recovery-policy-28-02-2013-en",
  icannErrpGuide: "https://www.icann.org/resources/pages/registrant-about-errp-2018-12-07-en",
  icannEpp: "https://www.icann.org/epp",
  rfc5731: "https://www.rfc-editor.org/rfc/rfc5731",
  rfc8056: "https://www.rfc-editor.org/rfc/rfc8056",
  rfc1034: "https://www.rfc-editor.org/rfc/rfc1034",
  rfc2182: "https://www.rfc-editor.org/rfc/rfc2182",
  rfc1912: "https://www.rfc-editor.org/rfc/rfc1912",
  rfc8499: "https://www.rfc-editor.org/rfc/rfc8499",
  rfc2308: "https://www.rfc-editor.org/rfc/rfc2308",
  rfc4033: "https://www.rfc-editor.org/rfc/rfc4033",
  rfc5321: "https://www.rfc-editor.org/rfc/rfc5321",
  rfc7505: "https://www.rfc-editor.org/rfc/rfc7505",
  rfc7208: "https://www.rfc-editor.org/rfc/rfc7208",
  rfc7489: "https://www.rfc-editor.org/rfc/rfc7489",
  icannDnssec: "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en",
  canITakeOver: "https://github.com/EdOverflow/can-i-take-over-xyz",
  cfRenew: "https://developers.cloudflare.com/registrar/account-options/renew-domains/",
  cfDomainMgmt: "https://developers.cloudflare.com/registrar/account-options/domain-management/",
  cfRegistrarFaq: "https://developers.cloudflare.com/registrar/faq/",
  cfDnsRecords: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/",
  cfDnssec: "https://developers.cloudflare.com/dns/dnssec/",
  cfRegistrarDnssec: "https://developers.cloudflare.com/registrar/get-started/enable-dnssec/",
  godaddyAutoRenew: "https://www.godaddy.com/help/turn-my-domain-auto-renew-on-or-off-41085",
  namecheapLock: "https://www.namecheap.com/support/knowledgebase/article.aspx/380/46/how-do-i-setrelease-registrar-lock-for-a-domain/",
  namecheapBulk: "https://www.namecheap.com/support/knowledgebase/article.aspx/373/46/i-have-multiple-domains-in-my-account-how-do-i-manage-them-efficiently/",
};

const ASK = "Not confirmed from the registrar's own help pages: if you can't find it, ask the registrar's support.";

/* Registrar platforms */
const reg = {
  renew: [
    { id: "godaddy", label: "GoDaddy", possible: true, steps: ["Sign in and open the Domain Portfolio, then the domain's settings page.", "In the Renew section, turn Auto-renew on and confirm. Renew now if the date is close.", "Check the payment method on the account is current."] },
    { id: "namecheap", label: "Namecheap", possible: true, steps: ["Go to Domain List, select the domain, then Actions → Auto-Renew to turn it on.", "Renew now if the date is close (Renew Expiring covers domains expiring within 30 days).", "Check the payment method on the account is current."] },
    { id: "squarespace-domains", label: "Squarespace Domains", possible: "partial", steps: ["Open the domain in the Domains panel and look for the renewal / auto-renew setting.", ASK] },
    { id: "cloudflare-registrar", label: "Cloudflare Registrar", possible: true, steps: ["Auto-renew is on by default. Go to the Manage domains page and make sure the domain's Auto-renew toggle is on.", "To renew now: Manage domains → the domain → Manage → Registration → Renew/Extend Domain → choose years → Renew → Purchase.", "Cloudflare first tries to auto-renew about 30 days before expiry, so keep the payment method current."] },
  ],
  lock: [
    { id: "godaddy", label: "GoDaddy", possible: "partial", steps: ["Open the Domain Portfolio, then the domain's settings, and look for the Domain lock / transfer lock setting.", ASK] },
    { id: "namecheap", label: "Namecheap", possible: true, steps: ["Go to Domain List, click Manage next to the domain, open Sharing & Transfer.", "Under Transfer Out, click Lock for the Domain Lock option."] },
    { id: "squarespace-domains", label: "Squarespace Domains", possible: "partial", steps: ["Open the domain in the Domains panel and look for the transfer lock setting.", ASK] },
    { id: "cloudflare-registrar", label: "Cloudflare Registrar", possible: "partial", steps: ["Open Manage domains → the domain → Manage → Configuration and check the transfer lock.", ASK] },
  ],
};
const regAsk = (what) =>
  ["godaddy", "namecheap", "squarespace-domains", "cloudflare-registrar"].map((id) => ({
    id,
    label: { godaddy: "GoDaddy", namecheap: "Namecheap", "squarespace-domains": "Squarespace Domains", "cloudflare-registrar": "Cloudflare Registrar" }[id],
    possible: "partial",
    steps: [`Contact the registrar's support today about ${what}. Have the account login ready and send them the message below.`],
  }));

/* DNS host platforms */
const dnsCloudflare = (steps) => ({ id: "dns-cloudflare", label: "Cloudflare DNS", possible: true, steps: ["In the Cloudflare dashboard, go to the DNS Records page.", ...steps, "Select Save."] });
const dnsRegistrar = (steps) => ({ id: "dns-registrar", label: "Registrar's DNS (GoDaddy, Namecheap, Squarespace…)", possible: true, steps: ["Open the domain's DNS settings at whoever hosts the DNS (often the registrar).", ...steps, "Not confirmed for every registrar's screens: if the record type isn't offered, ask the DNS host's support."] });
const m365 = (steps) => ({ id: "microsoft-365", label: "Microsoft 365", possible: true, steps: [...steps, "Not confirmed from Microsoft's pages here: follow the domain setup steps in the Microsoft 365 admin center, or ask Microsoft support."] });
const google = (steps) => ({ id: "google-workspace", label: "Google Workspace", possible: true, steps: [...steps, "Not confirmed from Google's pages here: follow the domain setup steps in the Google Admin console, or ask Google support."] });

const MSG_END = "\n\nThank you!";

export const DOMAIN_GUIDES = {
  "domain-expiry": {
    tool: "domain",
    why: "When a domain expires, the website and every email address on it stop working. If it isn't renewed in time, someone else can register it.",
    difficulty: "easy",
    time: "5–15 minutes",
    risk: "Renew from the registrar's own site or account only. Expiry \"renewal notices\" from other companies are often scams.",
    platforms: reg.renew,
    message: "Hi,\n\nOur IT provider checked {domain} and found: {finding}\n\nDetails: {detail}\n\nCould you please renew the domain, turn on auto-renew, and confirm the payment card and account owner are current?" + MSG_END,
    verify: "Run the Domain Health check again: the renewal date should be more than 60 days away.",
    sources: [S.icannErrp, S.icannErrpGuide, S.cfRenew, S.godaddyAutoRenew, S.namecheapBulk],
    variants: {
      expired: { why: "The domain has expired. The website and email stop working, and after the registrar's grace period it can be lost.", time: "Today", risk: "Act today: after the grace period, restoring the domain costs more, and later it's released to anyone." },
      "expiring-urgent": { why: "The domain expires within two weeks. If it lapses, the website and every email address on it stop working." },
    },
  },
  "domain-status": {
    tool: "domain",
    why: "Without a transfer lock, it's easier for someone who gets into the registrar account or tricks the registrar to move the domain away.",
    difficulty: "easy",
    time: "5 minutes",
    platforms: reg.lock,
    message: "Hi,\n\nOur IT provider checked {domain} and found that the domain isn't locked against transfers.\n\nDetails: {detail}\n\nCould you please turn on the registrar transfer lock (domain lock)?" + MSG_END,
    verify: "Run the Domain Health check again: the status should include client transfer prohibited.",
    sources: [S.icannEpp, S.rfc5731, S.rfc8056, S.namecheapLock],
    variants: {
      redemption: { why: "The domain expired and was deleted by the registrar. It can only be restored (redeemed) for a fee during a short window.", difficulty: "moderate", time: "Today", risk: "Act today: once the redemption period ends, the domain is released to anyone.", platforms: regAsk("restoring (redeeming) the domain"), message: "Hi,\n\nOur IT provider checked {domain}: the domain is in its redemption period.\n\nDetails: {detail}\n\nPlease restore (redeem) the domain today and turn on auto-renew." + MSG_END },
      "pending-delete": { why: "The domain is about to be deleted and released for anyone to register.", difficulty: "moderate", time: "Today", risk: "It may already be too late to restore. Contact the registrar immediately.", platforms: regAsk("whether the domain can still be restored"), message: "Hi,\n\nOur IT provider checked {domain}: the domain is pending deletion.\n\nDetails: {detail}\n\nPlease tell us today whether it can still be restored." + MSG_END },
      "on-hold": { why: "The domain is on hold, so it has been taken out of DNS: the website and email don't work.", difficulty: "moderate", time: "15–60 minutes", platforms: regAsk("why the domain is on hold (often an unpaid renewal or unverified contact details)"), message: "Hi,\n\nOur IT provider checked {domain}: the domain is on hold.\n\nDetails: {detail}\n\nCould you tell us why and what's needed to release it?" + MSG_END },
    },
  },
  nameservers: {
    tool: "domain",
    why: "Nameservers tell the internet where the domain's records live. With only one, or a broken one, the website and email can stop working for some visitors.",
    difficulty: "moderate",
    time: "15–30 minutes, plus up to 48 hours to take effect",
    risk: "Changing nameservers can take the website and email offline if the new DNS host doesn't have all the records. Before switching, copy every record (export the zone) and check the new host has them.",
    platforms: [
      ...reg.lock.map((p) => ({ ...p, steps: [`At ${p.label}, open the domain's nameserver settings.`, "Make sure the list contains only the nameservers your DNS host gives you (at least two), with no old or misspelled entries.", ASK] })),
      { id: "dns-cloudflare", label: "Cloudflare DNS", possible: true, steps: ["Cloudflare assigns two nameservers to each zone. Use exactly those two at the registrar, and remove any others."] },
    ],
    message: "Hi,\n\nOur IT provider checked {domain} and found a nameserver problem: {finding}\n\nDetails: {detail}\n\nCould you please make sure the domain lists at least two working nameservers from the current DNS host, and remove any old or broken ones?" + MSG_END,
    verify: "Run the Domain Health check again: every nameserver should show as authoritative.",
    sources: [S.rfc1034, S.rfc2182, S.rfc1912, S.rfc8499],
    variants: {
      "too-few": { why: "With only one nameserver, a single outage takes the website and email down." },
      "ns-unresolvable": { why: "One of the listed nameservers doesn't exist, so lookups that pick it fail.", time: "15 minutes" },
      lame: { why: "One of the listed nameservers doesn't know about this domain (lame delegation), so some lookups fail or are slow." },
    },
  },
  soa: {
    tool: "domain",
    why: "The nameservers disagree about the current version of the zone, so some visitors may get old records.",
    difficulty: "advanced",
    time: "Ask the DNS host",
    platforms: [
      { id: "dns-cloudflare", label: "Cloudflare DNS", possible: "partial", steps: ["Cloudflare manages the SOA record itself. If the domain also lists nameservers from another provider, remove those at the registrar."] },
      { id: "dns-registrar", label: "Registrar's DNS", possible: "partial", steps: ["The SOA record is managed by the DNS host. Send the message below to its support."] },
    ],
    message: "Hi,\n\nOur IT provider checked {domain} and found: {finding}\n\nDetails: {detail}\n\nCould you please check the zone on all of the domain's nameservers?" + MSG_END,
    verify: "Run the Domain Health check again: all nameservers should report the same SOA serial.",
    sources: [S.rfc1912, S.rfc2308],
    variants: { missing: { why: "The domain has no SOA record, which every DNS zone needs. The zone may be set up wrongly at the DNS host." } },
  },
  dnssec: {
    tool: "domain",
    why: "DNSSEC is switched on at the registry but the DNS host isn't signing the zone. Resolvers that check DNSSEC may refuse to look the domain up at all.",
    difficulty: "advanced",
    time: "30 minutes, plus a day or two for caches",
    risk: "Removing or changing DS records has a delay: resolvers cache them for their TTL. The quickest safe fix is usually to remove the DS record at the registrar, wait for its TTL, and turn DNSSEC on again properly later.",
    platforms: [
      ...regAsk("removing the DS (DNSSEC) record").map((p) => (p.id === "cloudflare-registrar" ? { ...p, possible: true, steps: ["If the DNS is also on Cloudflare: turn DNSSEC on in the DNS settings and Cloudflare publishes the DS record for you (it can take one to two days).", "Otherwise turn DNSSEC off for the domain so the DS record is removed."] } : p)),
      { id: "dns-cloudflare", label: "Cloudflare DNS", possible: true, steps: ["To keep DNSSEC: enable DNSSEC in Cloudflare's DNS settings and add the DS record it shows at the registrar.", "To remove it: delete the DS record at the registrar first, and keep signing on in Cloudflare until the old DS has expired from caches."] },
    ],
    message: "Hi,\n\nOur IT provider checked {domain}: DNSSEC is turned on at the registry, but the DNS servers aren't serving the signing keys.\n\nDetails: {detail}\n\nCould you please either enable DNSSEC signing at the DNS host and publish the matching DS record, or remove the DS record at the registrar?" + MSG_END,
    verify: "Run the Domain Health check again after a day: DNSSEC should show the keys are served, or that DNSSEC is off.",
    sources: [S.rfc4033, S.icannDnssec, S.cfDnssec, S.cfRegistrarDnssec],
  },
  mx: {
    tool: "domain",
    why: "A mail server listed for the domain doesn't exist or points at a private address, so some incoming email bounces or is delayed.",
    difficulty: "moderate",
    time: "15–30 minutes",
    risk: "MX changes affect incoming email. Check the exact values with the email provider before saving, and don't remove the working MX records.",
    platforms: [
      dnsCloudflare(["Find the broken MX record and select Edit (or delete it if the mail service no longer exists)."]),
      dnsRegistrar(["Find the broken MX record and correct or delete it."]),
      m365(["Use the MX value the Microsoft 365 admin center gives for this domain."]),
      google(["Use the MX values Google gives for Google Workspace."]),
    ],
    message: "Hi,\n\nOur IT provider checked {domain} and found a broken mail (MX) record.\n\nDetails: {detail}\n\nCould you please correct or remove it so every MX record points at a working, public mail server?" + MSG_END,
    verify: "Run the Domain Health check again, and send a test email to an address at {domain}.",
    sources: [S.rfc5321, S.rfc7505, S.cfDnsRecords],
  },
  "email-auth": {
    tool: "domain",
    why: "Without SPF and DMARC it's easy for someone to send email that looks like it came from this domain. The Email Security Check shows the exact records to add.",
    difficulty: "moderate",
    time: "30 minutes, then a few weeks of monitoring",
    risk: "SPF and DMARC can block real email if they leave out a service that sends for you. Use the Email Security Check and the Fix Plan, which start DMARC in monitoring mode.",
    platforms: [
      dnsCloudflare(["Add the TXT records from the Email Security Check / Fix Plan (SPF on the domain, DMARC on _dmarc)."]),
      dnsRegistrar(["Add the TXT records from the Email Security Check / Fix Plan."]),
      m365(["Microsoft 365 shows the SPF record it needs in the admin center's domain setup."]),
      google(["Google Workspace's setup lists the SPF include it needs."]),
    ],
    message: "Hi,\n\nOur IT provider checked {domain} and found: {finding}\n\nWe'll send the exact SPF and DMARC records to add. Could you please let us know who manages the DNS?" + MSG_END,
    verify: "Run the full Email Security Check for {domain}.",
    sources: [S.rfc7208, S.rfc7489, S.cfDnsRecords],
  },
  "dangling-cname": {
    tool: "domain",
    why: "A name on this domain points at a cloud service resource that no longer exists. Someone else could create a resource with that name and serve their own content on this domain.",
    difficulty: "easy",
    time: "10 minutes",
    risk: "Before deleting, confirm nobody still uses that subdomain. Deleting the record is safe if the service it pointed to is gone.",
    platforms: [
      dnsCloudflare(["Find the CNAME record for the name listed in the details and delete it (or edit it to point at the current service)."]),
      dnsRegistrar(["Find the CNAME record for the name listed in the details and delete it."]),
    ],
    message: "Hi,\n\nOur IT provider checked {domain} and found a CNAME record pointing at a service that no longer exists.\n\nDetails: {detail}\n\nCould you please delete that DNS record today (or recreate the resource it points to if it's still needed)?" + MSG_END,
    verify: "Run the Domain Health check again: no dangling CNAME should be listed.",
    sources: [S.canITakeOver, S.cfDnsRecords],
    variants: {
      dangling: { why: "A name on this domain points at a name that doesn't exist. Not a known takeover service, but the record is broken and should be cleaned up.", risk: "Before deleting, confirm nobody still uses that subdomain." },
    },
  },
};

export const DOMAIN_PLATFORMS = {
  godaddy: "GoDaddy",
  namecheap: "Namecheap",
  "squarespace-domains": "Squarespace Domains",
  "cloudflare-registrar": "Cloudflare Registrar",
  "dns-cloudflare": "Cloudflare DNS",
  "dns-registrar": "Registrar's DNS",
  "microsoft-365": "Microsoft 365",
  "google-workspace": "Google Workspace",
};
