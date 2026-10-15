// "How to fix" guides for the Domain Health tool. Same structure as lib/fix-guides.js (which merges
// these in), but the platforms are registrars and DNS hosts instead of web servers.
//
// Every registrar / DNS-host step below is taken from that vendor's own help page (listed in S and in
// each guide's sources). Anything that couldn't be confirmed there was dropped rather than guessed:
//   Cloudflare (cloudflare/cloudflare-docs): Registrar renew-domains (auto-renew on by default, Manage
//     domains → Auto-renew; manual renew path; first attempt ~30 days before expiry), transfer-out
//     (Manage Domains → Manage → Configuration → Unlock / lock), DNS records (Edit → Save; Edit →
//     Delete), full setup (assigned nameservers on the zone Overview page, copy exactly, remove the old
//     ones, turn DNSSEC off first), DNSSEC (activate in Cloudflare, add the DS at the registrar; to
//     remove, delete the DS first and keep signing until it expires; Cloudflare Registrar publishes DS
//     via CDS/CDNSKEY in 1–2 days), DNS record types (Cloudflare creates the SOA record itself).
//   GoDaddy help 41085 (auto-renew), 410 (lock: Domain Settings → Transfer toggle), 664 (nameservers).
//   Namecheap KB 373 (Actions → Auto-Renew; Renew Expiring = within 30 days), 380 (Sharing & Transfer
//     → Domain Lock → Lock), 767 (Manage → Nameservers drop-down → green checkmark).
//   Microsoft Learn "Gather the information you need to create DNS records" (admin center → Settings →
//     Domains → domain → Manage DNS; MX = <domain-key>.mail.protection.outlook.com).
//   Google Workspace Admin Help 61158 (MX smtp.google.com, priority 1, host @; remove old MX records;
//     pre-2023 setups may use aspmx values).
//   ICANN ERRP (renewal reminders about 1 month and 1 week before expiry; a notice within 5 days after).
// Dropped (no official page could be confirmed): every Squarespace Domains step, Cloudflare Registrar
// nameserver steps, and Microsoft 365 / Google Workspace SPF steps.

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
  cfTransferOut: "https://developers.cloudflare.com/registrar/account-options/transfer-out-from-cloudflare/",
  cfDnsRecords: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/",
  cfRecordTypes: "https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/",
  cfNameservers: "https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/",
  cfDnssec: "https://developers.cloudflare.com/dns/dnssec/",
  cfRegistrarDnssec: "https://developers.cloudflare.com/registrar/get-started/enable-dnssec/",
  godaddyAutoRenew: "https://www.godaddy.com/help/turn-my-domain-auto-renew-on-or-off-41085",
  godaddyLock: "https://www.godaddy.com/help/unlock-or-lock-my-domain-410",
  godaddyNameservers: "https://www.godaddy.com/help/change-my-domain-nameservers-664",
  namecheapLock: "https://www.namecheap.com/support/knowledgebase/article.aspx/380/46/how-do-i-setrelease-registrar-lock-for-a-domain/",
  namecheapBulk: "https://www.namecheap.com/support/knowledgebase/article.aspx/373/46/i-have-multiple-domains-in-my-account-how-do-i-manage-them-efficiently/",
  namecheapNameservers: "https://www.namecheap.com/support/knowledgebase/article.aspx/767/10/how-can-i-change-the-nameservers-for-my-domain/",
  m365Dns: "https://learn.microsoft.com/en-us/microsoft-365/admin/get-help-with-domains/information-for-dns-records",
  googleMx: "https://support.google.com/a/answer/61158",
};

/* Registrar platforms (verified steps only) */
const GODADDY = "GoDaddy";
const NAMECHEAP = "Namecheap";
const CF_REG = "Cloudflare Registrar";
const reg = {
  renew: [
    { id: "godaddy", label: GODADDY, possible: true, steps: ["Sign in to the Domain Portfolio and open the domain's settings page.", "In the Renew section, switch Auto-renew on and select Continue to confirm.", "Changes can take up to 90 minutes to show in the account."] },
    { id: "namecheap", label: NAMECHEAP, possible: true, steps: ["Go to Domain List, select the domain, then Actions → Auto-Renew to turn it on.", "To renew now, Renew Expiring covers domains expiring within the next 30 days."] },
    { id: "cloudflare-registrar", label: CF_REG, possible: true, steps: ["Auto-renew is on by default. On the Manage domains page, make sure the domain's Auto-renew toggle is on.", "To renew now: Manage domains → the domain → Manage → Registration → Renew/Extend Domain → choose the years → Renew → Purchase.", "Cloudflare first tries to auto-renew about 30 days before expiry, so keep the payment method current."] },
  ],
  lock: [
    { id: "godaddy", label: GODADDY, possible: true, steps: ["Sign in to the Domain Portfolio and select the domain to open its Domain Settings page.", "In the Transfer section, switch the toggle On (On means locked: the domain can't be transferred away).", "Domains with Domain Protection ask for a verification code. Changes can take up to 90 minutes to show."] },
    { id: "namecheap", label: NAMECHEAP, possible: true, steps: ["Go to Domain List, click Manage next to the domain, open Sharing & Transfer.", "Under Transfer Out, click Lock for the Domain Lock option."] },
    { id: "cloudflare-registrar", label: CF_REG, possible: true, steps: ["Go to the Manage Domains page, find the domain and select Manage, then Configuration.", "If the domain shows as unlocked (unlocking is only needed to transfer it away), lock it again there."] },
  ],
  nameservers: [
    { id: "godaddy", label: GODADDY, possible: true, steps: ["Sign in to the Domain Portfolio and open the domain's settings page.", "Select DNS, then Nameservers, choose your DNS host's nameservers (or GoDaddy's default) and save.", "Most changes take effect within an hour; allow up to 48 hours."] },
    { id: "namecheap", label: NAMECHEAP, possible: true, steps: ["Go to Domain List and click Manage next to the domain.", "In the Nameservers section, choose the option for your DNS host from the drop-down, enter its nameservers (names only, no IP addresses) and click the green checkmark.", "Switching nameservers doesn't copy DNS records across: set them up at the new host first."] },
  ],
};
// Restore / hold problems can only be solved by the registrar itself.
const regAsk = (what) =>
  [["godaddy", GODADDY], ["namecheap", NAMECHEAP], ["cloudflare-registrar", CF_REG]].map(([id, label]) => ({
    id,
    label,
    possible: "partial",
    steps: [`Contact the registrar's support today about ${what}. Have the account login ready and send them the message below.`],
  }));

/* DNS host platforms */
const CF_DNS = { id: "dns-cloudflare", label: "Cloudflare DNS", possible: true };
const cfEdit = (what) => ({ ...CF_DNS, steps: ["In the Cloudflare dashboard, go to the DNS Records page.", `On the ${what} record, select Edit, correct it and select Save. To remove it instead, select Edit, then Delete.`] });
const cfAdd = (what) => ({ ...CF_DNS, steps: ["In the Cloudflare dashboard, go to the DNS Records page.", "Select Add record, choose the record type and fill in the fields.", what, "Select Save."] });
// Generic (not vendor-specific) instructions for any other DNS host.
const otherDns = (what) => ({ id: "dns-other", label: "Other DNS host", possible: true, steps: ["Open the DNS settings wherever the domain's DNS is hosted (often the registrar).", what, "Every host's screens differ: if you can't find it, ask that host's support."] });
const m365Mx = { id: "microsoft-365", label: "Microsoft 365", possible: true, steps: ["In the Microsoft 365 admin center, go to Settings → Domains, select the domain and choose Manage DNS to see the records Microsoft expects.", "The MX record points at <domain-key>.mail.protection.outlook.com. Copy the exact value from the admin center, and delete any other MX records so mail only goes to Microsoft."] };
const googleMx = { id: "google-workspace", label: "Google Workspace", possible: true, steps: ["Remove the old MX records, then add one MX record: host @ (or blank), value smtp.google.com, priority 1.", "Domains set up before 2023 may use older values starting with aspmx; those still appear in Google's instructions.", "Some DNS hosts want a trailing dot (smtp.google.com.)."] };

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
    sources: [S.icannErrp, S.icannErrpGuide, S.godaddyAutoRenew, S.namecheapBulk, S.cfRenew],
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
    sources: [S.icannEpp, S.rfc5731, S.rfc8056, S.godaddyLock, S.namecheapLock, S.cfTransferOut],
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
    risk: "Changing nameservers can take the website and email offline if the new DNS host doesn't have all the records. Before switching, copy every record (export the zone) and check the new host has them. If DNSSEC is on, turn it off at the registrar before replacing nameservers.",
    platforms: [
      ...reg.nameservers,
      { ...CF_DNS, steps: ["Cloudflare's assigned nameservers are shown on the zone's Overview page.", "At the registrar, remove the existing nameservers and add Cloudflare's, copied exactly.", "Allow up to 24 hours for the registrar to update them."] },
    ],
    message: "Hi,\n\nOur IT provider checked {domain} and found a nameserver problem: {finding}\n\nDetails: {detail}\n\nCould you please make sure the domain lists at least two working nameservers from the current DNS host, and remove any old or broken ones?" + MSG_END,
    verify: "Run the Domain Health check again: every nameserver should show as authoritative.",
    sources: [S.rfc1034, S.rfc2182, S.rfc1912, S.rfc8499, S.godaddyNameservers, S.namecheapNameservers, S.cfNameservers],
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
      { ...CF_DNS, possible: "partial", steps: ["Cloudflare creates the SOA record itself (only Enterprise accounts can change its values). A serial mismatch usually means the domain also lists another provider's nameservers: remove those at the registrar."] },
      { id: "dns-other", label: "Other DNS host", possible: "partial", steps: ["The SOA record is managed by the DNS host. Send the message below to its support."] },
    ],
    message: "Hi,\n\nOur IT provider checked {domain} and found: {finding}\n\nDetails: {detail}\n\nCould you please check the zone on all of the domain's nameservers?" + MSG_END,
    verify: "Run the Domain Health check again: all nameservers should report the same SOA serial.",
    sources: [S.rfc1912, S.rfc2308, S.cfRecordTypes],
    variants: { missing: { why: "The domain has no SOA record, which every DNS zone needs. The zone may be set up wrongly at the DNS host." } },
  },
  dnssec: {
    tool: "domain",
    why: "DNSSEC is switched on at the registry but the DNS host isn't signing the zone. Resolvers that check DNSSEC may refuse to look the domain up at all.",
    difficulty: "advanced",
    time: "30 minutes, plus a day or two for caches",
    risk: "Removing or changing DS records has a delay: resolvers cache them for their TTL. The quickest safe fix is usually to remove the DS record at the registrar, wait for its TTL, and turn DNSSEC on again properly later.",
    platforms: [
      ...regAsk("removing the DS (DNSSEC) record").map((p) => (p.id === "cloudflare-registrar" ? { ...p, possible: true, steps: ["If the DNS is also on Cloudflare: activate DNSSEC in Cloudflare and it publishes the DS record for you (CDS/CDNSKEY scanning can take one to two days).", "Otherwise disable DNSSEC for the domain so the DS record is removed."] } : p)),
      { ...CF_DNS, steps: ["To keep DNSSEC: activate DNSSEC in Cloudflare and add the DS record it gives you at the registrar.", "To remove it: remove the DS record at the registrar first, and keep zone signing on in Cloudflare until the old DS has expired from caches."] },
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
      cfEdit("broken MX"),
      otherDns("Find the broken MX record and correct or delete it."),
      m365Mx,
      googleMx,
    ],
    message: "Hi,\n\nOur IT provider checked {domain} and found a broken mail (MX) record.\n\nDetails: {detail}\n\nCould you please correct or remove it so every MX record points at a working, public mail server?" + MSG_END,
    verify: "Run the Domain Health check again, and send a test email to an address at {domain}.",
    sources: [S.rfc5321, S.rfc7505, S.cfDnsRecords, S.m365Dns, S.googleMx],
  },
  "email-auth": {
    tool: "domain",
    why: "Without SPF and DMARC it's easy for someone to send email that looks like it came from this domain. The Email Security Check shows the exact records to add.",
    difficulty: "moderate",
    time: "30 minutes, then a few weeks of monitoring",
    risk: "SPF and DMARC can block real email if they leave out a service that sends for you. Use the Email Security Check and the Fix Plan, which start DMARC in monitoring mode.",
    platforms: [
      cfAdd("Add the TXT records from the Email Security Check / Fix Plan (SPF on the domain itself, DMARC on _dmarc)."),
      otherDns("Add the TXT records from the Email Security Check / Fix Plan."),
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
      cfEdit("CNAME (the name listed in the details)"),
      otherDns("Find the CNAME record for the name listed in the details and delete it."),
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
  "cloudflare-registrar": "Cloudflare Registrar",
  "dns-cloudflare": "Cloudflare DNS",
  "dns-other": "Other DNS host",
  "microsoft-365": "Microsoft 365",
  "google-workspace": "Google Workspace",
};
