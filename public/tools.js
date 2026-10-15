// The technician tools registry: the one list of tools. The /tools dashboard cards (dashboard.js)
// and the header's Tools menu on every tool page (generated from this list by scripts/site-chrome.js,
// then checked by test/branding.test.js) both come from here, so a new tool is added in one place.
// Pure data, no DOM: Node imports it too.
//
// - href: where the tool lives. To move a tool, change it here and run `node scripts/sync-chrome.js`.
// - status: "live" tools appear on the dashboard and in the Tools menu; "soon" tools only on the
//   dashboard, as "Coming soon" cards, never in the menu.
// - category: the menu group, one of CATEGORIES (in that order).
// - feature: (optional) a switch from lib/features.js. A "live" tool with a feature shows as
//   "Coming soon" on the dashboard and in the menu until the signed-in session reports it's on.
// - icon: a symbol id in /assets/icons.svg.
// - admin: (optional) only for admins (lib/admin.js). Hidden on the dashboard and in the menu unless
//   the signed-in session is an admin; its API refuses non-admins either way.

export const CATEGORIES = ["Email", "Web", "Domain", "Office", "Admin"];

export const TOOLS = [
  { id: "email-security", category: "Email", icon: "mail", name: "Email Security Check", blurb: "Email platform, SPF, DMARC, DKIM, domain registration and website certificate, from public records.", href: "/tools/email", status: "live" },
  { id: "domain-health", category: "Domain", icon: "domain", name: "Domain Health", blurb: "Renewal date, transfer lock, nameservers, SOA, MX, CAA, DNSSEC and dangling CNAMEs, from public DNS and RDAP.", href: "/tools/domain", status: "live" },
  { id: "website-security", category: "Web", icon: "globe-lock", name: "Website Security Check", blurb: "HTTPS, certificate, security headers, cookies, mixed content and WordPress version, from one passive homepage visit.", href: "/tools/website", status: "live" },
  { id: "breach-check", category: "Email", icon: "lock", name: "Breach Check", blurb: "Breached addresses on a client's verified domain (XposedOrNot) and a private password check (Have I Been Pwned).", href: "/tools/breach", status: "live", feature: "breachCheck" },
  { id: "exposed-services", category: "Web", icon: "dns", name: "Exposed Services", blurb: "Internet-facing services a business may not know it's running.", href: null, status: "soon" },
  { id: "backup-checklist", category: "Office", icon: "checklist", name: "Backup Checklist", blurb: "A guided walkthrough of what's backed up, where, and whether restores work.", href: null, status: "soon" },
  { id: "account-security", category: "Office", icon: "lock", name: "Account Security Checklist", blurb: "MFA, admin accounts, shared passwords and offboarding.", href: null, status: "soon" },
  { id: "device-inventory", category: "Office", icon: "report", name: "Device Inventory", blurb: "Computers, phones and network gear, with update and warranty status.", href: null, status: "soon" },
  { id: "phishing-quiz", category: "Office", icon: "mail-shield", name: "Phishing Quiz", blurb: "A short quiz to help staff spot fake emails.", href: null, status: "soon" },
  { id: "pricing-sheet", category: "Admin", icon: "report", name: "Pricing sheet", blurb: "Current prices and offers, straight from the price settings. Admin only; never shown to clients.", href: "/tools/pricing", status: "live", admin: true },
];
