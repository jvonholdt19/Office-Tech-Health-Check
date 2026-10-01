// =====================================================================
// YOUR BUSINESS SETTINGS: edit this file to change prices and branding.
// Prices are in US dollars. Nothing else needs to change.
// =====================================================================

export const BUSINESS = {
  name: "NWIM PM",
  fullName: "Northwest Iowa Marketing Project Management",
  contactEmail: "josh@nwimpm.com",
  // Paste your Cal.com link here once it's set up, e.g. "https://cal.com/nwimpm/office-tech-review"
  bookingUrl: "mailto:josh@nwimpm.com?subject=Office%20Tech%20Fix%20Plan",
  // Where DMARC reports for client domains are sent. Create this address as a Cloudflare
  // Email Routing rule, and add the one-time authorization record listed in the README.
  dmarcReportAddress: "dmarc@nwimpm.com",
};

// One price per fix. The plan adds up the fixes a client actually needs.
export const ITEM_PRICES = {
  "domain-security": 75, // auto-renew, transfer lock, ownership/2FA review at the registrar
  "domain-renewal": 50, // urgent renewal handling (added on top of domain-security)
  spf: 100, // build or repair the approved-senders record, including sender discovery
  dkim: 75, // turn on email signing in Google/Microsoft and publish the key
  dmarc: 200, // phased rollout: monitor, review reports, then enforce (about 30 days)
  ssl: 100, // fix or replace the website certificate
  "https-redirect": 50, // force all visitors onto HTTPS
};

// If the fixes add up to more than a package price, the plan offers the package instead.
export const PACKAGES = [
  {
    id: "email-domain-protection",
    name: "Email & Domain Protection Package",
    price: 450,
    covers: ["domain-security", "domain-renewal", "spf", "dkim", "dmarc", "ssl", "https-redirect"],
    blurb: "Everything on this list, fixed and verified, including 30 days of email monitoring before full enforcement.",
  },
];

// Bigger projects the plan can recommend but doesn't price exactly.
export const QUOTE_ITEMS = {
  "email-migration": { title: "Move email to Google Workspace or Microsoft 365", from: 1500 },
};

// Optional monthly service offered at the end of every plan. Set to null to hide it.
export const MONTHLY_OFFER = {
  name: "Monthly Tech Desk",
  price: 300,
  blurb: "Monthly re-scan and report, DMARC report monitoring, user adds/removals and a few hours of support. Next-business-day response.",
};
