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

// =====================================================================
// PRICES (approved by Josh, Oct 15 2026). This file is the only place prices live: the Fix Plan
// page and the client plan read them from here. Flat fees per business, never per user.
// =====================================================================

// One-time fix packages. A plan lists the fixes a client needs (no per-fix prices), recommends the
// package that fits and shows both. Plus is recommended when the scan finds extra sending services
// or messy records (see packageFit in lib/plan.js); otherwise Standard.
export const PACKAGES = [
  {
    id: "standard",
    name: "Standard",
    price: 350,
    scope: "One domain and one email provider",
    blurb: "Every fix in this plan for one domain and one email provider, done and checked with a follow-up health check.",
  },
  {
    id: "plus",
    name: "Plus",
    price: 550,
    scope: "Extra sending services or messy records",
    blurb: "Everything in Standard, plus finding and approving every other service that sends email for you (newsletters, invoicing, website forms) and cleaning up duplicate or broken records.",
  },
];

// Bigger projects the plan can recommend but doesn't price exactly (quoted separately).
export const QUOTE_ITEMS = {
  "email-migration": { title: "Move email to Google Workspace or Microsoft 365", from: 1500 },
};

// Optional ongoing care offered at the end of every plan: one flat fee per business, not per user.
// `period` is "year" or "month" and is shown with the price. Set to [] to hide.
export const RECURRING_OPTIONS = [
  {
    id: "quarterly-checkups",
    name: "Quarterly Checkups",
    price: 150,
    period: "year",
    blurb: "A full health check of your email, domain and website every three months, with a plain-English report of anything that changed and what to do about it.",
  },
  {
    id: "monthly-watch",
    name: "Monthly Watch",
    price: 35,
    period: "month",
    blurb: "A health check every month, and a heads-up as soon as something important changes, such as a domain or certificate about to expire or a change that weakens your email protection.",
  },
];

// Founding offer for the first 3 clients only. It never shows unless the technician ticks
// "Show the founding client offer" on the Fix Plan page for that plan (off by default).
// Set to null to remove it entirely.
export const FOUNDING_OFFER = {
  name: "Founding client offer",
  limit: 3,
  packageId: "standard",
  price: 210,
  bonusRecurringId: "quarterly-checkups", // a free first year of this recurring option
  terms: "For our first 3 clients only, in exchange for a short written testimonial and permission to use your business name.",
};
