// Technician tools dashboard (/tools). The cards come from the TOOLS registry below.
// Every tool lives under /tools behind the technician sign-in; the public lander is at /.
// To move a tool, change its href here; nothing else on the dashboard depends on where a tool lives.
import { $, h, initGate } from "./tech-session.js";

export const TOOLS = [
  { id: "email-security", name: "Email Security Check", blurb: "Email platform, SPF, DMARC, DKIM, domain registration and website certificate, from public records.", href: "/tools/email", status: "live" },
  { id: "domain-health", name: "Domain Health", blurb: "Renewal date, transfer lock, nameservers, SOA, MX, CAA, DNSSEC and dangling CNAMEs, from public DNS and RDAP.", href: "/tools/domain", status: "live" },
  { id: "website-security", name: "Website Security Check", blurb: "HTTPS, certificate, security headers, cookies, mixed content and WordPress version, from one passive homepage visit.", href: "/tools/website", status: "live" },
  { id: "breach-check", name: "Breach Check", blurb: "Whether the business's email addresses appear in known data breaches.", href: null, status: "soon" },
  { id: "exposed-services", name: "Exposed Services", blurb: "Internet-facing services a business may not know it's running.", href: null, status: "soon" },
  { id: "backup-checklist", name: "Backup Checklist", blurb: "A guided walkthrough of what's backed up, where, and whether restores work.", href: null, status: "soon" },
  { id: "account-security", name: "Account Security Checklist", blurb: "MFA, admin accounts, shared passwords and offboarding.", href: null, status: "soon" },
  { id: "device-inventory", name: "Device Inventory", blurb: "Computers, phones and network gear, with update and warranty status.", href: null, status: "soon" },
  { id: "phishing-quiz", name: "Phishing Quiz", blurb: "A short quiz to help staff spot fake emails.", href: null, status: "soon" },
];

function card(tool) {
  const live = tool.status === "live" && tool.href;
  const body = [
    h("div", { class: "tool-card-head" }, h("h2", {}, tool.name), live ? null : h("span", { class: "soon-tag" }, "Coming soon")),
    h("p", {}, tool.blurb),
  ];
  return live
    ? h("a", { class: "tool-card", href: tool.href, "data-tool": tool.id }, ...body)
    : h("div", { class: "tool-card disabled", "aria-disabled": "true", "data-tool": tool.id }, ...body);
}

function render() {
  $("tool-grid").replaceChildren(...TOOLS.map(card));
}

initGate({ contentId: "dashboard", onSignedIn: render });
