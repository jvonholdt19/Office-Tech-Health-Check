// Technician tools dashboard (/tools). The cards come from the TOOLS registry below.
// To move a tool (e.g. the email scanner, today at "/") under /tools later, change its href here;
// nothing else on the dashboard depends on where a tool lives.
import { $, h, initGate } from "./tech-session.js";

export const TOOLS = [
  { id: "email-domain", name: "Email & Domain Health Check", blurb: "SPF, DMARC, DKIM, domain registration and certificate, from public records. The public scanner.", href: "/", status: "live" },
  { id: "website-security", name: "Website Security Check", blurb: "HTTPS, certificate, security headers, cookies, mixed content and WordPress version, from one passive homepage visit.", href: "/tools/website", status: "live" },
  { id: "domain-health", name: "Domain Health", blurb: "Registrar, renewals, nameservers and DNSSEC in one place.", href: null, status: "soon" },
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
