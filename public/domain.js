// Domain Health (/tools/domain). Renders GET /api/domain output with the shared report view.
// Record values come from public DNS and RDAP, so everything goes in through textContent.
import { $, api, showError, initGate } from "./tech-session.js";
import { createReportView } from "./report-view.js";

const CATEGORY_ORDER = ["Registration", "DNS", "Email"];
const CATEGORY_BLURB = {
  Registration: "Who holds the domain, when it renews, and whether it's locked against transfers.",
  DNS: "The nameservers and records that point the domain at its website and services.",
  Email: "Whether the domain can receive email and publishes the basic anti-spoofing records.",
};
// Registrars and DNS hosts the guides cover.
const PLATFORM_NAMES = {
  godaddy: "GoDaddy",
  namecheap: "Namecheap",
  "cloudflare-registrar": "Cloudflare Registrar",
  "dns-cloudflare": "Cloudflare DNS",
  "dns-other": "Other DNS host",
  "microsoft-365": "Microsoft 365",
  "google-workspace": "Google Workspace",
};

export const DISCLAIMER = "Back up your DNS records and test changes first. Your registrar, DNS host or IT provider should apply these changes.";

function headline(r) {
  if (!r.grade) return r.score === null ? "We couldn't read this domain's records." : "Not enough could be checked for a grade.";
  if (r.grade === "A") return "This domain's registration and DNS look healthy.";
  if (r.grade === "B") return "Healthy, with a few things to tidy up.";
  if (r.grade === "C") return "Several domain and DNS settings need attention.";
  return "This domain has problems that can take the website or email down.";
}

const view = createReportView({
  rootId: "domain-report",
  toolName: "Domain Health",
  platformNames: PLATFORM_NAMES,
  categoryOrder: CATEGORY_ORDER,
  categoryBlurb: CATEGORY_BLURB,
  headline,
  storageKey: (domain) => `ohc-domain-platform:${domain}`,
  disclaimer: DISCLAIMER,
  messageHeading: "Message to your registrar or DNS host",
  footNote: () => "Based on public DNS and registry (RDAP) data at the time of the check.",
});

async function runCheck(domain) {
  showError("domain-error", "");
  $("domain-report").hidden = true;
  $("domain-loading").hidden = false;
  $("domain-btn").disabled = true;
  try {
    const { res, body } = await api(`/api/domain?domain=${encodeURIComponent(domain)}`);
    if (res.status === 401) return;
    if (!res.ok) return showError("domain-error", body.error || "The check failed. Try again.");
    view.render(body);
    history.replaceState(null, "", `?d=${encodeURIComponent(body.domain)}`);
  } catch {
    showError("domain-error", "Couldn't reach the server.");
  } finally {
    $("domain-loading").hidden = true;
    $("domain-btn").disabled = false;
  }
}

$("domain-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("target").value.trim();
  if (v) runCheck(v);
});

initGate({
  contentId: "tool",
  // ?d=acme.com only pre-fills the field; a check runs when the technician presses "Check domain".
  onSignedIn: () => {
    const d = new URLSearchParams(location.search).get("d");
    if (d && !$("target").value) $("target").value = d.slice(0, 253);
    $("target").focus();
  },
  onSignedOut: () => ($("domain-report").hidden = true),
});
