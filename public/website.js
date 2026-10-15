// Website Security Check (/tools/website). Renders GET /api/website output. Everything in the report
// comes from the client's website (headers, cookie names, URLs), so it's inserted with textContent
// through h(), never innerHTML.
import { $, h, api, showError, initGate } from "./tech-session.js";
import { createReportView } from "./report-view.js";

const CATEGORY_ORDER = ["Encryption", "Browser protections", "Page content", "Software"];
const CATEGORY_BLURB = {
  Encryption: "Whether visitors' connections to the site are private and the certificate is trusted.",
  "Browser protections": "Security headers that tell browsers how to protect visitors on this site.",
  "Page content": "What the homepage itself sets and loads.",
  Software: "What the site reveals about the software it runs.",
};

function headline(r) {
  if (!r.grade) return r.score === null ? "We couldn't reach this website." : "Not enough could be checked for a grade.";
  if (r.grade === "A") return "This website's security setup looks strong.";
  if (r.grade === "B") return "Good, with a few improvements to make.";
  if (r.grade === "C") return "Several website protections are missing.";
  return "This website is missing important protections.";
}

export const DISCLAIMER = "Back up your site and test changes first. Your web host or developer should apply these changes.";
const PLATFORM_NAMES = { cloudflare: "Cloudflare", wordpress: "WordPress", apache: "Apache", nginx: "Nginx", iis: "IIS (Windows)", builders: "Website builder (Wix / Squarespace / GoDaddy / Shopify)" };

const view = createReportView({
  rootId: "website-report",
  toolName: "Website Security Check",
  platformNames: PLATFORM_NAMES,
  categoryOrder: CATEGORY_ORDER,
  categoryBlurb: CATEGORY_BLURB,
  headline,
  // Saved per domain in this browser only, so a new scan of a different site starts with all platforms.
  storageKey: (domain) => `ohc-fix-platform:${domain}`,
  disclaimer: DISCLAIMER,
  messageHeading: "Message to your web host or developer",
  meta: (r) => (r.finalUrl ? `Final page: ${r.finalUrl}` : null),
  extraLines: (r) => {
    const path = (hops) => hops.map((x) => `${x.status} ${x.url}`).join(" → ");
    const stopped = r.redirects.stopped && (r.redirects.stopped.https || r.redirects.stopped.http);
    return [
      r.redirects.https.length ? h("p", { class: "redirect-path" }, "HTTPS: ", h("code", {}, path(r.redirects.https))) : null,
      r.redirects.http.length ? h("p", { class: "redirect-path" }, "HTTP: ", h("code", {}, path(r.redirects.http))) : null,
      stopped ? h("p", { class: "redirect-path" }, stopped.offsite ? "Off-site redirect (not followed): " : "Not followed: ", h("code", {}, stopped.offsite ? stopped.location || "" : `${stopped.location || ""} (${stopped.reason})`)) : null,
    ];
  },
  footNote: () => "Based on one visit to the homepage; other pages may differ.",
});
const render = (r) => view.render(r);

async function runCheck(target) {
  showError("website-error", "");
  $("website-report").hidden = true;
  $("website-loading").hidden = false;
  $("website-btn").disabled = true;
  try {
    const { res, body } = await api(`/api/website?target=${encodeURIComponent(target)}`);
    if (res.status === 401) return;
    if (!res.ok) return showError("website-error", body.error || "The check failed. Try again.");
    render(body);
    history.replaceState(null, "", `?t=${encodeURIComponent(body.target)}`);
  } catch {
    showError("website-error", "Couldn't reach the server.");
  } finally {
    $("website-loading").hidden = true;
    $("website-btn").disabled = false;
  }
}

$("website-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("target").value.trim();
  if (v) runCheck(v);
});

initGate({
  contentId: "tool",
  // ?t=acme.com only pre-fills the field. A scan never starts from a link: the technician has to
  // press "Check website" (so a crafted URL can't make a signed-in technician scan a site).
  onSignedIn: () => {
    const t = new URLSearchParams(location.search).get("t");
    if (t && !$("target").value) $("target").value = t.slice(0, 2048);
    $("target").focus();
  },
  onSignedOut: () => ($("website-report").hidden = true),
});
