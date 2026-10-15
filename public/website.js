// Website Security Check (/tools/website). Renders GET /api/website output. Everything in the report
// comes from the client's website (headers, cookie names, URLs), so it's inserted with textContent
// through h(), never innerHTML.
import { $, h, api, showError, initGate } from "./tech-session.js";

const STATUS_LABEL = { pass: "Good", warn: "Needs attention", fail: "At risk", unknown: "Couldn't verify", info: "FYI" };
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

function checkCard(c) {
  return h("article", { class: "check", "data-status": c.status },
    h("div", { class: "check-head" }, h("span", { class: "status", "data-status": c.status }, STATUS_LABEL[c.status] || c.status), h("h4", { class: "check-title" }, c.title)),
    h("p", { class: "check-summary" }, c.summary),
    c.fix && (c.status === "fail" || c.status === "warn") ? h("p", { class: "check-summary" }, h("strong", {}, "Fix: "), c.fix) : null,
    c.detail ? h("details", { class: "check-details" }, h("summary", {}, "Technical details"), h("code", { class: "check-raw" }, c.detail)) : null,
  );
}

function render(r) {
  const root = $("website-report");
  const pills = ["fail", "warn", "pass", "unknown"].filter((s) => r.counts[s]).map((s) => h("span", { class: "pill", "data-status": s }, `${r.counts[s]} ${STATUS_LABEL[s]}`));
  const meta = [r.score !== null ? `Score ${r.score}/100` : null, r.coverage < 100 && r.score !== null ? `based on ${r.coverage}% of checks` : null, r.finalUrl ? `Final page: ${r.finalUrl}` : null].filter(Boolean).join(" · ");
  const path = (hops) => hops.map((x) => `${x.status} ${x.url}`).join(" → ");
  const stopped = r.redirects.stopped && (r.redirects.stopped.https || r.redirects.stopped.http);

  // replaceChildren would print null as text, so empty sections are filtered out first.
  const parts = [
    h("div", { class: "summary-card" },
      h("div", { class: "grade", "data-grade": r.grade || "none", "aria-label": "Overall grade" }, r.grade || "–"),
      h("div", { class: "summary-text" },
        h("p", { class: "summary-domain" }, r.target),
        h("h2", {}, headline(r)),
        h("p", { class: "summary-meta" }, meta),
        h("div", { class: "pills" }, pills),
      ),
      h("div", { class: "summary-actions no-print" }, h("button", { type: "button", class: "btn-ghost", onclick: () => window.print() }, "Save as PDF")),
    ),
    r.data && r.data.cappedBy ? h("p", { class: "grade-cap" }, `Grade capped at ${r.data.cappedBy[0].maxGrade} because ${r.data.cappedBy.map((c) => c.reason).join("; ")}.`) : null,
    r.redirects.https.length ? h("p", { class: "redirect-path" }, "HTTPS: ", h("code", {}, path(r.redirects.https))) : null,
    r.redirects.http.length ? h("p", { class: "redirect-path" }, "HTTP: ", h("code", {}, path(r.redirects.http))) : null,
    stopped ? h("p", { class: "redirect-path" }, stopped.offsite ? "Off-site redirect (not followed): " : "Not followed: ", h("code", {}, stopped.offsite ? stopped.location || "" : `${stopped.location || ""} (${stopped.reason})`)) : null,
    r.unverified.length ? h("p", { class: "redirect-path" }, `Couldn't verify: ${r.unverified.map((u) => u.title).join(", ")}. These are left out of the score.`) : null,
    ...CATEGORY_ORDER.map((cat) => {
      const checks = r.checks.filter((c) => c.category === cat);
      if (!checks.length) return null;
      return h("section", { class: "category" }, h("h3", {}, cat), h("p", { class: "category-blurb" }, CATEGORY_BLURB[cat]), h("div", { class: "check-grid" }, checks.map(checkCard)));
    }),
    r.fixes.length ? h("section", { class: "fix-card" }, h("h3", {}, "What to fix"), h("ol", {}, r.fixes.map((f) => h("li", {}, h("strong", {}, `${f.title}: `), f.fix)))) : null,
    h("p", { class: "report-foot" }, `Checked ${new Date(r.scannedAt).toLocaleString()} in ${(r.durationMs / 1000).toFixed(1)}s. Based on one visit to the homepage; other pages may differ.`),
  ];
  root.replaceChildren(...parts.filter(Boolean));
  root.hidden = false;
}

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
