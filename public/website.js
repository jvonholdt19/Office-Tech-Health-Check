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

const DIFFICULTY_LABEL = { easy: "Easy", moderate: "Moderate", advanced: "Advanced" };
const POSSIBLE_LABEL = { true: "Possible", partial: "Partly possible", false: "Usually not possible" };
const PLATFORM_KEY = "ohc-fix-platform";

// Which platform the technician picked for this client ("" = all). Kept per browser for convenience only.
let platformChoice = "";
try {
  platformChoice = localStorage.getItem(PLATFORM_KEY) || "";
} catch {}

/**
 * Copy `text` to the clipboard and say so on the button. Without clipboard access (http://, old
 * browsers, denied permission) the text in `fallbackEl` is selected so Ctrl+C / Cmd+C works.
 */
function copyButton(label, text, fallbackEl) {
  const btn = h("button", { type: "button", class: "btn-ghost copy-btn no-print" }, label);
  const flash = (msg) => {
    btn.textContent = msg;
    setTimeout(() => (btn.textContent = label), 2000);
  };
  btn.addEventListener("click", async () => {
    try {
      if (!navigator.clipboard) throw new Error("no clipboard");
      await navigator.clipboard.writeText(text);
      flash("Copied");
    } catch {
      const range = document.createRange();
      range.selectNodeContents(fallbackEl);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      flash("Selected: press Ctrl+C");
    }
  });
  return btn;
}

function snippetBlock(snippet) {
  const code = h("code", {}, snippet.code);
  const pre = h("pre", { class: "snippet", "data-lang": snippet.lang || "" }, code);
  return h("div", { class: "snippet-wrap" }, pre, copyButton("Copy", snippet.code, code));
}

function platformSection(p) {
  return h("details", { class: "platform", "data-platform": p.id },
    h("summary", {}, h("span", { class: "platform-label" }, p.label), h("span", { class: "possible", "data-possible": String(p.possible) }, POSSIBLE_LABEL[String(p.possible)] || "")),
    h("ol", { class: "steps" }, p.steps.map((step) => h("li", {}, step))),
    p.snippet ? snippetBlock(p.snippet) : null,
    p.note ? h("p", { class: "platform-note" }, p.note) : null,
  );
}

function guideBlock(c) {
  const g = c.guide;
  const message = h("pre", { class: "message" }, g.message);
  return h("details", { class: "fix-guide", id: `fix-${c.id}` },
    h("summary", {}, "How to fix"),
    g.risk ? h("div", { class: "risk", role: "note" }, h("strong", {}, "Before you change anything: "), g.risk) : null,
    h("div", { class: "platforms" }, g.platforms.map(platformSection)),
    h("div", { class: "message-block" },
      h("h5", {}, "Message to your web host or developer"),
      message,
      copyButton("Copy message", g.message, message),
    ),
    h("p", { class: "verify" }, h("strong", {}, "How to confirm it's fixed: "), g.verify),
    g.sources && g.sources.length
      ? h("p", { class: "sources" }, "Sources: ", g.sources.flatMap((u, i) => [i ? ", " : null, h("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, new URL(u).hostname + new URL(u).pathname.replace(/\/$/, ""))]))
      : null,
  );
}

function checkCard(c) {
  const flagged = c.status === "fail" || c.status === "warn";
  const g = flagged ? c.guide : null;
  return h("article", { class: "check", id: `check-${c.id}`, "data-status": c.status },
    h("div", { class: "check-head" },
      h("span", { class: "status", "data-status": c.status }, STATUS_LABEL[c.status] || c.status),
      h("h4", { class: "check-title" }, c.title),
      g ? h("span", { class: "badge", "data-difficulty": g.difficulty }, `${DIFFICULTY_LABEL[g.difficulty] || g.difficulty} · ${g.time}`) : null,
    ),
    h("p", { class: "check-summary" }, c.summary),
    g ? h("p", { class: "why" }, h("strong", {}, "Why it matters: "), g.why) : null,
    c.fix && flagged ? h("p", { class: "check-summary" }, h("strong", {}, "Fix: "), c.fix) : null,
    g ? guideBlock(c) : null,
    c.detail ? h("details", { class: "check-details" }, h("summary", {}, "Technical details"), h("code", { class: "check-raw" }, c.detail)) : null,
  );
}

/** Show only the chosen platform (first), or all of them in their usual order. */
function applyPlatformFilter() {
  for (const container of document.querySelectorAll("#website-report .platforms")) {
    const sections = [...container.querySelectorAll(".platform")];
    for (const sec of sections) sec.hidden = Boolean(platformChoice) && sec.dataset.platform !== platformChoice;
    const chosen = sections.find((sec) => sec.dataset.platform === platformChoice);
    if (chosen) {
      container.prepend(chosen);
      chosen.open = true;
    }
  }
  const label = $("print-platform");
  if (label) label.textContent = platformChoice ? `Platform: ${PLATFORM_NAMES[platformChoice]}` : "";
}

const PLATFORM_NAMES = { cloudflare: "Cloudflare", wordpress: "WordPress", apache: "Apache", nginx: "Nginx", iis: "IIS (Windows)", builders: "Website builder (Wix / Squarespace / GoDaddy / Shopify)" };

function platformPicker() {
  const select = h("select", { id: "platform-select" },
    h("option", { value: "" }, "All platforms"),
    Object.entries(PLATFORM_NAMES).map(([id, name]) => h("option", { value: id }, name)),
  );
  select.value = platformChoice;
  select.addEventListener("change", () => {
    platformChoice = select.value;
    try {
      localStorage.setItem(PLATFORM_KEY, platformChoice);
    } catch {}
    applyPlatformFilter();
  });
  return h("div", { class: "platform-picker no-print" }, h("label", { for: "platform-select" }, "Platform for this client: "), select);
}

/** Jump to a guide and open it (used by the cap line and the "What to fix" list). */
function guideLink(id, hasGuide, text) {
  const target = hasGuide ? `fix-${id}` : `check-${id}`;
  return h("a", {
    href: `#${target}`,
    onclick: () => {
      const el = document.getElementById(target);
      if (el && el.tagName === "DETAILS") el.open = true;
    },
  }, text);
}

const SEVERITY = { fail: 0, warn: 1 };

function render(r) {
  const root = $("website-report");
  const pills = ["fail", "warn", "pass", "unknown"].filter((s) => r.counts[s]).map((s) => h("span", { class: "pill", "data-status": s }, `${r.counts[s]} ${STATUS_LABEL[s]}`));
  const meta = [r.score !== null ? `Score ${r.score}/100` : null, r.coverage < 100 && r.score !== null ? `based on ${r.coverage}% of checks` : null, r.finalUrl ? `Final page: ${r.finalUrl}` : null].filter(Boolean).join(" · ");
  const path = (hops) => hops.map((x) => `${x.status} ${x.url}`).join(" → ");
  const stopped = r.redirects.stopped && (r.redirects.stopped.https || r.redirects.stopped.http);

  const byId = Object.fromEntries(r.checks.map((c) => [c.id, c]));
  // Only mention a cap when it actually lowered the grade (an F site capped "at C" isn't capped).
  const caps = r.data && r.data.cappedBy && r.data.uncappedGrade !== r.grade ? r.data.cappedBy : null;
  const fixes = [...r.fixes].sort((a, b) => (SEVERITY[a.status] ?? 2) - (SEVERITY[b.status] ?? 2) || (byId[b.id]?.weight || 0) - (byId[a.id]?.weight || 0));

  // replaceChildren would print null as text, so empty sections are filtered out first.
  const parts = [
    h("div", { class: "print-header" },
      h("p", { class: "print-title" }, `Website Security Check: ${r.target}`),
      h("p", {}, `${new Date(r.scannedAt).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })} · Grade ${r.grade || "not graded"}${r.score !== null ? ` (${r.score}/100)` : ""} · Prepared by Office Tech`),
      h("p", { id: "print-platform" }),
    ),
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
    caps
      ? h("p", { class: "grade-cap" }, `Grade capped at ${caps[0].maxGrade} because `, caps.flatMap((c, i) => [i ? "; " : null, guideLink(c.check, Boolean(byId[c.check]?.guide), c.reason)]), ".")
      : null,
    r.checks.some((c) => c.guide) ? platformPicker() : null,
    r.redirects.https.length ? h("p", { class: "redirect-path" }, "HTTPS: ", h("code", {}, path(r.redirects.https))) : null,
    r.redirects.http.length ? h("p", { class: "redirect-path" }, "HTTP: ", h("code", {}, path(r.redirects.http))) : null,
    stopped ? h("p", { class: "redirect-path" }, stopped.offsite ? "Off-site redirect (not followed): " : "Not followed: ", h("code", {}, stopped.offsite ? stopped.location || "" : `${stopped.location || ""} (${stopped.reason})`)) : null,
    r.unverified.length ? h("p", { class: "redirect-path" }, `Couldn't verify: ${r.unverified.map((u) => u.title).join(", ")}. These are left out of the score.`) : null,
    ...CATEGORY_ORDER.map((cat) => {
      const checks = r.checks.filter((c) => c.category === cat);
      if (!checks.length) return null;
      return h("section", { class: "category" }, h("h3", {}, cat), h("p", { class: "category-blurb" }, CATEGORY_BLURB[cat]), h("div", { class: "check-grid" }, checks.map(checkCard)));
    }),
    fixes.length
      ? h("section", { class: "fix-card" }, h("h3", {}, "What to fix"), h("ol", {}, fixes.map((f) => h("li", {}, h("strong", {}, guideLink(f.id, Boolean(byId[f.id]?.guide), f.title), ": "), f.fix))))
      : null,
    h("p", { class: "report-foot" }, `Checked ${new Date(r.scannedAt).toLocaleString()} in ${(r.durationMs / 1000).toFixed(1)}s. Based on one visit to the homepage; other pages may differ.`),
  ];
  root.replaceChildren(...parts.filter(Boolean));
  root.hidden = false;
  applyPlatformFilter();
  hookPrint();
}

// Printing: open every guide (and the platforms that are showing) so the PDF has the full steps,
// then put the page back the way it was. Hooked up on the first report, when there's something to print.
let reopened = [];
let printHooked = false;
function hookPrint() {
  if (printHooked) return;
  printHooked = true;
  // Accumulate rather than reset: Chrome can fire beforeprint twice before one afterprint.
  window.addEventListener("beforeprint", () => {
    for (const d of document.querySelectorAll("#website-report .fix-guide, #website-report .platform:not([hidden])")) {
      if (!d.open) {
        d.open = true;
        reopened.push(d);
      }
    }
  });
  window.addEventListener("afterprint", () => {
    for (const d of reopened) d.open = false;
    reopened = [];
  });
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
