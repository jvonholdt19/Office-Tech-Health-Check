// Shared report rendering for the technician check tools (Website Security Check, Domain Health):
// summary card, grade-cap line, check cards with "How to fix" guides, Copy buttons, the per-domain
// "Platform for this client" picker, the "What to fix" list, and print handling. Everything goes
// through h() / textContent, never innerHTML, because report text comes from the checked site/domain.
import { disclaimerBlock } from "./legal.js";
import { $, h } from "./tech-session.js";

export const STATUS_LABEL = { pass: "Good", warn: "Needs attention", fail: "At risk", unknown: "Couldn't verify", info: "FYI" };
const DIFFICULTY_LABEL = { easy: "Easy", moderate: "Moderate", advanced: "Advanced" };
const POSSIBLE_LABEL = { true: "Possible", partial: "Partly possible", false: "Usually not possible" };
const SEVERITY = { fail: 0, warn: 1 };

/**
 * Copy `text` to the clipboard and say so on the button. Without clipboard access (http://, old
 * browsers, denied permission) the text in `fallbackEl` is selected so Ctrl+C / Cmd+C works.
 */
export function copyButton(label, text, fallbackEl) {
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

/**
 * Build a renderer for one tool. Options:
 *   rootId, toolName, platformNames {id: label}, categoryOrder, categoryBlurb, headline(r),
 *   storageKey(domain), disclaimer, messageHeading, meta(r) → extra summary text,
 *   extraLines(r) → nodes shown under the summary, footNote(r) → string.
 */
export function createReportView(opts) {
  const { rootId, toolName, platformNames, categoryOrder, categoryBlurb, headline, storageKey, disclaimer, messageHeading } = opts;
  let platformChoice = "";
  let reportDomain = "";

  function loadPlatformChoice(domain) {
    reportDomain = domain;
    try {
      platformChoice = localStorage.getItem(storageKey(domain)) || "";
    } catch {
      platformChoice = "";
    }
    if (!platformNames[platformChoice]) platformChoice = "";
  }

  function guideBlock(c) {
    const g = c.guide;
    const message = h("pre", { class: "message" }, g.message);
    return h("details", { class: "fix-guide", id: `fix-${c.id}` },
      h("summary", {}, "How to fix"),
      g.risk ? h("div", { class: "risk", role: "note" }, h("strong", {}, "Before you change anything: "), g.risk) : null,
      g.note ? h("p", { class: "guide-note" }, h("strong", {}, "Good to know: "), g.note) : null,
      h("div", { class: "platforms" }, g.platforms.map(platformSection)),
      h("div", { class: "message-block" }, h("h5", {}, messageHeading), message, copyButton("Copy message", g.message, message)),
      h("p", { class: "verify" }, h("strong", {}, "How to confirm it's fixed: "), g.verify),
      g.sources && g.sources.length
        ? h("p", { class: "sources" }, "Sources: ", g.sources.flatMap((u, i) => [i ? ", " : null, h("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, new URL(u).hostname + new URL(u).pathname.replace(/\/$/, ""))]))
        : null,
    );
  }

  function checkCard(c) {
    const flagged = c.status === "fail" || c.status === "warn";
    const g = flagged ? c.guide : null;
    const link = c.data && c.data.link && /^\/tools\//.test(c.data.link.href) ? c.data.link : null;
    return h("article", { class: "check", id: `check-${c.id}`, "data-status": c.status },
      h("div", { class: "check-head" },
        h("span", { class: "status", "data-status": c.status }, STATUS_LABEL[c.status] || c.status),
        h("h4", { class: "check-title" }, c.title),
        g ? h("span", { class: "badge", "data-difficulty": g.difficulty }, `${DIFFICULTY_LABEL[g.difficulty] || g.difficulty} · ${g.time}`) : null,
      ),
      h("p", { class: "check-summary" }, c.summary),
      g ? h("p", { class: "why" }, h("strong", {}, "Why it matters: "), g.why) : null,
      c.fix && flagged ? h("p", { class: "check-summary" }, h("strong", {}, "Fix: "), c.fix) : null,
      link ? h("p", { class: "check-summary no-print" }, h("a", { href: link.href }, `${link.text} →`)) : null,
      g ? guideBlock(c) : null,
      c.detail ? h("details", { class: "check-details" }, h("summary", {}, "Technical details"), h("code", { class: "check-raw" }, c.detail)) : null,
    );
  }

  /** Show only the chosen platform (first), or all of them in their usual order. */
  function applyPlatformFilter() {
    for (const container of document.querySelectorAll(`#${rootId} .platforms`)) {
      const sections = [...container.querySelectorAll(".platform")];
      for (const sec of sections) sec.hidden = Boolean(platformChoice) && sec.dataset.platform !== platformChoice;
      const chosen = sections.find((sec) => sec.dataset.platform === platformChoice);
      if (chosen) {
        container.prepend(chosen);
        chosen.open = true;
      }
    }
    const label = $("print-platform");
    if (label) label.textContent = platformChoice ? `Platform: ${platformNames[platformChoice]}` : "";
  }

  function platformPicker() {
    const select = h("select", { id: "platform-select" },
      h("option", { value: "" }, "All platforms"),
      Object.entries(platformNames).map(([id, name]) => h("option", { value: id }, name)),
    );
    select.value = platformChoice;
    select.addEventListener("change", () => {
      platformChoice = select.value;
      try {
        if (platformChoice) localStorage.setItem(storageKey(reportDomain), platformChoice);
        else localStorage.removeItem(storageKey(reportDomain));
      } catch {}
      applyPlatformFilter();
    });
    return h("div", { class: "platform-picker no-print" }, h("label", { for: "platform-select" }, "Platform for this client: "), select);
  }

  // Printing: open every guide (and the platforms that are showing) so the PDF has the full steps,
  // then put the page back. Hooked up on the first report. Accumulate rather than reset: Chrome can
  // fire beforeprint twice before one afterprint.
  let reopened = [];
  let printHooked = false;
  function hookPrint() {
    if (printHooked) return;
    printHooked = true;
    window.addEventListener("beforeprint", () => {
      for (const d of document.querySelectorAll(`#${rootId} .fix-guide, #${rootId} .platform:not([hidden])`)) {
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

  function render(r) {
    const root = $(rootId);
    const target = r.target || r.domain;
    const pills = ["fail", "warn", "pass", "unknown"].filter((s) => r.counts[s]).map((s) => h("span", { class: "pill", "data-status": s }, `${r.counts[s]} ${STATUS_LABEL[s]}`));
    const meta = [r.score !== null ? `Score ${r.score}/100` : null, r.coverage < 100 && r.score !== null ? `based on ${r.coverage}% of checks` : null, opts.meta ? opts.meta(r) : null].filter(Boolean).join(" · ");

    loadPlatformChoice(target);
    const byId = Object.fromEntries(r.checks.map((c) => [c.id, c]));
    // Only mention a cap when it actually lowered the grade (an F site capped "at C" isn't capped).
    const caps = r.data && r.data.cappedBy && r.data.uncappedGrade !== r.grade ? r.data.cappedBy : null;
    const fixes = [...r.fixes].sort((a, b) => (SEVERITY[a.status] ?? 2) - (SEVERITY[b.status] ?? 2) || (byId[b.id]?.weight || 0) - (byId[a.id]?.weight || 0));

    // replaceChildren would print null as text, so empty sections are filtered out first.
    const parts = [
      h("div", { class: "print-header" },
        h("p", { class: "print-title" }, `${toolName}: ${target}`),
        h("p", {}, `${new Date(r.scannedAt).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })} · Grade ${r.grade || "not graded"}${r.score !== null ? ` (${r.score}/100)` : ""} · Prepared by Office Tech`),
        h("p", { id: "print-platform" }),
      ),
      // Shown on screen and in print, straight after the print header.
      h("p", { class: "disclaimer", role: "note" }, disclaimer),
      h("div", { class: "summary-card" },
        h("div", { class: "grade", "data-grade": r.grade || "none", "aria-label": "Overall grade" }, r.grade || "–"),
        h("div", { class: "summary-text" },
          h("p", { class: "summary-domain" }, target),
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
      ...(opts.extraLines ? opts.extraLines(r) : []),
      r.unverified.length ? h("p", { class: "redirect-path" }, `Couldn't verify: ${r.unverified.map((u) => u.title).join(", ")}. These are left out of the score.`) : null,
      ...categoryOrder.map((cat) => {
        const checks = r.checks.filter((c) => c.category === cat);
        if (!checks.length) return null;
        return h("section", { class: "category" }, h("h3", {}, cat), h("p", { class: "category-blurb" }, categoryBlurb[cat] || ""), h("div", { class: "check-grid" }, checks.map(checkCard)));
      }),
      fixes.length
        ? h("section", { class: "fix-card" }, h("h3", {}, "What to fix"), h("ol", {}, fixes.map((f) => h("li", {}, h("strong", {}, guideLink(f.id, Boolean(byId[f.id]?.guide), f.title), ": "), f.fix))))
        : null,
      disclaimerBlock(),
      h("p", { class: "report-foot" }, `Checked ${new Date(r.scannedAt).toLocaleString()} in ${(r.durationMs / 1000).toFixed(1)}s. ${opts.footNote ? opts.footNote(r) : ""}`.trim()),
    ];
    root.replaceChildren(...parts.filter(Boolean));
    root.hidden = false;
    applyPlatformFilter();
    hookPrint();
  }

  return { render };
}
