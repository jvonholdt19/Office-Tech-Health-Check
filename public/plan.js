// Fix Plan Builder (private). Renders /api/plan output as a client proposal and a
// technician checklist. All text is inserted with textContent, never innerHTML, because
// DNS records come from the prospect's domain and must be treated as untrusted.
import { showSignedInChrome, checkSession, rememberSession } from "./tech-session.js";

const $ = (id) => document.getElementById(id);

/** Tiny element builder: h("p", { class: "x" }, "text", child, ...) */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const money = (n) => `$${Number(n).toLocaleString("en-US")}`;

// Founding client offer (first three clients): shown in the client plan only when the technician ticks
// it for this plan. Off by default, and reset to off for every new plan.
let showFoundingOffer = false;
const fmtDate = (iso) => new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

// Technician access is a server-side session: the code is sent once to /api/session, which sets an
// HttpOnly cookie. Nothing secret is kept in the page or in browser storage.
async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== "/api/session") {
    unlockUI(false);
    showError("gate-error", "Your session has ended. Sign in again.");
  }
  return { res, body: json };
}

function showError(id, msg) {
  $(id).textContent = msg || "";
  $(id).hidden = !msg;
}

function unlockUI(on) {
  $("gate").hidden = on;
  $("builder").hidden = !on;
  $("lock-btn").hidden = !on;
  showSignedInChrome(on);
  if (on) $("domain").focus();
}

/* ------------------------------------------------------------------ */
/* Client view                                                          */
/* ------------------------------------------------------------------ */

function gradeChip(grade) {
  return h("div", { class: "grade-chip", "data-grade": grade || "none" }, grade || "?");
}

function renderClient(plan) {
  const b = plan.business;
  const root = $("client-view");
  root.replaceChildren();

  root.append(
    h("div", { class: "doc-head" },
      h("div", {}, h("div", { class: "doc-brand" }, b.name), h("div", { class: "muted" }, b.fullName)),
      h("div", { class: "doc-meta" }, h("div", {}, `Prepared ${fmtDate(plan.preparedAt)}`), h("div", {}, b.contactEmail)),
    ),
    h("h2", {}, `Office Tech Fix Plan for ${plan.domain}`),
  );

  // What the plan can't fix on its own, in plain English (see projectGrade in lib/plan.js).
  const limits = plan.projected?.limitedBy || [];
  const limitsList = () => h("ul", { class: "grade-limits" }, limits.map((l) => h("li", {}, l.reason)));

  if (plan.nothingToFix && limits.length) {
    root.append(
      h("p", {}, `There's nothing we can fix straight away, but the health check graded ${plan.domain} ${plan.current.grade ?? "low"}. These need a conversation with you first:`),
      limitsList(),
    );
  } else if (plan.nothingToFix) {
    root.append(
      h("p", {}, "Good news: the health check didn't find anything that needs fixing right now."),
      plan.verifyItems.length ? h("p", { class: "muted" }, "A few items couldn't be confirmed from outside. We can verify them with you in a short call.") : null,
    );
  } else {
    root.append(
      h("div", { class: "grade-shift" },
        gradeChip(plan.current.grade), h("span", { class: "arrow" }, "→"), gradeChip(plan.projected.grade),
        h("div", { class: "grade-caption" }, `Today: ${plan.current.grade ?? "not graded"}${plan.current.score != null ? ` (${plan.current.score}/100)` : ""}. After these fixes: ${plan.projected.grade} (${plan.projected.score}/100).`),
      ),
      limits.length ? h("p", { class: "grade-limits-title" }, plan.projected.grade === "A" ? "Still to confirm with you:" : `Still capped at ${plan.projected.grade} because:`) : null,
      limits.length ? limitsList() : null,
      h("p", {}, `We found ${plan.items.length} thing${plan.items.length === 1 ? "" : "s"} to fix. None of them require new hardware or software, and your team can keep working normally throughout. Here's exactly what we'll do, in order.`),
    );

    root.append(h("h3", {}, "What we'll fix"));
    for (const phase of plan.phases) {
      root.append(h("div", { class: "phase-label" }, `Step ${phase.id}: ${phase.name} · ${phase.when}`));
      for (const id of phase.items) {
        const it = plan.items.find((x) => x.id === id);
        root.append(
          h("div", { class: "fix-item" },
            h("div", { class: "fix-item-head" }, h("h4", {}, it.title)),
            h("p", { class: "why" }, it.clientWhy),
            h("p", { class: "change" }, it.clientChange),
          ),
        );
      }
    }

    // Investment: one flat package for every fix above (prices come from lib/config.js via the plan).
    const p = plan.pricing;
    root.append(h("h3", {}, "Investment"));
    root.append(
      h("div", { class: "packages" },
        p.packages.map((pk) =>
          h("div", { class: "package", "data-recommended": String(pk.recommended) },
            h("div", { class: "package-head" },
              h("h4", {}, pk.name),
              pk.recommended ? h("span", { class: "package-tag" }, "Recommended for you") : null,
              h("span", { class: "price" }, pk.label),
            ),
            h("p", { class: "package-scope" }, pk.scope),
            h("p", { class: "muted" }, pk.blurb),
          ),
        ),
      ),
    );
    if (p.recommended?.reasons?.length) {
      root.append(h("p", { class: "muted" }, `Why ${p.recommended.name}: ${p.recommended.reasons.join(" ")}`));
    }
    root.append(h("p", { class: "muted" }, "One-time fee for the whole business. Includes checking every fix with a follow-up health check."));

    // Founding offer: only when the technician turned it on for this plan (off by default).
    if (p.founding && showFoundingOffer) {
      const f = p.founding;
      root.append(
        h("div", { class: "callout founding-offer" },
          h("div", { class: "founding-label" }, `${f.name} · first ${f.limit} clients only`),
          h("p", {}, h("strong", {}, `${f.packageName} fix for ${f.label}`), ` (usually ${f.regularLabel})`, f.bonus ? `, plus ${f.bonus.name} free for the first year (usually ${f.bonus.regularLabel}).` : "."),
          h("p", { class: "muted" }, f.terms),
        ),
      );
    }

    // Timeline
    root.append(
      h("h3", {}, "Timeline"),
      h("p", {}, plan.items.some((i) => i.id === "dmarc")
        ? "Most fixes are completed in a single session. Impersonation protection starts in monitoring mode, and we switch it fully on after 2–4 weeks once we've confirmed all of your real email passes. That way nothing legitimate gets blocked."
        : "All fixes can be completed in a single session."),
    );

    // What we need
    if (plan.accessNeeded.length) {
      root.append(h("h3", {}, "What we'll need from you"), h("ul", {}, plan.accessNeeded.map((a) => h("li", {}, a))));
      root.append(h("p", { class: "muted" }, "We'll walk you through granting access. We never ask you to send passwords by email."));
    }
  }

  if (plan.verifyItems.length && !plan.nothingToFix) {
    root.append(h("h3", {}, "We'll also confirm"), h("ul", {}, plan.verifyItems.map((v) => h("li", {}, v.title))), h("p", { class: "muted" }, "These can't be seen from outside, so we check them together at no extra cost."));
  }

  if (plan.quoteItems.length) {
    root.append(h("h3", {}, "Recommended next project"));
    for (const q of plan.quoteItems) {
      root.append(h("div", { class: "fix-item" }, h("div", { class: "fix-item-head" }, h("h4", {}, q.title), h("span", { class: "price" }, `from ${money(q.from)}`)), h("p", { class: "why" }, q.clientWhy)));
    }
  }

  if (plan.pricing.recurring.length) {
    root.append(
      h("h3", {}, "Keep it that way (optional)"),
      h("div", { class: "recurring" },
        plan.pricing.recurring.map((r) =>
          h("div", { class: "callout recurring-option", "data-period": r.period },
            h("div", { class: "package-head" }, h("h4", {}, r.name), h("span", { class: "price" }, r.label)),
            h("p", { class: "muted" }, r.blurb),
          ),
        ),
      ),
      h("p", { class: "muted" }, "One flat fee for the whole business, not per person."),
    );
  }

  root.append(
    h("div", { class: "next-step no-print" },
      h("div", {}, h("strong", {}, "Ready to get this fixed?"), h("div", { class: "muted" }, "Book a quick call and we'll schedule the work.")),
      h("a", { class: "btn-primary", href: b.bookingUrl, target: "_blank", rel: "noopener" }, "Book a call"),
    ),
    h("p", { class: "muted" }, `Questions? ${b.contactEmail}`),
  );
}

/* ------------------------------------------------------------------ */
/* Technician view                                                      */
/* ------------------------------------------------------------------ */

// Copy buttons stay locked until the technician confirms the change set (typed domain) and the
// server has verified and logged that confirmation. Only server-confirmed values unlock.
const locked = []; // { el, value }
let confirmedValues = null; // Set of values the server returned from /api/plan/confirm

function lockable(el, value) {
  const ok = confirmedValues && (value === null || confirmedValues.has(value));
  el.disabled = !ok;
  if (!ok) el.title = "Review the changes and press Confirm changes first";
  locked.push({ el, value });
  return el;
}

function unlockConfirmed(values) {
  confirmedValues = new Set(values);
  for (const { el, value } of locked) {
    if (value === null || confirmedValues.has(value)) {
      el.disabled = false;
      el.removeAttribute("title");
    }
  }
}

function copyButton(text) {
  return lockable(h("button", {
    type: "button",
    class: "btn-ghost copy-btn",
    onclick: async (e) => {
      try {
        await navigator.clipboard.writeText(text);
        e.target.textContent = "Copied";
      } catch {
        e.target.textContent = "Select & copy";
      }
      setTimeout(() => (e.target.textContent = "Copy value"), 1500);
    },
  }, "Copy value"), text);
}

function checklist(steps) {
  return h("ul", { class: "checklist" }, steps.map((s) => {
    const li = h("li", {});
    const box = h("input", { type: "checkbox", onchange: () => li.classList.toggle("done", box.checked) });
    li.append(box, h("span", {}, s));
    return li;
  }));
}

function renderTech(plan, report) {
  const root = $("tech-view");
  root.replaceChildren();
  root.append(
    h("div", { class: "doc-head" },
      h("div", {}, h("div", { class: "doc-brand" }, `${plan.business.name} · Technician checklist`), h("h2", {}, plan.domain)),
      h("div", { class: "doc-meta" }, h("div", {}, `Scanned ${new Date(plan.preparedAt).toLocaleString()}`), h("div", {}, `Estimated hands-on time: ${plan.effort.hours} h`)),
    ),
    h("div", { class: "facts" },
      h("div", { class: "fact" }, h("div", { class: "k" }, "Email platform"), h("div", { class: "v" }, plan.provider.name)),
      h("div", { class: "fact" }, h("div", { class: "k" }, "DNS host"), h("div", { class: "v" }, plan.dnsHost.name)),
      h("div", { class: "fact" }, h("div", { class: "k" }, "Nameservers"), h("div", { class: "v" }, (plan.dnsHost.nameservers || []).join(", ") || "n/a")),
      h("div", { class: "fact" }, h("div", { class: "k" }, "Registrar"), h("div", { class: "v" }, plan.registrar || "Unknown")),
      h("div", { class: "fact" }, h("div", { class: "k" }, "Grade now → target"), h("div", { class: "v" }, `${plan.current.grade ?? "–"} (${plan.current.score ?? "–"}) → ${plan.projected.grade ?? "–"} (${plan.projected.score ?? "–"})`)),
      h("div", { class: "fact" }, h("div", { class: "k" }, "Quote"), h("div", { class: "v" }, plan.pricing.recommended ? `${plan.pricing.recommended.name} ${plan.pricing.recommended.label}${plan.pricing.founding ? ` (founding offer, if used: ${plan.pricing.founding.label})` : ""}` : "Nothing to fix")),
    ),
    h("p", { class: "muted" }, `Add DNS records at: ${plan.dnsHost.where}`),
  );

  if (plan.safety?.problems?.length) {
    root.append(h("div", { class: "safety bad" }, h("b", {}, "Safety check found problems. Read before changing anything:"), h("ul", {}, plan.safety.problems.map((p) => h("li", {}, p)))));
  } else if (plan.safety?.checked && plan.items.some((it) => it.records?.some((r) => /^v=spf1/i.test(r.value || "")))) {
    root.append(h("div", { class: "safety ok" }, "✓ Safety check passed: every proposed SPF record was resolved against live DNS, every include is valid, and it stays within the 10-lookup limit."));
  }
  if (plan.accessNeeded.length) root.append(h("h3", {}, "Before you start: access"), checklist(plan.accessNeeded));
  if (plan.items.some((it) => it.records?.length)) {
    root.append(h("h3", {}, "Before you change any DNS"), checklist([
      `Take a screenshot or export of the whole DNS zone for ${plan.domain} at ${plan.dnsHost.name}. That is your full undo.`,
      "Make one change at a time and test before the next. Never change SPF and DMARC policy on the same day.",
      "Do the work early in a business day, so the client can report problems while you can still fix them.",
    ]));
  }

  for (const it of plan.items) {
    const task = h("section", { class: "task" },
      h("h4", {}, `${it.step}. ${it.title} `, h("span", { class: "est" }, `· ~${it.minutes} min · fixes: ${it.fixes.join(", ")}`)),
    );
    if (it.found?.length) task.append(h("div", { class: "sub" }, "Found now"), h("ul", { class: "found" }, it.found.map((f) => h("li", {}, f))));
    if (it.settings?.length) {
      task.append(
        h("div", { class: "sub" }, "Change"),
        h("table", { class: "change-table" },
          h("thead", {}, h("tr", {}, h("th", {}, "Setting"), h("th", {}, "Now"), h("th", {}, "Change to"))),
          h("tbody", {}, it.settings.map((s) => h("tr", {}, h("td", {}, s.what), h("td", { class: "now" }, s.now), h("td", { class: "to" }, s.to)))),
        ),
      );
    }
    if (it.records.length) task.append(h("div", { class: "sub" }, `DNS records${it.records.some((r) => r.zone) ? "" : ` (at ${plan.dnsHost.name})`}`));
    for (const r of it.records) {
      const value = r.generated
        ? h("div", { class: "record-value generated" }, h("em", {}, r.value))
        : h("div", { class: "record-value" }, h("code", {}, r.value), r.action === "Delete" || r.blocked ? null : copyButton(r.value));
      task.append(
        h("div", { class: "record", "data-action": r.action, "data-blocked": r.blocked ? "true" : null },
          h("div", { class: "record-head" },
            h("span", {}, h("span", { class: "action" }, r.action), "  Type ", h("b", {}, r.type), "  Name/Host ", h("b", {}, r.name), r.zone ? h("span", {}, "  on ", h("b", {}, r.zone)) : null, "  TTL ", h("b", {}, r.ttl)),
            r.note ? h("span", { class: "record-note" }, r.note) : null,
          ),
          r.current ? h("div", { class: "record-value current" }, h("span", { class: "lbl" }, "Now"), h("code", {}, r.current)) : null,
          r.current ? h("div", { class: "record-value" }, h("span", { class: "lbl" }, "New"), h("code", {}, r.value), r.blocked ? null : copyButton(r.value)) : value,
          r.lookupText ? h("div", { class: "record-check" }, r.blocked === true ? `✗ Checked live: ${r.lookupText} DNS lookups (limit 10), ${r.voids ?? "?"} void (limit 2)` : r.blocked === "unverified" ? `? Checked live: ${r.lookupText} DNS lookups so far; not every lookup could be resolved` : `✓ Checked live: ${r.lookupText} of 10 DNS lookups, ${r.voids} of 2 void`) : null,
        ),
      );
    }
    task.append(h("div", { class: "sub" }, "Steps"), checklist(it.steps));
    task.append(h("p", { class: "verify" }, h("b", {}, "Verify: "), it.verify));
    if (it.rollback) task.append(h("p", { class: "rollback" }, h("b", {}, "If something goes wrong: "), it.rollback));
    if (it.followUp) task.append(h("p", { class: "verify" }, h("b", {}, "Follow-up: "), it.followUp));
    root.append(task);
  }

  if (plan.verifyItems.length) {
    root.append(h("h3", {}, "Confirm at kickoff"));
    for (const v of plan.verifyItems) root.append(h("section", { class: "task" }, h("h4", {}, v.title), checklist(v.steps)));
  }

  root.append(
    h("h3", {}, "Close out"),
    checklist([
      "Re-run the health check and save the after report for the client.",
      "Send the client the before/after grades.",
      "Record registrar, DNS host, email admin and renewal dates in the client's runbook.",
    ]),
    h("p", {}, h("a", { href: `/tools/email?d=${encodeURIComponent(plan.domain)}`, target: "_blank", rel: "noopener" }, "Open the Email Security Check for this domain →")),
  );

  // Raw findings for reference
  const raw = h("details", {}, h("summary", {}, "Raw scan findings"));
  for (const c of report.checks) raw.append(h("p", {}, h("strong", {}, `${c.title}: ${c.status}`), " ", h("code", {}, c.detail || "")));
  root.append(raw);
}

/* ------------------------------------------------------------------ */
/* Change review: before | after diff, guards, confirmation             */
/* ------------------------------------------------------------------ */

let lastBuild = null; // { domain, zone, confirmExport, body } for the plan on screen

const isSpf = (v) => /^v=spf1(\s|$)/i.test(String(v));
const isDmarcValue = (v) => /^v=DMARC1/i.test(String(v).trim());
const spfParts = (v) => String(v).trim().split(/\s+/);
const dmarcParts = (v) => String(v).split(";").map((t) => t.trim()).filter(Boolean);

/** One value, split into terms (SPF) or tags (DMARC), with the ones missing on the other side marked. */
function diffValue(value, otherValues, side) {
  const split = isSpf(value) ? spfParts : isDmarcValue(value) ? dmarcParts : null;
  if (!split) {
    const changed = !otherValues.includes(value);
    return h("div", { class: `diff-value${changed ? (side === "before" ? " removed" : " added") : ""}` }, h("code", {}, value));
  }
  // DMARC report lists (rua=a,b) are compared address by address, so a kept address isn't shown as removed.
  const listTag = (t) => (split === dmarcParts ? t.match(/^(rua|ruf)\s*=\s*(.*)$/i) : null);
  const tokens = (t) => {
    const m = listTag(t);
    return m ? m[2].split(",").map((a) => `${m[1].toLowerCase()}=${a.trim().toLowerCase()}`) : [t.toLowerCase()];
  };
  const other = new Set(otherValues.filter((v) => (split === spfParts ? isSpf(v) : isDmarcValue(v))).flatMap((v) => split(v).flatMap(tokens)));
  const cls = (changed) => `term${changed ? (side === "before" ? " removed" : " added") : ""}`;
  const sep = split === spfParts ? " " : "; ";
  const parts = split(value);
  return h("div", { class: "diff-value" }, h("code", {}, parts.flatMap((t, i) => {
    const m = listTag(t);
    const el = m
      ? h("span", {}, `${m[1]}=`, m[2].split(",").flatMap((a, j, all) => {
          const span = h("span", { class: cls(!other.has(`${m[1].toLowerCase()}=${a.trim().toLowerCase()}`)) }, a.trim());
          return j < all.length - 1 ? [span, ","] : [span];
        }))
      : h("span", { class: cls(!other.has(t.toLowerCase())) }, t);
    return i < parts.length - 1 ? [el, sep] : [el];
  })));
}

function diffEntry(e) {
  const side = (values, other, which) =>
    h("div", { class: `diff-col ${which}` },
      h("div", { class: "diff-label" }, which === "before" ? "Before" : "After"),
      values.length ? values.map((v) => diffValue(v, other, which)) : h("div", { class: "diff-empty" }, "(nothing)"),
    );
  return h("div", { class: "diff-entry", "data-blocked": e.blocked ? String(e.blocked) : null },
    h("div", { class: "diff-head" },
      h("span", { class: "action" }, e.action), " ", h("b", {}, e.type), " ", h("code", {}, e.name),
      h("span", { class: "muted" }, ` · ${e.reason}`),
    ),
    e.blocked ? h("div", { class: "diff-blocked" }, e.blocked === "unverified" ? `Unverified: ${e.blockedReason}` : `Blocked: ${e.blockedReason}`) : null,
    h("div", { class: "diff-cols" }, side(e.before, e.after, "before"), side(e.after, e.before, "after")),
    e.changes?.some((c) => c.op !== "keep")
      ? h("ul", { class: "diff-changes" }, e.changes.filter((c) => c.op !== "keep").map((c) => h("li", { class: `op-${c.op}` }, `${c.op}: ${c.term}. ${c.reason}`)))
      : null,
  );
}

function renderChangeReview(body) {
  const { changeSet = [], guards, simulation } = body;
  const domain = body.plan.domain;
  const box = h("section", { class: "review-panel" }, h("h3", {}, "Review the changes"));
  if (!changeSet.length) {
    box.append(h("p", { class: "muted" }, "No DNS records change in this plan."));
    return box;
  }
  box.append(h("p", { class: "muted" }, `${guards.recordsTouched} record${guards.recordsTouched === 1 ? "" : "s"} change. Added terms are green, removed terms are red and struck through. Nothing is written to DNS by this tool: you enter the values at ${body.plan.dnsHost.name} yourself.`));

  const hardBlocked = guards.blocked === true || guards.blocked === "too-broad";
  if (guards.blocked) {
    box.append(h("div", { class: "safety bad" }, h("b", {}, guards.blocked === "upload-mismatch" ? "Waiting on you: the upload doesn't match live DNS." : guards.blocked === "too-broad" ? "Blocked: the change set is too broad." : "Blocked by the safety guards:"), h("ul", {}, guards.reasons.map((r) => h("li", {}, r)))));
  } else {
    box.append(h("div", { class: "safety ok" }, "✓ Guards passed: no MX, NS, SOA, website, verification or DKIM records are removed; one SPF and one DMARC record; every existing SPF term is kept unless its removal is listed with a reason."));
  }
  for (const w of guards.warnings || []) box.append(h("div", { class: "safety bad" }, w));
  for (const e of changeSet) box.append(diffEntry(e));

  const status = h("p", { class: "muted", role: "status" });
  const canConfirm = !guards.blocked && simulation?.verdict !== "blocked";
  const btn = h("button", { type: "button", class: "btn-primary", disabled: canConfirm ? null : true, onclick: () => openConfirm(body, status) }, "Confirm changes");
  box.append(h("div", { class: "review-actions no-print" }, btn, status));
  box.append(h("p", { class: "muted small" }, "Confirming unlocks the day-one values only. Later DMARC stages stay locked: build and confirm the plan again when it's time for each stage."));
  if (!canConfirm) status.textContent = hardBlocked || simulation?.verdict === "blocked" ? "Resolve the blocked items, then build the plan again." : "Confirm the export first (Client DNS records panel).";
  return box;
}

function openConfirm(body, status) {
  const domain = body.plan.domain;
  const risky = body.changeSet.filter((e) => e.action !== "add");
  const unverified = body.changeSet.filter((e) => e.blocked === "unverified");
  const typed = h("input", { type: "text", autocomplete: "off", spellcheck: "false", placeholder: domain, "aria-label": "Type the domain name to confirm" });
  const override = unverified.length ? h("input", { type: "checkbox", id: "override-unverified" }) : null;
  const err = h("p", { class: "form-error", role: "alert", hidden: true });
  const go = h("button", { type: "submit", class: "btn-primary" }, "Confirm and unlock values");
  const dialog = h("dialog", { class: "confirm-dialog" },
    h("form", { method: "dialog" },
      h("h3", {}, `Confirm changes for ${domain}`),
      risky.length
        ? h("div", {}, h("p", {}, "These records are replaced or deleted:"), h("ul", {}, risky.map((e) => h("li", {}, `${e.action.toUpperCase()} ${e.type} ${e.name}: ${e.before.join(" | ") || "(nothing)"} → ${e.after.join(" | ") || "(nothing)"}`))))
        : h("p", {}, "Only new records are added. Nothing existing is replaced or deleted."),
      unverified.length ? h("label", { class: "check-row" }, override, ` I checked ${unverified.map((e) => `${e.type} ${e.name}`).join(", ")} by hand (lookup count couldn't be verified live)`) : null,
      h("label", {}, `Type ${domain} to confirm`, typed),
      err,
      h("div", { class: "review-actions" }, go, h("button", { type: "button", class: "btn-ghost", onclick: () => dialog.close() }, "Cancel")),
    ),
  );
  dialog.querySelector("form").addEventListener("submit", async (e) => {
    e.preventDefault();
    err.hidden = true;
    if (typed.value.trim().toLowerCase() !== domain) {
      err.textContent = `Type ${domain} exactly.`;
      err.hidden = false;
      return;
    }
    if (override && !override.checked) {
      err.textContent = "Tick the box once you've checked the unverified record by hand.";
      err.hidden = false;
      return;
    }
    go.disabled = true;
    try {
      const { res, body: out } = await api("/api/plan/confirm", {
        method: "POST",
        body: {
          domain, typedDomain: typed.value.trim(), changeSetHash: body.changeSetHash,
          ...(lastBuild?.zone ? { zone: lastBuild.zone } : {}),
          ...(lastBuild?.confirmExport ? { confirmExport: lastBuild.confirmExport } : {}),
          ...(override ? { overrideUnverified: override.checked } : {}),
        },
      });
      if (!res.ok) throw new Error(out.error || "Couldn't confirm.");
      unlockConfirmed(out.values.map((v) => v.value));
      status.textContent = `✓ Confirmed and logged. ${out.values.length} value${out.values.length === 1 ? "" : "s"} unlocked for copying. Nothing has been changed in DNS.`;
      dialog.close();
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
    } finally {
      go.disabled = false;
    }
  });
  dialog.addEventListener("close", () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
  typed.focus();
}

/* ------------------------------------------------------------------ */
/* Client DNS records (zone upload)                                     */
/* ------------------------------------------------------------------ */

let zoneUpload = null; // { text, filename } while a client's records are loaded; kept in memory only

function setZone(z) {
  zoneUpload = z;
  $("zone-chip").hidden = !z;
  $("zone-clear").hidden = !z;
  $("zone-chip").textContent = z ? `Using records from ${z.filename || "pasted text"} (${Math.max(1, Math.round(z.text.length / 1024))} KB)` : "";
  $("plan-btn").textContent = z ? "Build plan from these records" : "Build fix plan";
}

$("zone-file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  e.target.value = "";
  if (!f) return;
  if (f.size > 2_000_000) return showError("plan-error", "That file is larger than 2 MB. Export only the one domain's zone.");
  showError("plan-error", "");
  setZone({ text: await f.text(), filename: f.name });
  $("zone-paste").hidden = true;
});
$("zone-paste-btn").addEventListener("click", () => {
  $("zone-paste").hidden = !$("zone-paste").hidden;
  if (!$("zone-paste").hidden) $("zone-text").focus();
});
$("zone-paste-use").addEventListener("click", () => {
  const t = $("zone-text").value;
  if (!t.trim()) return;
  setZone({ text: t, filename: "" });
  $("zone-text").value = "";
  $("zone-paste").hidden = true;
});
$("zone-clear").addEventListener("click", () => setZone(null));

function recordTable(rows) {
  return h("table", { class: "change-table zone-table" },
    h("thead", {}, h("tr", {}, h("th", {}, "What"), h("th", {}, "Name"), h("th", {}, "Type"), h("th", {}, "Value"))),
    h("tbody", {}, rows.map((r) => h("tr", {}, h("td", {}, r.role), h("td", {}, h("code", {}, r.name)), h("td", {}, r.type), h("td", {}, h("code", { class: "wrap" }, r.value))))),
  );
}

function renderZone(zone, domain) {
  const inv = zone.inventory;
  const box = h("section", { class: "zone-panel" },
    h("h3", {}, "Client DNS records"),
    h("p", { class: "muted" }, `${zone.filename || "Pasted records"} · ${inv.total} records · ${zone.format === "bind" ? "zone file" : zone.format === "csv" ? "CSV" : "Route 53 JSON"}. This plan and dry run were built from these records, not just public DNS.`),
  );
  if (zone.warnings?.length) box.append(h("ul", { class: "found" }, zone.warnings.map((w) => h("li", {}, w))));
  const mismatches = (zone.differences || []).filter((d) => d.match === false);
  if (mismatches.length) {
    box.append(h("div", { class: "safety bad" },
      h("b", {}, "The file doesn't match live DNS. Re-export before making changes, or check the domain's DNS is really hosted where this file came from:"),
      h("ul", {}, mismatches.map((d) => h("li", {}, `${d.label}: file has ${d.file.length ? d.file.join(" | ") : "nothing"}; live has ${d.live?.length ? d.live.join(" | ") : "nothing"}`))),
    ));
    if (!lastBuild?.confirmExport) {
      const tick = h("input", { type: "checkbox" });
      const again = h("button", { type: "button", class: "btn-ghost", disabled: true, onclick: () => buildPlan(domain, { confirmExport: { sha256: zone.sha256 } }) }, "Rebuild with this confirmation");
      tick.addEventListener("change", () => (again.disabled = !tick.checked));
      box.append(h("div", { class: "no-print review-actions" }, h("label", { class: "check-row" }, tick, " I confirm the export is current"), again));
    } else {
      box.append(h("p", { class: "muted" }, "You confirmed this export is current."));
    }
  } else if ((zone.differences || []).length && zone.differences.every((d) => d.match === null)) {
    box.append(h("div", { class: "safety bad" }, "Live DNS couldn't be reached, so the file wasn't compared with what's published. Build the plan again in a minute."));
  } else if ((zone.differences || []).some((d) => d.match === true)) {
    box.append(h("div", { class: "safety ok" }, "✓ The email records in the file match live public DNS."));
  }
  if (inv.email.length) box.append(h("div", { class: "sub" }, "Email"), recordTable(inv.email));
  if (inv.website.length) box.append(h("div", { class: "sub" }, "Website"), recordTable(inv.website));
  if (inv.verification.length) box.append(h("div", { class: "sub" }, "Other TXT at the main domain"), recordTable(inv.verification));
  box.append(h("p", { class: "muted" }, `All record types in the file: ${Object.entries(inv.counts).map(([t, n]) => `${t} ${n}`).join(", ")}`));
  return box;
}

/* ------------------------------------------------------------------ */
/* Dry run                                                              */
/* ------------------------------------------------------------------ */

const STATUS_TEXT = { pass: "Good", warn: "Needs attention", fail: "At risk", unknown: "Couldn't verify", info: "FYI" };
const CHANGE_TEXT = { applied: "Day one", assumed: "Day one (value from platform)", later: "Later stage", blocked: "Blocked", conflict: "Conflict", "not-simulated": "Not simulated" };

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderSimulation(sim, domain, zone) {
  const root = $("sim-view");
  root.replaceChildren();
  $("sim-badge").textContent = sim ? (sim.verdict === "safe" ? "✓" : "!") : "";
  $("sim-badge").dataset.verdict = sim?.verdict || "";
  if (!sim) return;
  const safe = sim.verdict === "safe";
  const check = sim.verdict === "check";
  root.append(
    h("div", { class: "doc-head" },
      h("div", {}, h("div", { class: "doc-brand" }, "Dry run · day-one changes"), h("h2", {}, domain)),
      h("div", { class: "doc-meta" }, h("div", {}, sim.mode === "zone" ? `From ${zone?.filename || "uploaded records"}` : "From public DNS (upload the client's records for a full check)")),
    ),
    h("div", { class: `verdict ${safe ? "ok" : check ? "check" : "bad"}` },
      h("div", { class: "verdict-title" }, safe ? "✓ Safe to apply" : check ? "! Check before applying" : "✗ Blocked: don't make these changes yet"),
      h("div", {}, safe
        ? "Every day-one change was applied to a copy of the records and every check was re-run. Nothing gets worse, SPF stays within limits with every include valid, and no website, mail-server or verification records are touched."
        : check
          ? "Nothing failed, but not everything could be confirmed. Resolve the points below before making changes."
          : "The dry run found problems. Fix these first, then build the plan again."),
      sim.blockers.length ? h("ul", {}, sim.blockers.map((b) => h("li", {}, b))) : null,
      check ? h("ul", {}, sim.warnings.map((w) => h("li", {}, w))) : null,
    ),
    h("div", { class: "grade-move" },
      h("div", {}, h("div", { class: "k" }, "Now"), h("div", { class: "v" }, `${sim.before.grade ?? "–"}`), h("div", { class: "s" }, sim.before.score ?? "–")),
      h("div", { class: "arrow" }, "→"),
      h("div", {}, h("div", { class: "k" }, "After day one"), h("div", { class: "v" }, `${sim.after.grade ?? "–"}`), h("div", { class: "s" }, sim.after.score ?? "–")),
    ),
    h("p", { class: "muted" }, "Day one is SPF, DKIM and DMARC in monitor-only mode. The grade reaches its target after the later DMARC stages, once reports confirm every sender passes."),
  );
  if (sim.warnings.length && !check) root.append(h("div", { class: "safety bad" }, h("ul", {}, sim.warnings.map((w) => h("li", {}, w)))));
  if (sim.assumptions.length) root.append(h("div", { class: "sub" }, "Assumptions"), h("ul", { class: "found" }, sim.assumptions.map((a) => h("li", {}, a))));

  root.append(
    h("h3", {}, "Checks before and after"),
    h("table", { class: "change-table" },
      h("thead", {}, h("tr", {}, h("th", {}, "Check"), h("th", {}, "Now"), h("th", {}, "After day one"))),
      h("tbody", {}, sim.comparisons.map((c) => h("tr", { "data-delta": String(c.delta) },
        h("td", {}, c.title),
        h("td", {}, STATUS_TEXT[c.before] || c.before),
        h("td", { class: c.delta > 0 ? "to" : c.delta < 0 ? "now" : "" }, `${STATUS_TEXT[c.after] || c.after}${c.delta > 0 ? " ▲" : c.delta < 0 ? " ▼" : ""}`),
      ))),
    ),
  );

  const dayOne = sim.changes.filter((c) => c.status === "applied" || c.status === "assumed");
  const liveCells = new Map();
  root.append(
    h("h3", {}, "DNS changes"),
    h("table", { class: "change-table changes" },
      h("thead", {}, h("tr", {}, h("th", {}, "When"), h("th", {}, "Action"), h("th", {}, "Record"), h("th", {}, "Value"), h("th", {}, "Live"))),
      h("tbody", {}, sim.changes.map((c) => {
        const live = h("td", { class: "live" }, dayOne.includes(c) ? "–" : "");
        if (dayOne.includes(c)) liveCells.set(c, live);
        return h("tr", { "data-status": c.status },
          h("td", {}, CHANGE_TEXT[c.status] || c.status),
          h("td", {}, c.action),
          h("td", {}, h("code", {}, `${c.type} ${c.name}`)),
          h("td", {},
            c.from && c.action !== "Delete" ? h("div", { class: "from" }, h("code", { class: "wrap" }, c.from)) : null,
            c.action === "Delete" ? h("div", { class: "from" }, h("code", { class: "wrap" }, c.from)) : h("div", {}, h("code", { class: "wrap" }, c.status === "assumed" ? "(generated by the email platform)" : c.to)),
            c.note && c.status !== "applied" ? h("div", { class: "muted small" }, c.note) : null,
          ),
          live,
        );
      })),
    ),
  );

  const verifyMsg = h("p", { class: "muted", id: "verify-msg" });
  const verifyBtn = h("button", { type: "button", class: "btn-ghost", disabled: dayOne.length ? null : true }, "Verify live");
  verifyBtn.addEventListener("click", async () => {
    verifyBtn.disabled = true;
    verifyMsg.textContent = "Checking public DNS…";
    try {
      const { res, body } = await api("/api/verify", {
        method: "POST",
        body: { domain, changes: dayOne.map(({ action, type, name, from, to, status }) => ({ action, type, name, from, to, status })) },
      });
      if (!res.ok) throw new Error(body.error || "Couldn't verify.");
      body.results.forEach((r, i) => {
        const cell = liveCells.get(dayOne[i]);
        if (!cell) return;
        cell.replaceChildren(h("span", { class: `live-${r.live}` }, r.live === "done" ? "✓ Live" : r.live === "pending" ? "Not yet" : r.live === "skipped" ? "Check by hand" : "Error"), r.note ? h("div", { class: "muted small" }, r.note) : null);
      });
      verifyMsg.textContent = body.allDone
        ? "✓ Every day-one change is live. Re-run the health check and send the test emails from the checklist."
        : "Some changes aren't live yet. DNS changes can take a few minutes (up to the record's TTL) to appear. Check again shortly.";
    } catch (err) {
      verifyMsg.textContent = err.message;
    } finally {
      verifyBtn.disabled = false;
    }
  });

  root.append(
    h("div", { class: "sim-actions no-print" },
      safe && dayOne.length ? lockable(h("button", { type: "button", class: "btn-ghost", onclick: () => download(`${domain}-day-one-changes.txt`, sim.export.zone, "text/plain") }, "Download changes (zone format)"), null) : h("button", { type: "button", class: "btn-ghost", disabled: true }, "Download changes (zone format)"),
      safe && dayOne.length ? lockable(h("button", { type: "button", class: "btn-ghost", onclick: () => download(`${domain}-day-one-changes.csv`, sim.export.csv, "text/csv") }, "Download changes (CSV)"), null) : h("button", { type: "button", class: "btn-ghost", disabled: true }, "Download changes (CSV)"),
      verifyBtn,
    ),
    verifyMsg,
    h("p", { class: "muted small" }, "The downloads contain only the day-one changes, never a full zone, and unlock after you confirm the changes on the Technician checklist. Don't use your DNS host's \"replace zone\" import with them."),
  );
}

/* ------------------------------------------------------------------ */
/* Wiring                                                               */
/* ------------------------------------------------------------------ */

async function buildPlan(domain, opts = {}) {
  showError("plan-error", "");
  $("plan-output").hidden = true;
  $("plan-loading").hidden = false;
  $("plan-btn").disabled = true;
  try {
    const { res, body } = zoneUpload
      ? await api("/api/plan", { method: "POST", body: { domain, zone: zoneUpload, ...(opts.confirmExport ? { confirmExport: opts.confirmExport } : {}) } })
      : await api(`/api/plan?domain=${encodeURIComponent(domain)}`);
    if (res.status === 401) return;
    if (!res.ok) throw new Error(body.error || "Something went wrong.");
    lastBuild = { domain: body.plan.domain, zone: zoneUpload, confirmExport: opts.confirmExport || null, body };
    locked.length = 0;
    confirmedValues = null;
    showFoundingOffer = false;
    $("founding-toggle").checked = false;
    $("founding-row").hidden = !body.plan.pricing.founding;
    renderClient(body.plan);
    renderTech(body.plan, body.report);
    $("tech-view").prepend(renderChangeReview(body));
    if (body.zone) $("tech-view").prepend(renderZone(body.zone, body.plan.domain));
    renderSimulation(body.simulation, body.plan.domain, body.zone);
    $("domain").value = body.plan.domain;
    const url = new URL(location.href);
    url.searchParams.set("d", body.plan.domain);
    history.replaceState(null, "", url);
    $("plan-output").hidden = false;
  } catch (err) {
    showError("plan-error", err.message);
  } finally {
    $("plan-loading").hidden = true;
    $("plan-btn").disabled = false;
  }
}

$("gate-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = $("access-code").value;
  $("access-code").value = "";
  showError("gate-error", "");
  try {
    const { res, body } = await api("/api/session", { method: "POST", body: { code } });
    if (!res.ok) return showError("gate-error", body.error || "Couldn't sign in.");
    rememberSession(body);
  } catch {
    return showError("gate-error", "Couldn't reach the server.");
  }
  unlockUI(true);
  const d = new URLSearchParams(location.search).get("d");
  if (d) buildPlan(d);
});

$("founding-toggle").addEventListener("change", (e) => {
  showFoundingOffer = e.target.checked;
  if (lastBuild) renderClient(lastBuild.body.plan);
});

$("plan-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("domain").value.trim();
  if (v) buildPlan(v);
});

$("lock-btn").addEventListener("click", async () => {
  await api("/api/session", { method: "DELETE" }).catch(() => {});
  $("plan-output").hidden = true;
  unlockUI(false);
});

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const t of document.querySelectorAll(".tab")) {
      t.classList.toggle("active", t === tab);
      t.setAttribute("aria-selected", String(t === tab));
    }
    $("client-view").hidden = tab.dataset.tab !== "client";
    $("tech-view").hidden = tab.dataset.tab !== "tech";
    $("sim-view").hidden = tab.dataset.tab !== "sim";
  });
}

$("print-btn").addEventListener("click", () => window.print());

// The page loads in the neutral "checking your sign-in" state (see checkSession in tech-session.js).
checkSession({
  apiFn: api,
  onError: (msg) => showError("gate-error", msg),
  show: (on) => {
    unlockUI(on);
    if (!on) return;
    const d = new URLSearchParams(location.search).get("d");
    if (d) buildPlan(d);
  },
});
