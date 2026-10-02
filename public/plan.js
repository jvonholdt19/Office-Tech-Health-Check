// Fix Plan Builder (private). Renders /api/plan output as a client proposal and a
// technician checklist. All text is inserted with textContent, never innerHTML, because
// DNS records come from the prospect's domain and must be treated as untrusted.

const $ = (id) => document.getElementById(id);
const KEY = "ohc-plan-passcode";

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
const fmtDate = (iso) => new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

function getPass() {
  try { return sessionStorage.getItem(KEY) || ""; } catch { return ""; }
}
function setPass(v) {
  try { v ? sessionStorage.setItem(KEY, v) : sessionStorage.removeItem(KEY); } catch { /* storage unavailable: keep in memory only */ }
  memoryPass = v;
}
let memoryPass = getPass();

function showError(id, msg) {
  $(id).textContent = msg || "";
  $(id).hidden = !msg;
}

function unlockUI(on) {
  $("gate").hidden = on;
  $("builder").hidden = !on;
  $("lock-btn").hidden = !on;
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

  if (plan.nothingToFix) {
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
      h("p", {}, `We found ${plan.items.length} thing${plan.items.length === 1 ? "" : "s"} to fix. None of them require new hardware or software, and your team can keep working normally throughout. Here's exactly what we'll do, in order.`),
    );

    root.append(h("h3", {}, "What we'll fix"));
    for (const phase of plan.phases) {
      root.append(h("div", { class: "phase-label" }, `Step ${phase.id}: ${phase.name} · ${phase.when}`));
      for (const id of phase.items) {
        const it = plan.items.find((x) => x.id === id);
        root.append(
          h("div", { class: "fix-item" },
            h("div", { class: "fix-item-head" }, h("h4", {}, it.title), h("span", { class: "price" }, money(it.price))),
            h("p", { class: "why" }, it.clientWhy),
            h("p", { class: "change" }, it.clientChange),
          ),
        );
      }
    }

    // Investment
    root.append(h("h3", {}, "Investment"));
    const rows = plan.items.map((it) => h("tr", {}, h("td", {}, it.title), h("td", {}, money(it.price))));
    const p = plan.pricing;
    if (p.package) {
      rows.push(h("tr", { class: "strike" }, h("td", {}, "Total if done individually"), h("td", {}, money(p.itemsTotal))));
      rows.push(h("tr", { class: "total" }, h("td", {}, p.package.name), h("td", {}, money(p.package.price))));
    } else {
      rows.push(h("tr", { class: "total" }, h("td", {}, "Total"), h("td", {}, money(p.itemsTotal))));
    }
    root.append(h("table", { class: "price-table" }, h("tbody", {}, rows)));
    if (p.package) root.append(h("p", { class: "muted" }, `${p.package.blurb} You save ${money(p.package.savings)}.`));
    root.append(h("p", { class: "muted" }, "One-time fee. Includes verifying every fix with a follow-up health check."));

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

  if (plan.pricing.monthly) {
    const m = plan.pricing.monthly;
    root.append(h("h3", {}, "Keep it that way (optional)"), h("div", { class: "callout" }, h("strong", {}, `${m.name}: ${money(m.price)}/month. `), m.blurb));
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

function copyButton(text) {
  return h("button", {
    type: "button",
    class: "btn-ghost copy-btn",
    onclick: async (e) => {
      try {
        await navigator.clipboard.writeText(text);
        e.target.textContent = "Copied";
      } catch {
        e.target.textContent = "Select & copy";
      }
      setTimeout(() => (e.target.textContent = "Copy"), 1500);
    },
  }, "Copy");
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
      h("div", { class: "fact" }, h("div", { class: "k" }, "Quote"), h("div", { class: "v" }, money(plan.pricing.recommendedTotal))),
    ),
    h("p", { class: "muted" }, `Add DNS records at: ${plan.dnsHost.where}`),
  );

  if (plan.accessNeeded.length) root.append(h("h3", {}, "Before you start: access"), checklist(plan.accessNeeded));

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
        : h("div", { class: "record-value" }, h("code", {}, r.value), r.action === "Delete" ? null : copyButton(r.value));
      task.append(
        h("div", { class: "record", "data-action": r.action },
          h("div", { class: "record-head" },
            h("span", {}, h("span", { class: "action" }, r.action), "  Type ", h("b", {}, r.type), "  Name/Host ", h("b", {}, r.name), r.zone ? h("span", {}, "  on ", h("b", {}, r.zone)) : null, "  TTL ", h("b", {}, r.ttl)),
            r.note ? h("span", { class: "record-note" }, r.note) : null,
          ),
          r.current ? h("div", { class: "record-value current" }, h("span", { class: "lbl" }, "Now"), h("code", {}, r.current)) : null,
          r.current ? h("div", { class: "record-value" }, h("span", { class: "lbl" }, "New"), h("code", {}, r.value), copyButton(r.value)) : value,
        ),
      );
    }
    task.append(h("div", { class: "sub" }, "Steps"), checklist(it.steps));
    task.append(h("p", { class: "verify" }, h("b", {}, "Verify: "), it.verify));
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
    h("p", {}, h("a", { href: `/?d=${encodeURIComponent(plan.domain)}`, target: "_blank", rel: "noopener" }, "Open the public health check for this domain →")),
  );

  // Raw findings for reference
  const raw = h("details", {}, h("summary", {}, "Raw scan findings"));
  for (const c of report.checks) raw.append(h("p", {}, h("strong", {}, `${c.title}: ${c.status}`), " ", h("code", {}, c.detail || "")));
  root.append(raw);
}

/* ------------------------------------------------------------------ */
/* Wiring                                                               */
/* ------------------------------------------------------------------ */

async function buildPlan(domain) {
  showError("plan-error", "");
  $("plan-output").hidden = true;
  $("plan-loading").hidden = false;
  $("plan-btn").disabled = true;
  try {
    const res = await fetch(`/api/plan?domain=${encodeURIComponent(domain)}`, { headers: { "x-plan-passcode": memoryPass } });
    const body = await res.json().catch(() => ({}));
    if (res.status === 401) {
      setPass("");
      unlockUI(false);
      showError("gate-error", "Wrong passcode.");
      return;
    }
    if (!res.ok) throw new Error(body.error || "Something went wrong.");
    renderClient(body.plan);
    renderTech(body.plan, body.report);
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

$("gate-form").addEventListener("submit", (e) => {
  e.preventDefault();
  setPass($("passcode").value);
  $("passcode").value = "";
  showError("gate-error", "");
  unlockUI(true);
  const d = new URLSearchParams(location.search).get("d");
  if (d) buildPlan(d);
});

$("plan-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("domain").value.trim();
  if (v) buildPlan(v);
});

$("lock-btn").addEventListener("click", () => {
  setPass("");
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
  });
}

$("print-btn").addEventListener("click", () => window.print());

if (memoryPass) {
  unlockUI(true);
  const d = new URLSearchParams(location.search).get("d");
  if (d) buildPlan(d);
}
