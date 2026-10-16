// Admin pricing sheet (/tools/pricing). Every amount comes from GET /api/pricing, which reads
// lib/config.js: nothing is priced in this file. Admin only (lib/admin.js); never linked from the
// public lander or client plans. Inserted with textContent only.
import { $, h, api, showError, initGate, isAdminSession } from "./tech-session.js";

const row = (name, label, detail) => h("tr", {}, h("th", { scope: "row" }, name), h("td", { class: "pricing-amount" }, label), h("td", {}, detail));
const table = (caption, rows) =>
  h("table", { class: "pricing-table" },
    h("caption", {}, caption),
    h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Item"), h("th", { scope: "col" }, "Price"), h("th", { scope: "col" }, "What it covers"))),
    h("tbody", {}, rows),
  );

/** The sheet, built from the /api/pricing answer. */
export function renderSheet(s) {
  const parts = [
    table("One-time fix (per business)", s.packages.map((p) => row(p.name, p.label, `${p.scope}. ${p.blurb}`))),
    table("Ongoing (flat fee per business, not per user)", s.recurring.map((r) => row(r.name, r.label, r.blurb))),
  ];
  if (s.founding) {
    const f = s.founding;
    parts.push(
      h("section", { class: "callout founding-offer", "aria-labelledby": "founding-title" },
        h("h2", { id: "founding-title" }, `${f.name}: first ${f.limit} clients`),
        h("p", {}, h("strong", {}, `${f.label} ${f.packageName} fix`), f.regularLabel ? ` (usually ${f.regularLabel})` : "", f.bonus ? `, plus a free first year of ${f.bonus.name} (usually ${f.bonus.regularLabel}).` : "."),
        h("p", {}, f.terms),
        f.note ? h("p", { class: "pricing-note" }, h("strong", {}, "Note: "), f.note) : null,
      ),
    );
  }
  if (s.quotes.length) parts.push(table("Quoted separately", s.quotes.map((q) => row(q.title, q.label, "Scoped and quoted per client."))));
  parts.push(h("p", { class: "report-foot" }, `Prices approved ${s.approved}. To change them, edit lib/config.js; this sheet and every Fix Plan update together.`));
  return parts;
}

async function load() {
  showError("pricing-error", "");
  if (!isAdminSession()) return showError("pricing-error", "This page is for admins only.");
  $("pricing-loading").hidden = false;
  try {
    const { res, body } = await api("/api/pricing");
    if (res.status === 401) return;
    if (!res.ok) return showError("pricing-error", body.error || "Couldn't load the prices.");
    $("pricing-body").replaceChildren(...renderSheet(body));
    $("pricing-body").hidden = false;
  } catch {
    showError("pricing-error", "Couldn't reach the server.");
  } finally {
    $("pricing-loading").hidden = true;
  }
}

if (typeof document !== "undefined" && $("pricing-body")) {
  $("print-pricing").addEventListener("click", () => window.print());
  initGate({ contentId: "tool", onSignedIn: load, onSignedOut: () => ($("pricing-body").hidden = true) });
}
