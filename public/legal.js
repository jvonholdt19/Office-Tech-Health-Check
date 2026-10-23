// Legal text shown with results, kept in ONE place so it's easy to replace (e.g. with an
// attorney's wording). The source is docs/legal/scan-results-disclaimer.md; test/legal.test.js
// fails if this copy and that file drift apart. Also the consent checkbox wiring for every scan form.
// Rendered with createElement/textContent only (strict CSP, no innerHTML).

/** Short disclaimer for scan results, preview results and Fix Plans. [text](/path) becomes a link. */
export const RESULTS_DISCLAIMER =
  "These results are a snapshot of public information at the time of the check and may be incomplete or change at any time. They are not a guarantee that your business is secure, and many settings (like passwords, multi-factor authentication and backups) can't be seen from outside. This is not legal or compliance advice. Only check domains you own or have permission to check. See our [Terms](/terms) and [Privacy Policy](/privacy).";

/** Extra line on Fix Plans only. */
export const FIX_PLAN_TERMS = "Fixes are carried out only under a signed service agreement. Prices and scope in this plan are an estimate until that agreement is signed.";

/** Text of the consent checkbox on every scan form (the pages carry the same words; tested). */
export const CONSENT_LABEL = "I own this domain or have the owner's permission to check it.";

/** Small print under the consent checkbox (the element its aria-describedby names). [text](/path) becomes a link. */
export const CONSENT_NOTE =
  "This runs a read-only check of public records (DNS, email settings, and your homepage). Nothing is changed or logged into. By checking this box you confirm you're allowed to request this check and agree to our [Terms](/terms).";

/** "See our [Terms](/terms)" → text nodes and <a> elements. Only same-site paths become links. */
export function inlineNodes(text, doc = document) {
  const out = [];
  let last = 0;
  for (const m of text.matchAll(/\[([^\]]+)\]\((\/[a-z0-9/-]*)\)/gi)) {
    if (m.index > last) out.push(doc.createTextNode(text.slice(last, m.index)));
    const a = doc.createElement("a");
    a.setAttribute("href", m[2]);
    a.textContent = m[1];
    out.push(a);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(doc.createTextNode(text.slice(last)));
  return out;
}

/** The disclaimer block: <div class="results-disclaimer" role="note"><p>…</p>[<p>fix plan line</p>]</div>. */
export function disclaimerBlock({ fixPlan = false } = {}, doc = document) {
  const box = doc.createElement("div");
  box.className = "results-disclaimer";
  box.setAttribute("role", "note");
  const p = doc.createElement("p");
  p.append(...inlineNodes(RESULTS_DISCLAIMER, doc));
  box.append(p);
  if (fixPlan) {
    const extra = doc.createElement("p");
    extra.className = "results-disclaimer-plan";
    extra.textContent = FIX_PLAN_TERMS;
    box.append(extra);
  }
  return box;
}

/** Put the disclaimer into a placeholder element (static pages) once. */
export function fillDisclaimer(el, opts) {
  if (el && typeof el.replaceChildren === "function") el.replaceChildren(disclaimerBlock(opts));
}

/**
 * Consent checkbox: fills in CONSENT_NOTE where the checkbox's aria-describedby points, and keeps
 * the submit button disabled until it's ticked. Returns
 * { ok(): boolean, refresh(): void } so the page can re-check after a scan re-enables the button.
 * Pages without the checkbox (and test DOMs) are left as they are.
 */
export function wireConsent(checkbox, button) {
  if (!checkbox || !button) return { ok: () => true, refresh() {} };
  const doc = checkbox.ownerDocument;
  const noteId = checkbox.getAttribute?.("aria-describedby");
  const note = noteId && doc?.getElementById?.(noteId);
  if (note && typeof note.replaceChildren === "function") note.replaceChildren(...inlineNodes(CONSENT_NOTE, doc));
  const refresh = () => {
    button.disabled = !checkbox.checked;
  };
  checkbox.addEventListener("change", refresh);
  refresh();
  return { ok: () => Boolean(checkbox.checked), refresh };
}
