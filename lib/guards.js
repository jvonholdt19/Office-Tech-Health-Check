// Server-side guards on the change set. A violation marks the entry (and the plan) blocked, with a
// reason, so the technician can't copy values that would break the client's DNS. Enforced in
// buildFullPlan (api/plan.js) and again when a change set is confirmed (api/plan-confirm.js).

import { spfTerms, isSpfRecord } from "./checks/spf.js";
import { recordsTouched } from "./changeset.js";

export const MAX_RECORDS_TOUCHED = 5;
const PROTECTED_TYPES = new Set(["MX", "NS", "SOA", "A", "AAAA", "CNAME"]);
const norm = (v) => String(v ?? "").replace(/\s+/g, " ").trim().toLowerCase().replace(/\.$/, "");
const isDmarc = (v) => /^v=DMARC1/i.test(String(v).trim());
const spfTermSet = (values) =>
  new Set(
    values
      .filter(isSpfRecord)
      .flatMap((v) => spfTerms(v))
      .filter((t) => !(t.kind === "mechanism" && t.name === "all"))
      .map((t) => t.raw.replace(/^\+/, "").toLowerCase()),
  );

/**
 * Check a change set. Returns { blocked: false | true | "too-broad" | "upload-mismatch", reasons[],
 * warnings[], violations[] } and marks offending entries with blocked: true and a blockedReason.
 *  - differences / exportConfirmed: compareWithLive results for an upload, and whether the
 *    technician confirmed (on a second request) that the export is current.
 *  - partial: { uploadTypes, liveTypes } apex record types, to spot a partial export.
 */
export function checkChangeSet(changeSet, { domain, differences = null, exportConfirmed = false, partial = null } = {}) {
  const violations = [];
  const warnings = [];
  const d = String(domain).toLowerCase();
  const violate = (entry, code, message) => {
    violations.push({ code, message, name: entry?.name ?? null, type: entry?.type ?? null });
    if (entry) {
      entry.blocked = true;
      entry.blockedReason = entry.blockedReason ? `${entry.blockedReason} ${message}` : message;
    }
  };

  for (const e of changeSet) {
    const after = new Set(e.after.map(norm));
    const removed = e.before.filter((v) => !after.has(norm(v)));
    const isApex = e.fqdn === d;
    const isDmarcName = e.fqdn === `_dmarc.${d}`;
    const isDkimName = e.fqdn.endsWith(`._domainkey.${d}`);

    // 1. Never remove protected record types, other TXT records, or DKIM selectors.
    if (removed.length) {
      if (isDkimName) violate(e, "removes-dkim", `Would remove the DKIM key at ${e.name}. DKIM selectors are never removed: publish a new selector instead.`);
      else if (PROTECTED_TYPES.has(e.type)) violate(e, "removes-protected", `Would remove ${e.type} ${e.name} (${removed.join(" | ")}). This tool never removes ${e.type} records.`);
      else if (e.type === "TXT") {
        const allowed = (v) => (isApex && isSpfRecord(v)) || (isDmarcName && isDmarc(v));
        const bad = removed.filter((v) => !allowed(v));
        if (bad.length) violate(e, "removes-txt", `Would remove TXT ${e.name} (${bad.join(" | ")}). Only SPF and DMARC records may be replaced.`);
      } else violate(e, "removes-other", `Would remove ${e.type} ${e.name}.`);
    }

    // 2. Exactly one SPF / DMARC record afterwards.
    if (e.type === "TXT" && e.after.filter(isSpfRecord).length > 1) violate(e, "multiple-spf", `Would leave ${e.after.filter(isSpfRecord).length} SPF records at ${e.name}. Receivers treat that as broken.`);
    if (e.type === "TXT" && e.after.filter(isDmarc).length > 1) violate(e, "multiple-dmarc", `Would leave ${e.after.filter(isDmarc).length} DMARC records at ${e.name}. Receivers ignore all of them.`);

    // 3. SPF keeps every existing mechanism unless the plan lists its removal with a reason.
    if (e.type === "TXT" && e.before.some(isSpfRecord) && e.after.some(isSpfRecord)) {
      const explained = new Set(
        (e.changes || [])
          .filter((c) => (c.op === "remove" || c.op === "convert") && c.reason)
          .map((c) => (c.op === "convert" ? c.term.split(" → ")[0] : c.term).replace(/^\+/, "").toLowerCase()),
      );
      const afterTerms = spfTermSet(e.after);
      const lost = [...spfTermSet(e.before)].filter((t) => !afterTerms.has(t) && !explained.has(t));
      if (lost.length) violate(e, "spf-drops-mechanism", `The new SPF record drops ${lost.join(", ")} without a listed reason.`);
    }
  }

  // 4. Breadth.
  const touched = recordsTouched(changeSet);
  const tooBroad = touched > MAX_RECORDS_TOUCHED;
  if (tooBroad) violations.push({ code: "too-broad", message: `The change set touches ${touched} records (limit ${MAX_RECORDS_TOUCHED}). Split the work into smaller, separately confirmed changes.`, name: null, type: null });

  // 5. Uploaded export vs live DNS.
  const mismatches = (differences || []).filter((x) => x.match === false);
  const mismatch = mismatches.length > 0 && !exportConfirmed;
  if (mismatch) {
    violations.push({ code: "upload-mismatch", message: `The uploaded records differ from live DNS (${mismatches.map((m) => m.label).join(", ")}). Confirm the export is current to continue.`, name: null, type: null });
  }

  // 6. Partial export (warning only).
  if (partial) {
    const live = new Set(partial.liveTypes);
    const up = new Set(partial.uploadTypes);
    const shared = [...live].filter((t) => up.has(t)).length;
    const missing = ["SOA", "NS"].filter((t) => !up.has(t));
    if ((live.size && shared < live.size / 2) || missing.length) {
      warnings.push(`The export looks partial${missing.length ? ` (no ${missing.join(" or ")} record at the main domain)` : ""}: it has ${shared} of the ${live.size} record types live DNS shows at ${d}. Re-export the full zone if you can.`);
    }
  }

  const hard = violations.some((v) => !["too-broad", "upload-mismatch"].includes(v.code));
  const blocked = hard ? true : tooBroad ? "too-broad" : mismatch ? "upload-mismatch" : false;
  return { blocked, reasons: violations.map((v) => v.message), violations, warnings, recordsTouched: touched };
}
