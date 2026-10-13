// Private endpoint: POST /api/plan/confirm (rewritten here by vercel.json)
//   { domain, typedDomain, changeSetHash, zone?, confirmExport?, overrideUnverified? }
// The technician has reviewed the before/after diff and typed the domain name. The server rebuilds
// the plan from the same inputs, recomputes the change-set hash, re-runs the guards, logs the
// confirmation and returns the copy-ready values. Nothing is written to DNS: confirming only unlocks
// values for the technician to enter by hand at the client's DNS host.
import { normalizeDomain } from "../lib/domain.js";
import { defaultDeps } from "../lib/net.js";
import { authorize, send, readJson } from "../lib/private-api.js";
import { audit } from "../lib/audit.js";
import { recordsTouched } from "../lib/changeset.js";
import { buildFullPlan } from "./plan.js";

/** Rebuild, verify the hash and guards. Returns { status, body } (exported for tests). */
export async function confirmChangeSet(body, deps = defaultDeps) {
  const parsed = normalizeDomain(body?.domain || "");
  if (parsed.error) return { status: 400, body: { error: parsed.error } };
  if (String(body.typedDomain || "").trim().toLowerCase().replace(/\.$/, "") !== parsed.domain) {
    return { status: 400, body: { error: `Type the domain name (${parsed.domain}) exactly to confirm.` } };
  }
  if (typeof body.changeSetHash !== "string" || !/^[0-9a-f]{64}$/.test(body.changeSetHash)) return { status: 400, body: { error: "Missing change-set fingerprint." } };
  const zone = body.zone && typeof body.zone.text === "string" ? body.zone : null;
  const confirmExport = body.confirmExport && typeof body.confirmExport.sha256 === "string" ? { sha256: body.confirmExport.sha256 } : null;

  const result = await buildFullPlan(parsed.domain, zone, deps, { confirmExport });
  if (result.changeSetHash !== body.changeSetHash) {
    return { status: 409, body: { error: "The DNS records changed since this plan was built. Build the plan again and review the new diff.", changeSetHash: result.changeSetHash } };
  }
  if (result.guards.blocked) {
    return { status: 409, body: { error: `This change set is blocked: ${result.guards.reasons.join(" ")}`, blocked: result.guards.blocked } };
  }
  if (result.simulation.verdict === "blocked") {
    return { status: 409, body: { error: `The dry run blocked these changes: ${result.simulation.blockers.join(" ")}`, blocked: true } };
  }
  const unverified = result.changeSet.filter((e) => e.blocked === "unverified");
  if (unverified.length && body.overrideUnverified !== true) {
    return { status: 409, body: { error: "Some values couldn't be verified against live DNS. Check them by hand and tick the override to unlock them.", blocked: "unverified" } };
  }
  // Copy-ready values: every record of the day-one plan that isn't hard-blocked or platform-generated.
  const values = [];
  for (const it of result.plan.items) {
    for (const r of it.records || []) {
      // r.zone records (the one-time report authorization on our own domain) are unlocked too.
      if (r.later || r.generated || r.action === "Delete" || r.blocked === true) continue;
      values.push({ type: r.type, name: r.name, value: r.value, strings: r.strings || null });
    }
  }
  return {
    status: 200,
    body: { ok: true, domain: parsed.domain, changeSetHash: result.changeSetHash, recordsTouched: recordsTouched(result.changeSet), overrideUnverified: unverified.length > 0, values },
    audit: { domain: parsed.domain, changeSetHash: result.changeSetHash, recordsTouched: recordsTouched(result.changeSet), records: result.changeSet.map((e) => `${e.action} ${e.type} ${e.name}`), overrideUnverified: unverified.length > 0, source: zone ? "upload" : "live" },
  };
}

export default async function handler(req, res) {
  if (req.method !== "POST") return send(res, 405, { error: "Use POST" }, { Allow: "POST" });
  const auth = await authorize(req, res);
  if (!auth) return;
  let body;
  try {
    body = await readJson(req);
  } catch (err) {
    return send(res, err.status || 400, { error: "Couldn't read the request." });
  }
  try {
    const out = await confirmChangeSet(body);
    if (out.audit) await audit("plan_confirm", { sid: auth.sid, ip: auth.ip, ua: auth.ua, ...out.audit }, auth.store);
    return send(res, out.status, out.body);
  } catch (err) {
    if (err?.userFacing) return send(res, 400, { error: err.message });
    console.error("confirm failed", err?.code || err?.message);
    return send(res, 500, { error: "Couldn't confirm the changes. Please try again." });
  }
}
