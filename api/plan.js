import { normalizeDomain } from "../lib/domain.js";
import { runScan } from "../lib/scan.js";
import { buildPlan, safetyCheckPlan } from "../lib/plan.js";
import { defaultDeps } from "../lib/net.js";
import { parseZone, zoneResolver, dkimSelectors, inventory, compareWithLive } from "../lib/zone.js";
import { simulatePlan, liveBaseRecords } from "../lib/simulate.js";
import { buildChangeSet, changeSetHash } from "../lib/changeset.js";
import { checkChangeSet } from "../lib/guards.js";
import { createHash } from "node:crypto";
import { authorize, send, readJson, cachedDeps, passcodeMatches } from "../lib/private-api.js";
import { audit } from "../lib/audit.js";

export { passcodeMatches };

// Private endpoint (technician session cookie from POST /api/session; locked without
// SESSION_SECRET and Supabase):
//   GET  /api/plan?domain=example.com                → plan from public DNS
//   POST /api/plan { domain, zone: { text, filename }, confirmExport? } → plan from the client's exported zone
// Both include a dry run of the day-one changes. Uploaded records are never stored.

/** Record types live DNS shows at the apex, to tell whether an uploaded export is partial. */
async function liveApexTypes(domain, resolver) {
  const probes = { MX: "resolveMx", TXT: "resolveTxt", NS: "resolveNs", A: "resolve4", AAAA: "resolve6", SOA: "resolveSoa", CAA: "resolveCaa" };
  const types = [];
  for (const [type, fn] of Object.entries(probes)) {
    if (typeof resolver[fn] !== "function") continue;
    try {
      const r = await resolver[fn](domain);
      if (r && (!Array.isArray(r) || r.length)) types.push(type);
    } catch {
      /* not present, or unknown */
    }
  }
  return types;
}

/**
 * Build the plan, dry run, change set and guard results.
 * options.confirmExport: { sha256 } from a second request, confirming an upload that differs from
 * live DNS is current. It only counts when it matches the upload's own SHA-256.
 */
export async function buildFullPlan(domain, zoneUpload, baseDeps = defaultDeps, options = {}) {
  const deps = cachedDeps(baseDeps);
  let zone = null;
  let report;
  let resolver = deps.resolver;
  let base;
  let owned = null;

  if (zoneUpload?.text) {
    let parsed;
    try {
      parsed = parseZone(zoneUpload.text, domain);
    } catch (err) {
      throw Object.assign(new Error(err.message), { userFacing: true });
    }
    resolver = zoneResolver(parsed.records, domain, deps.resolver, { authoritative: true });
    report = await runScan(domain, { ...deps, resolver, dkimSelectors: dkimSelectors(parsed.records, domain), zoneAuthoritative: true });
    base = parsed.records;
    zone = {
      sha256: createHash("sha256").update(zoneUpload.text).digest("hex"),
      bytes: Buffer.byteLength(zoneUpload.text),
      filename: String(zoneUpload.filename || "").slice(0, 120) || null,
      format: parsed.format,
      warnings: parsed.warnings,
      inventory: inventory(parsed.records, domain),
      differences: await compareWithLive(parsed.records, domain, deps.resolver),
    };
  } else {
    report = await runScan(domain, deps);
    ({ records: base, owned } = await liveBaseRecords(domain, deps.resolver, report));
  }

  const plan = await safetyCheckPlan(buildPlan(report), { resolver });
  const simulation = await simulatePlan({ domain, base, owned, authoritative: Boolean(zone), plan, before: report, deps });

  // Change set + server-side guards. Nothing is written anywhere: this only decides what may be copied.
  const changeSet = buildChangeSet(base, plan, domain);
  const exportConfirmed = Boolean(zone && options.confirmExport && options.confirmExport.sha256 === zone.sha256);
  const partial = zone
    ? { uploadTypes: [...new Set(base.filter((r) => r.name === domain).map((r) => r.type))], liveTypes: await liveApexTypes(domain, deps.resolver) }
    : null;
  const guards = checkChangeSet(changeSet, { domain, differences: zone?.differences, exportConfirmed, partial });
  guards.exportConfirmed = exportConfirmed;
  // The dry run says whether the changes are safe; the guards say whether they may be copied yet.
  // The page and /api/plan/confirm require both.
  if (guards.warnings.length && zone) zone.warnings = [...zone.warnings, ...guards.warnings];
  return { report, plan, simulation, zone, changeSet, changeSetHash: changeSetHash(changeSet), guards };
}

export default async function handler(req, res) {
  if (req.method !== "GET" && req.method !== "POST") return send(res, 405, { error: "Use GET or POST" }, { Allow: "GET, POST" });
  const auth = await authorize(req, res);
  if (!auth) return;

  let domainInput;
  let zoneUpload = null;
  let confirmExport = null;
  if (req.method === "POST") {
    let body;
    try {
      body = await readJson(req);
    } catch (err) {
      return send(res, err.status || 400, { error: err.status ? err.message : "Couldn't read the upload." });
    }
    domainInput = body.domain;
    zoneUpload = body.zone && typeof body.zone.text === "string" ? body.zone : null;
    confirmExport = body.confirmExport && typeof body.confirmExport.sha256 === "string" ? { sha256: body.confirmExport.sha256 } : null;
  } else {
    domainInput = new URL(req.url, "http://localhost").searchParams.get("domain");
  }
  const parsed = normalizeDomain(domainInput || "");
  if (parsed.error) return send(res, 400, { error: parsed.error });

  try {
    const result = await buildFullPlan(parsed.domain, zoneUpload, defaultDeps, { confirmExport });
    await audit("plan_build", {
      sid: auth.sid, ip: auth.ip, ua: auth.ua, domain: parsed.domain, source: zoneUpload ? "upload" : "live",
      // The upload itself is never logged or stored: only its fingerprint, size and format.
      ...(zoneUpload ? { uploadSha256: createHash("sha256").update(zoneUpload.text).digest("hex"), uploadBytes: Buffer.byteLength(zoneUpload.text), uploadFormat: result.zone?.format || null } : {}),
    }, auth.store);
    return send(res, 200, result);
  } catch (err) {
    // Zone-file problems are explained to the user; anything else is logged without the upload's contents.
    if (err?.userFacing) return send(res, 400, { error: err.message });
    console.error("plan failed", parsed.domain, err?.code || err?.message);
    return send(res, 500, { error: "Couldn't build the plan. Please try again." });
  }
}
