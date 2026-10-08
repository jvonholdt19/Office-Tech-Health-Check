// "Verify live": after the technician makes the day-one changes, check public DNS change by change.
import { dnsReachable } from "./checks/email.js";

const norm = (v) => String(v ?? "").replace(/\s+/g, " ").trim().toLowerCase().replace(/\.$/, "");
const MAX_CHANGES = 50;

async function lookup(resolver, name, type) {
  try {
    if (type === "TXT") return (await resolver.resolveTxt(name)).map((c) => c.join(""));
    if (type === "CNAME") return await resolver.resolveCname(name);
    if (type === "MX") return (await resolver.resolveMx(name)).map((m) => `${m.priority} ${m.exchange}`);
    return null;
  } catch (err) {
    if (["ENOTFOUND", "ENODATA"].includes(err.code)) return [];
    throw err;
  }
}

/**
 * changes: [{ action, type, name (relative, "@" for the domain), to, from, status }]
 * Only changes inside `domain` are looked up, so the endpoint can't be used to query arbitrary names.
 */
export async function verifyLive(domain, changes, { resolver }) {
  const d = String(domain).toLowerCase();
  if (!Array.isArray(changes)) throw new Error("No changes to verify.");
  // Without this, an unreachable resolver would make every change look "not published yet".
  if (!(await dnsReachable(resolver))) throw new Error("Live DNS couldn't be reached right now, so nothing was checked. Try again in a minute.");
  const out = [];
  for (const c of changes.slice(0, MAX_CHANGES)) {
    const rel = String(c.name || "").toLowerCase();
    if (!/^(@|[a-z0-9_*<>-]+(\.[a-z0-9_*<>-]+)*)$/.test(rel) || !["TXT", "CNAME", "MX"].includes(c.type) || rel.includes("<")) {
      out.push({ ...c, live: "skipped", note: "Check this one by hand." });
      continue;
    }
    const name = rel === "@" ? d : `${rel}.${d}`;
    let values;
    try {
      values = await lookup(resolver, name, c.type);
    } catch (err) {
      out.push({ ...c, live: "error", note: `Couldn't check live DNS (${err.code || err.message}). Try again in a minute.` });
      continue;
    }
    const has = (v) => values.some((x) => norm(x) === norm(v));
    let live;
    let note = "";
    if (c.action === "Delete") {
      live = has(c.from) ? "pending" : "done";
      if (live === "pending") note = "The old record is still published.";
    } else if (c.status === "assumed") {
      // Platform-generated key: we can only confirm something DKIM-shaped is there.
      live = values.length && (c.type === "CNAME" || values.some((v) => /v=DKIM1|p=/i.test(v))) ? "done" : "pending";
      if (live === "pending") note = "No key published here yet.";
    } else {
      live = has(c.to) ? "done" : "pending";
      if (live === "done" && c.action === "Replace" && c.from && has(c.from)) {
        live = "pending";
        note = "The new value is live, but the old one is still there too. Delete the old one.";
      } else if (live === "pending") {
        note = values.length ? `Live value is different: ${values.find((v) => (c.type === "TXT" ? /^v=(spf1|dmarc1)/i.test(v) : true)) || values[0]}` : "Not published yet.";
      }
    }
    out.push({ ...c, live, note });
  }
  return { results: out, allDone: out.every((r) => r.live === "done" || r.live === "skipped") };
}
