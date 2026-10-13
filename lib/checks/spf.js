// SPF (RFC 7208): term parsing, syntax checks and an exact count of the DNS lookups evaluation needs.
import { txtRecords, withTimeout, isNotFound } from "../net.js";

const MECHANISMS = new Set(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]);
// Mechanisms (and the redirect modifier) that cost one DNS lookup each time they are evaluated (§4.6.4).
const LOOKUP_TERMS = new Set(["include", "a", "mx", "ptr", "exists", "redirect"]);
export const SPF_LOOKUP_LIMIT = 10;
export const SPF_VOID_LIMIT = 2;
const MX_NAME_LIMIT = 10;

export const isSpfRecord = (v) => /^v=spf1(\s|$)/i.test(String(v));

/**
 * Parse one SPF term.
 *  mechanism: { kind: "mechanism", qualifier, name, arg, raw }
 *  modifier:  { kind: "modifier", name, value, raw }
 *  anything else: { kind: "unknown", raw }
 */
export function parseTerm(raw) {
  const mod = raw.match(/^([a-z][a-z0-9_.-]*)=(.*)$/i);
  if (mod) return { kind: "modifier", name: mod[1].toLowerCase(), value: mod[2], raw };
  const m = raw.match(/^([+\-~?]?)([a-z][a-z0-9]*)(?::(.*?))?(\/.*)?$/i);
  if (!m || !MECHANISMS.has(m[2].toLowerCase())) return { kind: "unknown", raw };
  const name = m[2].toLowerCase();
  const arg = m[3] ? m[3] : null;
  // include/exists need a domain; ip4/ip6 need an address; all takes nothing.
  if ((["include", "exists", "ip4", "ip6"].includes(name) && !arg) || (name === "all" && (arg || m[4]))) return { kind: "unknown", raw };
  return { kind: "mechanism", qualifier: m[1] || "+", name, arg: arg && name !== "ip4" && name !== "ip6" ? arg.toLowerCase() : arg, cidr: m[4] || null, raw };
}

export function spfTerms(record) {
  return String(record).trim().split(/\s+/).slice(1).filter(Boolean).map(parseTerm);
}

const hasMacro = (s) => typeof s === "string" && s.includes("%{");

/**
 * Syntax problems in one record. Each issue is { code, severity: "permerror" | "warn", message }.
 * permerror means receivers treat the whole record as broken.
 */
export function validateSpfSyntax(record) {
  const terms = spfTerms(record);
  const issues = [];
  const alls = terms.filter((t) => t.kind === "mechanism" && t.name === "all");
  if (alls.length > 1) issues.push({ code: "multiple-all", severity: "warn", message: `The record has ${alls.length} "all" terms. Only the first one is ever used.` });
  const firstAll = terms.findIndex((t) => t.kind === "mechanism" && t.name === "all");
  if (firstAll >= 0) {
    const after = terms.slice(firstAll + 1).filter((t) => t.kind === "mechanism" && t.name !== "all");
    if (after.length) issues.push({ code: "terms-after-all", severity: "warn", message: `${after.map((t) => t.raw).join(", ")} come${after.length === 1 ? "s" : ""} after "${terms[firstAll].raw}", so receivers never check ${after.length === 1 ? "it" : "them"} (RFC 7208 §5.1).` });
  }
  for (const t of terms.filter((x) => x.kind === "unknown")) {
    issues.push({ code: "unknown-mechanism", severity: "permerror", message: `"${t.raw}" isn't a valid SPF term, which makes the whole record invalid (permerror).` });
  }
  for (const name of ["redirect", "exp"]) {
    const n = terms.filter((t) => t.kind === "modifier" && t.name === name).length;
    if (n > 1) issues.push({ code: "duplicate-modifier", severity: "permerror", message: `"${name}=" appears ${n} times. It may appear only once (RFC 7208 §6), so the record is invalid.` });
  }
  if (terms.some((t) => t.kind === "mechanism" && t.name === "ptr")) {
    issues.push({ code: "ptr-deprecated", severity: "warn", message: "RFC 7208 §5.5: ptr SHOULD NOT be used. It's slow, unreliable, and some receivers ignore it." });
  }
  return issues;
}

async function addressLookup(resolver, name) {
  // Returns the number of A + AAAA answers. Void = 0 answers / NXDOMAIN.
  let total = 0;
  for (const fn of ["resolve4", "resolve6"]) {
    if (typeof resolver[fn] !== "function") throw Object.assign(new Error(`${fn} not available`), { code: "ENOTIMP_RESOLVER" });
    try {
      total += (await withTimeout(resolver[fn](name), 5000, `${fn} ${name}`)).length;
    } catch (err) {
      if (!isNotFound(err)) throw err;
    }
  }
  return total;
}

async function mxLookup(resolver, name) {
  try {
    return await withTimeout(resolver.resolveMx(name), 5000, `MX ${name}`);
  } catch (err) {
    if (isNotFound(err)) return [];
    throw err;
  }
}

/**
 * Count the DNS lookups evaluating `record` needs, exactly as RFC 7208 §4.6.4 defines them:
 * +1 for every include, a, mx, ptr, exists and redirect each time it is evaluated (no
 * de-duplication), recursing into include and redirect targets. Also counts void lookups
 * (NXDOMAIN or empty answers) and checks the per-mx 10-name limit.
 *
 * Returns { count, voids, complete, exceeded, errors[], names[] }.
 *  - complete: false when any lookup failed or a macro target couldn't be followed, so `count`
 *    is only a lower bound ("at least N"). Never present it as exact.
 *  - exceeded: evaluation stopped because count went over 10.
 *  - errors: [{ code, severity, message }], severity "permerror" | "error" | "warn".
 *  - names: every include/redirect target reached (used to tell whether a platform is authorized).
 */
export async function countSpfLookups(resolver, record, { domain = null } = {}) {
  const state = { count: 0, voids: 0, complete: true, exceeded: false, errors: [], names: [] };
  const err = (code, severity, message) => state.errors.push({ code, severity, message });

  async function fetchSpf(target, how) {
    let txt;
    try {
      txt = await txtRecords(resolver, target);
    } catch (e) {
      state.complete = false;
      err("lookup-failed", "error", `Couldn't look up ${target} (${e.code || e.message}).`);
      return null;
    }
    if (txt.length === 0) state.voids++;
    const spf = txt.filter(isSpfRecord);
    if (spf.length === 0) {
      err("include-no-spf", "permerror", `${how} ${target} has no SPF record, which is a permanent error for receivers (RFC 7208 §5.2, §6.1).`);
      return null;
    }
    if (spf.length > 1) {
      err("include-multiple-spf", "permerror", `${target} has ${spf.length} SPF records, which is a permanent error.`);
      return null;
    }
    return spf[0];
  }

  const bump = () => {
    state.count++;
    if (state.count > SPF_LOOKUP_LIMIT) state.exceeded = true;
    return !state.exceeded;
  };

  async function walk(rec, current, path) {
    const terms = spfTerms(rec);
    const hasAll = terms.some((t) => t.kind === "mechanism" && t.name === "all");
    for (const t of terms) {
      if (state.exceeded) return;
      if (t.kind !== "mechanism") continue;
      if (t.name === "all") break; // nothing after "all" is ever evaluated (§5.1)
      if (!LOOKUP_TERMS.has(t.name)) continue;
      if (!bump()) return;
      const target = t.arg || current;
      if (t.name === "ptr") continue; // depends on the connecting IP; nothing to resolve here
      if (hasMacro(target) || !target) {
        if (t.name === "include") {
          state.complete = false;
          err("macro", "warn", `include:${t.arg} uses a macro, so what it includes can't be counted ahead of time.`);
        }
        continue;
      }
      if (t.name === "include") {
        state.names.push(target);
        if (path.includes(target)) {
          err("loop", "permerror", `include:${target} loops back to itself (${[...path, target].join(" → ")}), which is a permanent error.`);
          continue;
        }
        const child = await fetchSpf(target, "include:");
        if (child) await walk(child, target, [...path, target]);
      } else if (t.name === "mx") {
        try {
          const mx = await mxLookup(resolver, target);
          if (mx.length === 0) state.voids++;
          if (mx.length > MX_NAME_LIMIT) err("mx-too-many", "permerror", `The mx mechanism for ${target} returns ${mx.length} mail servers. More than 10 is a permanent error (RFC 7208 §4.6.4).`);
        } catch (e) {
          if (e.code === "ENOTIMP_RESOLVER") continue;
          state.complete = false;
          err("lookup-failed", "error", `Couldn't look up MX for ${target} (${e.code || e.message}).`);
        }
      } else {
        // a and exists
        try {
          if ((await addressLookup(resolver, target)) === 0) state.voids++;
        } catch (e) {
          if (e.code === "ENOTIMP_RESOLVER") continue;
          state.complete = false;
          err("lookup-failed", "error", `Couldn't look up ${target} (${e.code || e.message}).`);
        }
      }
    }
    if (state.exceeded) return;
    // redirect is ignored when the record has an "all" mechanism (§6.1).
    const redirect = terms.find((t) => t.kind === "modifier" && t.name === "redirect");
    if (redirect && !hasAll) {
      if (!bump()) return;
      const target = redirect.value.toLowerCase();
      if (hasMacro(target)) {
        state.complete = false;
        return;
      }
      state.names.push(target);
      if (path.includes(target)) {
        err("loop", "permerror", `redirect=${target} loops back (${[...path, target].join(" → ")}), which is a permanent error.`);
        return;
      }
      const child = await fetchSpf(target, "redirect=");
      if (child) await walk(child, target, [...path, target]);
    }
  }

  await walk(record, domain ? domain.toLowerCase() : null, domain ? [domain.toLowerCase()] : []);
  if (state.voids > SPF_VOID_LIMIT) err("too-many-void-lookups", "permerror", `${state.voids} lookups return no answer (limit 2), which receivers may treat as a permanent error (RFC 7208 §4.6.4).`);
  return state;
}

/** "11", "at least 7" or "more than 10": never presents a partial count as exact. */
export function describeLookupCount({ count, complete, exceeded }) {
  if (exceeded) return `more than ${SPF_LOOKUP_LIMIT}`;
  return complete ? String(count) : `at least ${count}`;
}

/**
 * Split a TXT value into strings of at most 255 bytes (a single DNS character-string can't be
 * longer; receivers join them back together). Splits only between UTF-8 characters.
 */
export function splitTxt(value, max = 255) {
  const out = [];
  let cur = "";
  for (const ch of String(value)) {
    if (Buffer.byteLength(cur + ch) > max) {
      out.push(cur);
      cur = "";
    }
    cur += ch;
  }
  if (cur || !out.length) out.push(cur);
  return out;
}

