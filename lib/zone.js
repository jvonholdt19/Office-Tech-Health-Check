// Reads a client's exported DNS zone so the checks can run against their real records.
// Supports the formats DNS hosts actually export:
//  - BIND zone files (Cloudflare, GoDaddy, Namecheap, DNSimple, most others)
//  - CSV (hosts that only offer a spreadsheet)
//  - JSON from `aws route53 list-resource-record-sets`
// Parsing never touches the network, and nothing is stored.

import { dnsReachable } from "./checks/email.js";

const TYPES = new Set(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "PTR", "SPF", "DS", "DNSKEY", "TLSA", "HTTPS", "SVCB", "NAPTR", "ALIAS", "ANAME", "URI", "SSHFP", "LOC", "CERT", "SMIMEA", "OPENPGPKEY"]);
const CLASSES = new Set(["IN", "CH", "HS", "CS"]);
const MAX_RECORDS = 5000;

const clean = (name) => String(name || "").trim().toLowerCase().replace(/\.$/, "");

/** Absolute name for an owner/target written relative to `origin` ("@", "www", "mail.example.com."). */
function qualify(name, origin) {
  const n = String(name).trim();
  if (n === "@" || n === "") return origin;
  if (n.endsWith(".")) return clean(n);
  // Some exports (Cloudflare's SOA line, many CSVs) write full names without the trailing dot.
  const lower = n.toLowerCase();
  if (lower === origin || lower.endsWith(`.${origin}`)) return clean(n);
  return clean(`${n}.${origin}`);
}

/** Split a zone line into tokens, keeping quoted strings intact (with \" and \DDD escapes decoded). */
function tokenize(line) {
  const out = [];
  let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (c === " " || c === "\t") {
      i++;
    } else if (c === '"') {
      let s = "";
      i++;
      while (i < line.length && line[i] !== '"') {
        if (line[i] === "\\" && i + 1 < line.length) {
          const dec = line.slice(i + 1, i + 4);
          if (/^\d{3}$/.test(dec)) {
            s += String.fromCharCode(Number(dec));
            i += 4;
          } else {
            s += line[i + 1];
            i += 2;
          }
        } else {
          s += line[i++];
        }
      }
      i++;
      out.push({ quoted: true, text: s });
    } else {
      let s = "";
      while (i < line.length && line[i] !== " " && line[i] !== "\t") s += line[i++];
      out.push({ quoted: false, text: s });
    }
  }
  return out;
}

/** Strip a ; comment that isn't inside quotes. */
function stripComment(line) {
  let q = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === "\\") i++;
    else if (line[i] === '"') q = !q;
    else if (line[i] === ";" && !q) return line.slice(0, i);
  }
  return line;
}

const isTtl = (t) => /^\d+[smhdw]?$/i.test(t) || /^(\d+[smhdw])+$/i.test(t);

function rdataFor(type, tokens, origin) {
  const texts = tokens.map((t) => t.text);
  switch (type) {
    case "TXT":
    case "SPF":
      return { value: texts.join("") };
    case "MX":
      return { priority: Number(texts[0]), value: qualify(texts[1] || ".", origin) };
    case "CNAME":
    case "NS":
    case "PTR":
    case "ALIAS":
    case "ANAME":
      return { value: qualify(texts[0] || "", origin) };
    default:
      return { value: texts.join(" ") };
  }
}

export function parseBind(text, domain) {
  const records = [];
  const warnings = [];
  let origin = clean(domain);
  let declaredOrigin = null;
  let defaultTtl = null;
  let lastOwner = origin;

  // Cloudflare and GoDaddy name the domain in a header comment (";; Domain: acme.com."). Use it to
  // catch a file exported for the wrong domain, even when record names are written without a trailing dot.
  const header = text.match(/^\s*;+\s*Domain:\s*(\S+)/im);
  if (header) declaredOrigin = clean(header[1]);

  // Join parenthesised multi-line records, then process logical lines.
  const logical = [];
  let buf = "";
  let depth = 0;
  for (const raw of text.replace(/\r\n?/g, "\n").split("\n")) {
    const line = stripComment(raw);
    for (const ch of line.replace(/"(?:[^"\\]|\\.)*"/g, "")) {
      if (ch === "(") depth++;
      else if (ch === ")") depth = Math.max(0, depth - 1);
    }
    buf = buf ? `${buf} ${line.replace(/^\s+/, "")}` : line;
    if (depth === 0) {
      if (buf.trim()) logical.push(buf.replace(/[()]/g, (m, idx, s) => (insideQuotes(s, idx) ? m : " ")));
      buf = "";
    }
  }
  if (buf.trim()) logical.push(buf);

  for (const line of logical) {
    const trimmed = line.trim();
    if (trimmed.startsWith("$ORIGIN")) {
      origin = clean(trimmed.split(/\s+/)[1]);
      declaredOrigin = declaredOrigin || origin;
      continue;
    }
    if (trimmed.startsWith("$TTL")) {
      defaultTtl = trimmed.split(/\s+/)[1];
      continue;
    }
    if (trimmed.startsWith("$INCLUDE") || trimmed.startsWith("$GENERATE")) {
      warnings.push(`Skipped "${trimmed.split(/\s+/)[0]}": the file refers to another file, which can't be read here.`);
      continue;
    }
    const tokens = tokenize(line);
    if (!tokens.length) continue;
    let owner;
    let idx = 0;
    if (/^[ \t]/.test(line)) {
      owner = lastOwner;
    } else {
      owner = qualify(tokens[0].text, origin);
      idx = 1;
    }
    let ttl = defaultTtl;
    // TTL and class can appear in either order before the type.
    for (let k = 0; k < 2 && idx < tokens.length; k++) {
      const t = tokens[idx].text.toUpperCase();
      if (!tokens[idx].quoted && isTtl(t) && !TYPES.has(t)) {
        ttl = tokens[idx].text;
        idx++;
      } else if (CLASSES.has(t)) {
        idx++;
      }
    }
    const type = (tokens[idx]?.text || "").toUpperCase();
    if (!TYPES.has(type)) {
      warnings.push(`Couldn't read line: ${trimmed.slice(0, 80)}`);
      continue;
    }
    lastOwner = owner;
    records.push({ name: owner, type, ttl: ttl ?? null, ...rdataFor(type, tokens.slice(idx + 1), origin) });
    if (records.length > MAX_RECORDS) throw new Error(`The file has more than ${MAX_RECORDS} records, which is more than this tool reads.`);
  }
  return { records, warnings, declaredOrigin };
}

function insideQuotes(s, idx) {
  let q = false;
  for (let i = 0; i < idx; i++) {
    if (s[i] === "\\") i++;
    else if (s[i] === '"') q = !q;
  }
  return q;
}

/** Minimal RFC 4180 CSV reader. */
function csvRows(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') q = false;
      else cell += c;
    } else if (c === '"') q = true;
    else if (c === ",") {
      row.push(cell);
      cell = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cell);
      if (row.some((x) => x.trim())) rows.push(row);
      row = [];
      cell = "";
    } else cell += c;
  }
  row.push(cell);
  if (row.some((x) => x.trim())) rows.push(row);
  return rows;
}

const COLS = {
  type: ["type", "record type", "recordtype", "rr type"],
  name: ["name", "host", "hostname", "host name", "record name", "record", "subdomain"],
  value: ["value", "content", "data", "points to", "answer", "target", "address", "record value", "value/points to"],
  priority: ["priority", "pref", "preference", "mx priority", "prio"],
  ttl: ["ttl"],
};

export function parseCsv(text, domain) {
  const origin = clean(domain);
  const rows = csvRows(text);
  const header = (rows.shift() || []).map((h) => h.trim().toLowerCase());
  const col = Object.fromEntries(Object.entries(COLS).map(([k, names]) => [k, header.findIndex((h) => names.includes(h))]));
  if (col.type < 0 || col.name < 0 || col.value < 0) {
    throw new Error("This CSV needs Type, Name/Host and Value/Content columns. Check the export or use the zone-file export instead.");
  }
  const records = [];
  const warnings = [];
  for (const r of rows) {
    const type = (r[col.type] || "").trim().toUpperCase();
    if (!TYPES.has(type)) {
      if (type) warnings.push(`Skipped a row with unknown type "${type}"`);
      continue;
    }
    let rawName = (r[col.name] || "").trim();
    // Many hosts list names relative to the domain; some include it. Accept both.
    if (rawName && !rawName.endsWith(".") && (clean(rawName) === origin || clean(rawName).endsWith(`.${origin}`))) rawName += ".";
    const name = qualify(rawName || "@", origin);
    let value = (r[col.value] || "").trim();
    let priority;
    if (type === "MX") {
      const m = value.match(/^(\d+)\s+(\S+)$/);
      if (m) [, priority, value] = m;
      else priority = col.priority >= 0 ? r[col.priority] : 10;
    }
    if (type === "TXT" || type === "SPF") value = value.replace(/^"(.*)"$/s, "$1").replace(/"\s+"/g, "");
    records.push({
      name,
      type,
      ttl: col.ttl >= 0 ? (r[col.ttl] || "").trim() || null : null,
      ...(type === "MX" ? { priority: Number(priority) || 0, value: clean(value) } : ["CNAME", "NS", "PTR", "ALIAS"].includes(type) ? { value: clean(value) } : { value }),
    });
    if (records.length > MAX_RECORDS) throw new Error(`The file has more than ${MAX_RECORDS} records, which is more than this tool reads.`);
  }
  return { records, warnings, declaredOrigin: null };
}

export function parseRoute53(text, domain) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("This looks like JSON but couldn't be read.");
  }
  const sets = data.ResourceRecordSets || data.resourceRecordSets;
  if (!Array.isArray(sets)) throw new Error("JSON files are read in the Route 53 format (ResourceRecordSets). Use a zone-file or CSV export instead.");
  const records = [];
  const warnings = [];
  for (const s of sets) {
    const type = String(s.Type || "").toUpperCase();
    if (!TYPES.has(type)) continue;
    const name = clean(String(s.Name || "").replace(/\\052/g, "*"));
    if (s.AliasTarget) {
      records.push({ name, type: type === "A" || type === "AAAA" ? type : "ALIAS", ttl: null, value: `ALIAS ${clean(s.AliasTarget.DNSName)}` });
      continue;
    }
    for (const rr of s.ResourceRecords || []) {
      const v = String(rr.Value || "");
      if (type === "TXT" || type === "SPF") {
        const parts = [...v.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, "$1"));
        records.push({ name, type, ttl: s.TTL ?? null, value: parts.length ? parts.join("") : v });
      } else if (type === "MX") {
        const [p, ex] = v.split(/\s+/);
        records.push({ name, type, ttl: s.TTL ?? null, priority: Number(p), value: clean(ex) });
      } else {
        records.push({ name, type, ttl: s.TTL ?? null, value: ["CNAME", "NS", "PTR"].includes(type) ? clean(v) : v });
      }
    }
  }
  return { records, warnings, declaredOrigin: null };
}

export function detectFormat(text) {
  const t = text.trim();
  if (t.startsWith("{") || t.startsWith("[")) return "route53-json";
  const first = t.split(/\r?\n/).find((l) => l.trim() && !l.trim().startsWith(";") && !l.trim().startsWith("#")) || "";
  if (first.includes(",") && /(^|,)\s*"?(type|record type)"?\s*(,|$)/i.test(first)) return "csv";
  return "bind";
}

/**
 * Parse an uploaded zone export and check it belongs to `domain`.
 * Returns { format, records, warnings, outside } or throws an Error with a plain-English message.
 */
export function parseZone(text, domain) {
  const d = clean(domain);
  if (!text || !text.trim()) throw new Error("The file is empty.");
  if (text.length > 2_000_000) throw new Error("The file is larger than 2 MB, which is more than this tool reads.");
  const format = detectFormat(text);
  const parsed = format === "csv" ? parseCsv(text, d) : format === "route53-json" ? parseRoute53(text, d) : parseBind(text, d);
  if (parsed.declaredOrigin && parsed.declaredOrigin !== d && !d.endsWith(`.${parsed.declaredOrigin}`)) {
    throw new Error(`This file is for ${parsed.declaredOrigin}, not ${d}. Export the zone for ${d} instead.`);
  }
  const inZone = (n) => n === d || n.endsWith(`.${d}`);
  const records = parsed.records.filter((r) => inZone(r.name));
  const outside = parsed.records.length - records.length;
  if (records.length === 0) {
    throw new Error(parsed.records.length ? `None of the records in this file are for ${d}. Check you exported the right domain.` : "No DNS records could be read from this file.");
  }
  const warnings = [...parsed.warnings];
  if (outside) warnings.push(`Ignored ${outside} record(s) that aren't part of ${d}.`);
  return { format, records, warnings, outside };
}

/* ------------------------------------------------------------------ */
/* Using the records                                                    */
/* ------------------------------------------------------------------ */

const notFound = (name) => Object.assign(new Error(`${name} not found in the zone file`), { code: "ENOTFOUND" });

/**
 * A DNS resolver that answers from the zone's records. Names outside the domain (for example
 * Google's SPF include) go to `fallback`, which is normally live DNS.
 *  - authoritative: true  → the records are the complete zone; a name with nothing in the file doesn't exist.
 *  - authoritative: false → only `owned` name|type pairs come from the records; everything else falls back.
 */
export function zoneResolver(records, domain, fallback, { authoritative = true, owned = null } = {}) {
  const d = clean(domain);
  const inZone = (n) => n === d || n.endsWith(`.${d}`);
  const at = (name, type) => records.filter((r) => r.name === name && r.type === type);
  const answersFor = (name, type) => (authoritative ? inZone(name) : owned?.has(`${name}|${type}`) || owned?.has(`${name}|CNAME`));

  async function resolve(rawName, type, depth = 0) {
    const name = clean(rawName);
    if (!answersFor(name, type)) return { from: "fallback", name };
    if (type !== "CNAME") {
      const cname = at(name, "CNAME")[0];
      if (cname && depth < 8) {
        return inZone(cname.value) && answersFor(cname.value, type) ? resolve(cname.value, type, depth + 1) : { from: "fallback", name: cname.value };
      }
    }
    const rows = at(name, type);
    if (!rows.length) throw notFound(name);
    return { from: "zone", rows };
  }

  return {
    async resolveTxt(name) {
      const r = await resolve(name, "TXT");
      if (r.from === "fallback") return fallback.resolveTxt(r.name);
      return r.rows.map((x) => [x.value]);
    },
    async resolveMx(name) {
      const r = await resolve(name, "MX");
      if (r.from === "fallback") return fallback.resolveMx(r.name);
      return r.rows.map((x) => ({ exchange: x.value, priority: x.priority }));
    },
    async resolveNs(name) {
      const n = clean(name);
      // Many exports leave out the apex NS records; ask live DNS then.
      if (n === d && !at(n, "NS").length) return fallback.resolveNs(n);
      const r = await resolve(name, "NS");
      if (r.from === "fallback") return fallback.resolveNs(r.name);
      return r.rows.map((x) => x.value);
    },
    async resolveCname(name) {
      const r = await resolve(name, "CNAME");
      if (r.from === "fallback") return fallback.resolveCname(r.name);
      return r.rows.map((x) => x.value);
    },
  };
}

/** DKIM selectors present in the zone: "google" from google._domainkey.example.com. */
export function dkimSelectors(records, domain) {
  const suffix = `._domainkey.${clean(domain)}`;
  return [...new Set(records.filter((r) => r.name.endsWith(suffix) && (r.type === "TXT" || r.type === "CNAME")).map((r) => r.name.slice(0, -suffix.length)))].filter(
    (s) => s && !s.includes("*"),
  );
}

/** Group the records a technician cares about, in plain terms. */
export function inventory(records, domain) {
  const d = clean(domain);
  const rel = (n) => (n === d ? "@" : n.slice(0, -(d.length + 1)));
  const show = (r) => ({ name: rel(r.name), type: r.type, value: r.type === "MX" ? `${r.priority} ${r.value}` : r.value, ttl: r.ttl });
  const apexTxt = records.filter((r) => r.name === d && r.type === "TXT");
  const email = [
    ...records.filter((r) => r.name === d && r.type === "MX").map((r) => ({ ...show(r), role: "Mail server (MX)" })),
    ...apexTxt.filter((r) => /^v=spf1/i.test(r.value)).map((r) => ({ ...show(r), role: "SPF (approved senders)" })),
    ...records.filter((r) => r.name === `_dmarc.${d}` && r.type === "TXT").map((r) => ({ ...show(r), role: "DMARC" })),
    ...records.filter((r) => r.name.endsWith(`._domainkey.${d}`)).map((r) => ({ ...show(r), role: `DKIM key "${r.name.split("._domainkey")[0]}"` })),
    ...records.filter((r) => /^(mta-sts|_mta-sts|_smtp\._tls|autodiscover|_autodiscover\._tcp)\./.test(`${rel(r.name)}.`)).map((r) => ({ ...show(r), role: "Email support record" })),
  ];
  const website = records
    .filter((r) => (r.name === d || r.name === `www.${d}`) && ["A", "AAAA", "CNAME", "ALIAS", "ANAME"].includes(r.type))
    .map((r) => ({ ...show(r), role: r.name === d ? "Website (main domain)" : "Website (www)" }));
  const verification = apexTxt.filter((r) => !/^v=spf1/i.test(r.value)).map((r) => ({ ...show(r), role: "Ownership verification / other TXT" }));
  const counts = records.reduce((acc, r) => ((acc[r.type] = (acc[r.type] || 0) + 1), acc), {});
  return { email, website, verification, total: records.length, counts };
}

/** Records that have nothing to do with email authentication: the simulation must leave these untouched. */
export function isEmailAuthRecord(r, domain) {
  const d = clean(domain);
  return (
    (r.name === d && r.type === "TXT" && /^v=spf1/i.test(r.value)) ||
    (r.name === `_dmarc.${d}` && r.type === "TXT") ||
    r.name.endsWith(`._domainkey.${d}`)
  );
}

/**
 * Compare the email records in the file with live public DNS. Differences usually mean the export
 * is out of date, or the domain's DNS is actually hosted somewhere else.
 */
export async function compareWithLive(records, domain, live) {
  const d = clean(domain);
  const names = [
    { name: d, type: "MX", label: "Mail servers (MX)" },
    { name: d, type: "TXT", label: "SPF", filter: (v) => /^v=spf1/i.test(v) },
    { name: `_dmarc.${d}`, type: "TXT", label: "DMARC", filter: (v) => /^v=DMARC1/i.test(v) },
    ...dkimSelectors(records, d).map((s) => ({ name: `${s}._domainkey.${d}`, type: "TXT", label: `DKIM key "${s}"`, viaCname: true })),
  ];
  const norm = (v) => String(v).replace(/\s+/g, " ").trim().toLowerCase().replace(/\.$/, "");
  if (!(await dnsReachable(live))) return names.map((n) => ({ name: n.name, type: n.type, label: n.label, file: [], live: null, match: null, note: "Couldn't reach live DNS" }));
  const out = [];
  for (const n of names) {
    let fileVals = records.filter((r) => r.name === n.name && r.type === n.type).map((r) => (n.type === "MX" ? `${r.priority} ${r.value}` : r.value));
    if (n.viaCname && !fileVals.length) {
      const c = records.find((r) => r.name === n.name && r.type === "CNAME");
      if (c) fileVals = [`CNAME → ${c.value}`];
    }
    if (n.filter) fileVals = fileVals.filter(n.filter);
    let liveVals;
    try {
      if (n.type === "MX") liveVals = (await live.resolveMx(n.name)).map((m) => `${m.priority} ${clean(m.exchange)}`);
      else liveVals = (await live.resolveTxt(n.name)).map((c) => c.join(""));
      if (n.filter) liveVals = liveVals.filter(n.filter);
    } catch (err) {
      if (["ENOTFOUND", "ENODATA"].includes(err.code)) liveVals = [];
      else {
        out.push({ ...n, filter: undefined, file: fileVals, live: null, match: null, note: "Couldn't check live DNS" });
        continue;
      }
    }
    // A DKIM CNAME in the file resolves to the provider's key live; we can't compare text, only presence.
    const match = fileVals[0]?.startsWith("CNAME → ")
      ? liveVals.length > 0
      : fileVals.length === liveVals.length && fileVals.map(norm).sort().join("|") === liveVals.map(norm).sort().join("|");
    out.push({ name: n.name, type: n.type, label: n.label, file: fileVals, live: liveVals, match });
  }
  return out;
}
