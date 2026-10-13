import { promises as dnsPromises } from "node:dns";
import tls from "node:tls";
import http from "node:http";
import net from "node:net";

/** Reject a promise if it takes longer than `ms`. */
export function withTimeout(promise, ms, label = "operation") {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error(`${label} timed out`), { code: "ETIMEOUT" })), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

const NOT_FOUND = new Set(["ENODATA", "ENOTFOUND", "ENOTIMP", "NXDOMAIN"]);

/** True when a DNS error just means "no such record" rather than a lookup failure. */
export function isNotFound(err) {
  return Boolean(err && NOT_FOUND.has(err.code));
}

/** Join TXT record chunks and return [] instead of throwing for missing records. */
export async function txtRecords(resolver, name) {
  try {
    const rows = await withTimeout(resolver.resolveTxt(name), 8000, `TXT ${name}`);
    return rows.map((chunks) => chunks.join(""));
  } catch (err) {
    if (isNotFound(err)) return [];
    throw err;
  }
}

export async function mxRecords(resolver, name) {
  try {
    const rows = await withTimeout(resolver.resolveMx(name), 5000, `MX ${name}`);
    return rows.sort((a, b) => a.priority - b.priority);
  } catch (err) {
    if (isNotFound(err)) return [];
    throw err;
  }
}

/* ------------------------------------------------------------------ */
/* SSRF guard: only connect to public addresses                        */
/* ------------------------------------------------------------------ */

const blocked = new net.BlockList();
for (const [addr, prefix] of [
  ["0.0.0.0", 8], // "this network" / unspecified
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local, incl. cloud metadata 169.254.169.254
  ["172.16.0.0", 12],
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.168.0.0", 16],
  ["198.18.0.0", 15], // benchmarking
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, incl. broadcast
]) blocked.addSubnet(addr, prefix, "ipv4");
for (const [addr, prefix] of [
  ["::", 128], // unspecified
  ["::1", 128], // loopback
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["ff00::", 8], // multicast
  ["64:ff9b::", 96], // NAT64 (embeds an IPv4 address)
  ["2002::", 16], // 6to4 (embeds an IPv4 address)
]) blocked.addSubnet(addr, prefix, "ipv6");

/** The IPv4 address inside an IPv4-mapped/compatible IPv6 address (::ffff:10.0.0.1, ::ffff:a00:1), or null. */
function embeddedIpv4(addr) {
  const m = String(addr).toLowerCase().match(/^(?:0{0,4}:){0,5}(?:ffff:)?(?:(\d+\.\d+\.\d+\.\d+)|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/);
  if (!m || !/^(::|0{1,4}:)/.test(String(addr).toLowerCase())) return null;
  if (m[1]) return m[1];
  const hi = parseInt(m[2], 16);
  const lo = parseInt(m[3], 16);
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

/** True for addresses a scan must never connect to (private, loopback, link-local, CGNAT, multicast, …). */
export function isNonPublicAddress(addr) {
  const family = net.isIP(addr);
  if (family === 4) return blocked.check(addr, "ipv4");
  if (family === 6) {
    // IPv4-mapped/compatible forms (::ffff:10.0.0.1, ::ffff:a00:1) are refused outright: a public
    // site publishes its IPv4 address in an A record, never like this.
    if (embeddedIpv4(addr)) return true;
    return blocked.check(addr, "ipv6");
  }
  return true; // not an IP at all
}

/**
 * Resolve A and AAAA for `host` and return one vetted public address to connect to. Refuses the
 * host when ANY address is non-public, so a name can't mix a public and a private answer.
 * Returns { ok: true, address, family } or { ok: false, error }.
 */
export async function resolvePublicAddress(host, resolver = dnsPromises) {
  const addrs = [];
  let lookupError = null;
  for (const [fn, family] of [["resolve4", 4], ["resolve6", 6]]) {
    try {
      for (const a of await withTimeout(resolver[fn](host), 5000, `${fn} ${host}`)) addrs.push({ address: a, family });
    } catch (err) {
      if (!isNotFound(err)) lookupError = err;
    }
  }
  if (!addrs.length) return { ok: false, error: lookupError ? lookupError.code || lookupError.message : "ENOTFOUND" };
  if (addrs.some((a) => isNonPublicAddress(a.address))) return { ok: false, error: "non-public address" };
  return { ok: true, ...(addrs.find((a) => a.family === 4) || addrs[0]) };
}

/**
 * Open a TLS connection and report on the certificate the server presents.
 * The host is resolved and vetted first, and the connection goes to that exact IP (with SNI set
 * to the host), so a DNS answer can't be swapped for a private address in between (rebinding).
 * Never throws: connection problems are returned as { ok: false, error }.
 */
export async function inspectTls(host, { timeoutMs = 7000, resolver = dnsPromises, connect = tls.connect } = {}) {
  const target = await resolvePublicAddress(host, resolver);
  if (!target.ok) return { ok: false, error: target.error };
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    const socket = connect({ host: target.address, port: 443, servername: host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      const cert = socket.getPeerCertificate();
      done({
        ok: true,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        validTo: cert && cert.valid_to ? new Date(cert.valid_to).toISOString() : null,
        issuer: cert && cert.issuer ? cert.issuer.O || cert.issuer.CN || null : null,
        subjectAltNames: cert && cert.subjectaltname ? cert.subjectaltname : null,
        protocol: socket.getProtocol(),
      });
    });
    socket.on("timeout", () => done({ ok: false, error: "Connection timed out" }));
    socket.on("error", (err) => done({ ok: false, error: err.code || err.message }));
  });
}

/**
 * Request http://host/ without following redirects to see whether the site
 * pushes visitors onto HTTPS. Connects only to a vetted public IP. Never throws.
 */
export async function probeHttp(host, { timeoutMs = 7000, resolver = dnsPromises, request = http.request } = {}) {
  const target = await resolvePublicAddress(host, resolver);
  if (!target.ok) return { ok: false, error: target.error };
  return new Promise((resolve) => {
    // Connect to the vetted IP; the Host header keeps virtual hosting working.
    const req = request({ host: target.address, port: 80, path: "/", method: "GET", timeout: timeoutMs, headers: { Host: host, "User-Agent": "OfficeTechHealthCheck/0.1" } }, (res) => {
      res.resume();
      resolve({ ok: true, status: res.statusCode, location: res.headers.location || null });
    });
    req.on("timeout", () => {
      req.destroy();
      resolve({ ok: false, error: "Connection timed out" });
    });
    req.on("error", (err) => resolve({ ok: false, error: err.code || err.message }));
    req.end();
  });
}

const RDAP_HEADERS = {
  Accept: "application/rdap+json, application/json",
  "User-Agent": "OfficeTechHealthCheck/0.2 (+https://office-tech-health-check.vercel.app)",
};

// Registries for the most common extensions, so most lookups skip the bootstrap fetch.
const KNOWN_RDAP = {
  com: "https://rdap.verisign.com/com/v1/",
  net: "https://rdap.verisign.com/net/v1/",
  org: "https://rdap.publicinterestregistry.org/rdap/",
};
let bootstrapCache = null; // { at, services }

/** IANA's official list of which registry answers RDAP for each extension. */
async function rdapBaseFor(tld, fetchImpl, timeoutMs) {
  if (KNOWN_RDAP[tld]) return KNOWN_RDAP[tld];
  if (!bootstrapCache || Date.now() - bootstrapCache.at > 24 * 60 * 60 * 1000) {
    const res = await withTimeout(fetchImpl("https://data.iana.org/rdap/dns.json", { headers: RDAP_HEADERS }), timeoutMs, "RDAP bootstrap");
    if (!res.ok) throw new Error(`bootstrap HTTP ${res.status}`);
    bootstrapCache = { at: Date.now(), services: (await res.json()).services || [] };
  }
  const svc = bootstrapCache.services.find(([tlds]) => tlds.includes(tld));
  return svc ? svc[1][0] : null;
}

async function rdapGet(url, fetchImpl, timeoutMs) {
  const res = await withTimeout(fetchImpl(url, { headers: RDAP_HEADERS, redirect: "follow" }), timeoutMs, "RDAP lookup");
  if (!res.ok) return { ok: false, error: `HTTP ${res.status}`, status: res.status };
  return { ok: true, data: await res.json() };
}

/**
 * Fetch registration data via RDAP (the modern replacement for WHOIS), asking the
 * registry that runs the extension directly, with rdap.org as a fallback. Never throws.
 * Returns { ok:false, unsupported:true } when the extension has no public RDAP service.
 */
export async function fetchRdap(domain, { fetchImpl = globalThis.fetch, timeoutMs = 7000 } = {}) {
  const tld = domain.split(".").pop();
  const errors = [];
  try {
    const base = await rdapBaseFor(tld, fetchImpl, timeoutMs);
    if (base) {
      const r = await rdapGet(`${base.replace(/\/?$/, "/")}domain/${encodeURIComponent(domain)}`, fetchImpl, timeoutMs);
      if (r.ok || r.status === 404) return r;
      errors.push(`registry ${r.error}`);
    } else {
      return { ok: false, unsupported: true, error: `.${tld} registry doesn't publish RDAP data` };
    }
  } catch (err) {
    errors.push(err.code || err.message);
  }
  try {
    const r = await rdapGet(`https://rdap.org/domain/${encodeURIComponent(domain)}`, fetchImpl, timeoutMs);
    if (r.ok) return r;
    errors.push(`rdap.org ${r.error}`);
  } catch (err) {
    errors.push(err.code || err.message);
  }
  return { ok: false, error: errors.join("; ") };
}

export const defaultDeps = {
  resolver: dnsPromises,
  inspectTls,
  probeHttp,
  fetchRdap,
  now: () => new Date(),
};
