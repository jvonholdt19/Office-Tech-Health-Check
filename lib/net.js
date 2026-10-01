import { promises as dnsPromises } from "node:dns";
import tls from "node:tls";
import http from "node:http";

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

/**
 * Open a TLS connection and report on the certificate the server presents.
 * Never throws: connection problems are returned as { ok: false, error }.
 */
export function inspectTls(host, { timeoutMs = 7000 } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
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
 * pushes visitors onto HTTPS. Never throws.
 */
export function probeHttp(host, { timeoutMs = 7000 } = {}) {
  return new Promise((resolve) => {
    const req = http.request({ host, port: 80, path: "/", method: "GET", timeout: timeoutMs, headers: { "User-Agent": "OfficeTechHealthCheck/0.1" } }, (res) => {
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

/** Fetch registration data via RDAP (the modern replacement for WHOIS). Never throws. */
export async function fetchRdap(domain, { fetchImpl = globalThis.fetch, timeoutMs = 7000 } = {}) {
  try {
    const res = await withTimeout(
      fetchImpl(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        headers: { Accept: "application/rdap+json, application/json" },
        redirect: "follow",
      }),
      timeoutMs,
      "RDAP lookup",
    );
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    return { ok: true, data: await res.json() };
  } catch (err) {
    return { ok: false, error: err.code || err.message };
  }
}

export const defaultDeps = {
  resolver: dnsPromises,
  inspectTls,
  probeHttp,
  fetchRdap,
  now: () => new Date(),
};
