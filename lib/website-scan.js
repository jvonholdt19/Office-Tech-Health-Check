// Website Security Check: composes the passive checks in lib/checks/website-security.js into one
// scored report, reusing safely / scoreChecks / gradeFor (via summarizeChecks) from lib/scan.js.
// Website-specific grade caps live here (applyGradeCaps) so the shared email-scanner grading is untouched.
import { isIP } from "node:net";
import { defaultDeps, fetchChain } from "./net.js";
import { normalizeDomain } from "./domain.js";
import { safely, summarizeChecks } from "./scan.js";
import {
  httpsResponse,
  hostsVisited,
  checkCertificate,
  checkTlsDetails,
  checkCors,
  checkSri,
  checkHttpsAvailable,
  checkHttpRedirect,
  checkHsts,
  checkCsp,
  checkFraming,
  checkNosniff,
  checkReferrerPolicy,
  checkPermissionsPolicy,
  checkCookies,
  checkMixedContent,
  checkVersionDisclosure,
  checkWordPress,
  fetchWordPressVersions,
} from "./checks/website-security.js";

/**
 * Turn "acme.com", "https://www.acme.com/contact" or "http://acme.com" into the host to check.
 * Only http/https, only the default port, no user:pass@, no IP literals. Any path, query or fragment
 * is dropped: the check always starts from the homepage. Returns { host } or { error }.
 */
export function parseWebsiteTarget(input) {
  if (typeof input !== "string" || !input.trim()) return { error: "Enter a website, like acmeaccounting.com." };
  const raw = input.trim();
  if (raw.length > 2048) return { error: "That address is too long." };
  const hasScheme = /^[a-z][a-z0-9+.-]*:/i.test(raw) && !/^[^/:]+:\d+(?:[/?#]|$)/.test(raw);
  if (hasScheme && !/^https?:\/\//i.test(raw)) return { error: "Only http:// and https:// websites can be checked." };
  let url;
  try {
    url = new URL(hasScheme ? raw : `https://${raw}`);
  } catch {
    return { error: "That doesn't look like a valid website address." };
  }
  if (url.username || url.password) return { error: "Enter the website address without a username or password." };
  // Only the host is used, so an explicit :80 or :443 is harmless; anything else is refused.
  if (url.port !== "" && url.port !== "80" && url.port !== "443") return { error: "Only websites on the standard ports (80 and 443) can be checked." };
  const hostname = url.hostname.replace(/\.$/, "");
  if (isIP(hostname) || hostname.startsWith("[")) return { error: "Enter a domain name, not an IP address." };
  const parsed = normalizeDomain(hostname);
  if (parsed.error) return { error: parsed.error };
  return { host: parsed.domain };
}

const GRADE_ORDER = ["A", "B", "C", "D", "F"];

/**
 * Hard caps on top of the weighted score (the score number itself is not changed):
 *   no working HTTPS, an https → http downgrade, or an invalid/expired/untrusted certificate → F
 *     (SSL Labs grades untrusted certificates T/F; Observatory takes 20–50 points off);
 *   TLS older than 1.2 → at most B (SSL Labs caps TLS 1.0/1.1 at B);
 *   plain HTTP not redirected to HTTPS → at most C.
 * Returns { grade, cappedBy } where cappedBy lists every cap that applied (worst first).
 */
export function applyGradeCaps(grade, checks) {
  const by = Object.fromEntries(checks.map((c) => [c.id, c]));
  const code = (id) => by[id]?.data?.code;
  const caps = [];
  if (by.https?.status === "fail" && code("https") === "no-https") caps.push({ check: "https", maxGrade: "F", reason: "the site doesn't work over HTTPS" });
  if (by.https?.status === "fail" && code("https") === "downgrade") caps.push({ check: "https", maxGrade: "F", reason: "the HTTPS address redirects back to plain HTTP" });
  if (by.ssl?.status === "fail" && code("ssl") === "invalid") caps.push({ check: "ssl", maxGrade: "F", reason: "the certificate is invalid, expired or not trusted" });
  if (by["tls-details"]?.status === "fail" && code("tls-details") === "old-tls") caps.push({ check: "tls-details", maxGrade: "B", reason: "the server only supports TLS older than 1.2" });
  if (by["https-redirect"]?.status === "warn" && code("https-redirect") === "no-redirect") caps.push({ check: "https-redirect", maxGrade: "C", reason: "plain HTTP isn't redirected to HTTPS" });
  caps.sort((a, b) => GRADE_ORDER.indexOf(b.maxGrade) - GRADE_ORDER.indexOf(a.maxGrade));
  if (!grade || !caps.length) return { grade, cappedBy: caps };
  const worst = caps[0].maxGrade;
  return { grade: GRADE_ORDER.indexOf(grade) < GRADE_ORDER.indexOf(worst) ? worst : grade, cappedBy: caps };
}

/** Try the bare domain first, then www (many small-business sites only answer on www). */
async function chainFor(scheme, host, deps) {
  const opts = { scope: host, resolver: deps.resolver, fetch: deps.fetchPage, budgetMs: deps.budgetMs };
  const first = await fetchChain(`${scheme}://${host}/`, opts);
  if (first.ok || first.refused) return first;
  const www = await fetchChain(`${scheme}://www.${host}/`, opts);
  return www.ok ? www : first;
}

export async function runWebsiteScan(input, overrides = {}) {
  const target = parseWebsiteTarget(input);
  if (target.error) return { error: target.error };
  const { host } = target;
  const deps = {
    ...defaultDeps,
    wordpressVersions: () => fetchWordPressVersions(),
    budgetMs: 18_000,
    ...testDeps,
    ...overrides,
  };
  const started = Date.now();

  // One TLS handshake per host (apex and www), as before; minVersion lets a TLS 1.0/1.1-only server
  // complete it so the old protocol can be reported instead of looking unreachable.
  const tlsHosts = [host, `www.${host}`];
  const [https, http, tls] = await Promise.all([
    chainFor("https", host, deps),
    chainFor("http", host, deps),
    Promise.all(tlsHosts.map((h) => Promise.resolve(deps.inspectTls(h, { minVersion: "TLSv1" })).then((r) => ({ host: h, ...r }), (err) => ({ host: h, ok: false, error: err.message })))),
  ]);
  const usesWww = [...hostsVisited(https, http)].some((h) => h === `www.${host}`);
  const ctx = { host, https, http };
  const res = httpsResponse(https);
  const meta = (id, title, category, weight) => ({ id, title, category, weight });

  const checks = [
    await safely(meta("https", "Website loads over HTTPS", "Encryption", 15), () => checkHttpsAvailable(ctx)),
    await safely(meta("https-redirect", "Sends visitors from HTTP to HTTPS", "Encryption", 10), () => checkHttpRedirect(ctx)),
    await safely(meta("ssl", "Security certificate (SSL/TLS)", "Encryption", 15), () => checkCertificate({ host, tls, usesWww }, deps)),
    await safely(meta("tls-details", "TLS version and key", "Encryption", 0), () => checkTlsDetails({ host, tls })),
    await safely(meta("hsts", "Strict-Transport-Security (HSTS)", "Browser protections", 8), () => checkHsts(res, ctx)),
    await safely(meta("clickjacking", "Clickjacking protection", "Browser protections", 6), () => checkFraming(res)),
    await safely(meta("nosniff", "X-Content-Type-Options", "Browser protections", 4), () => checkNosniff(res)),
    await safely(meta("csp", "Content-Security-Policy", "Browser protections", 5), () => checkCsp(res)),
    await safely(meta("referrer-policy", "Referrer-Policy", "Browser protections", 2), () => checkReferrerPolicy(res)),
    await safely(meta("permissions-policy", "Permissions-Policy", "Browser protections", 0), () => checkPermissionsPolicy(res)),
    await safely(meta("cors", "Cross-origin access (CORS)", "Browser protections", 0), () => checkCors(res, host)),
    await safely(meta("cookies", "Cookie security flags", "Page content", 8), () => checkCookies(ctx)),
    await safely(meta("mixed-content", "Mixed content", "Page content", 6), () => checkMixedContent(res)),
    await safely(meta("sri", "Subresource Integrity on third-party scripts", "Page content", 3), () => checkSri(res, host)),
    await safely(meta("version-disclosure", "Server software versions shown", "Software", 3), () => checkVersionDisclosure(res)),
    await safely(meta("cms-wordpress", "WordPress core version", "Software", 8), () => checkWordPress(res, deps)),
  ];

  // Reachability gate: if nothing answered at all, don't pretend the header checks were graded.
  if (!https.ok && !http.ok) {
    for (const c of checks) if (c.id !== "ssl" && c.id !== "tls-details" && c.status !== "info") Object.assign(c, { status: "info", weight: 0, summary: "Not checked: the website couldn't be reached.", fix: null });
  }

  const summary = summarizeChecks(checks);
  const { grade, cappedBy } = applyGradeCaps(summary.grade, checks);
  const fixes = checks.filter((c) => c.fix && (c.status === "fail" || c.status === "warn"));
  const hop = (r) => ({ url: r.url, status: r.status });
  return {
    target: host,
    scannedAt: deps.now().toISOString(),
    durationMs: Date.now() - started,
    finalUrl: res?.url || (http.ok ? http.final.url : null),
    redirects: {
      https: (https.responses || []).map(hop),
      http: (http.responses || []).map(hop),
      stopped: https.stopped || http.stopped ? { https: https.stopped || null, http: http.stopped || null } : null,
    },
    ...summary,
    grade,
    data: { cappedBy: cappedBy.length ? cappedBy : null, uncappedGrade: summary.grade },
    checks,
    fixes: fixes.map((c) => ({ id: c.id, title: c.title, status: c.status, fix: c.fix })),
  };
}

let testDeps = {};
/** Tests (and only tests) replace the network layer here, like setStoreForTests. */
export function setWebsiteDepsForTests(deps) {
  testDeps = deps || {};
}
