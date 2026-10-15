// Website Security Check (technician tool). Every check is passive: it only looks at the responses
// to plain GETs of the homepage and its redirects (see fetchChain in lib/net.js), plus the TLS
// certificate. No payloads, no path probing, no crawling.
//
// Weights (out of 100 when every check applies; our own judgment, not an industry standard):
//   HTTPS available 15 · HTTP → HTTPS redirect 10 · Certificate (checkSsl) 15 · HSTS 10
//   Clickjacking protection 8 · Cookies 8 · CSP 6 · nosniff 5 · Mixed content 5 · Version disclosure 4
//   Referrer-Policy 3 · Permissions-Policy 3 · WordPress core version 8 (only when WordPress is detected)

import { withTimeout } from "../net.js";

const CAT_TRANSPORT = "Encryption";
const CAT_HEADERS = "Browser protections";
const CAT_CONTENT = "Page content";
const CAT_SOFTWARE = "Software";

const SIX_MONTHS = 15_552_000; // 180 days, in seconds

/** Header value as one string (Node joins most repeated headers; set-cookie stays an array). */
function header(headers, name) {
  const v = headers?.[name];
  if (v === undefined || v === null) return null;
  return Array.isArray(v) ? v.join(", ") : String(v);
}

const short = (s, n = 160) => (s.length > n ? `${s.slice(0, n)}…` : s);

/** The response the header checks are graded on: the last HTTPS response of the chain, or null. */
export function httpsResponse(chain) {
  if (!chain?.ok) return null;
  return [...(chain.responses || [])].reverse().find((r) => /^https:/i.test(r.url)) || null;
}

/** Header checks only make sense on an HTTPS page; without one they're left out (the HTTPS check fails instead). */
function noHttpsRow(base) {
  return {
    ...base,
    status: "info",
    weight: 0,
    summary: "Not checked: the site didn't answer over HTTPS, so there was no secure page to inspect.",
    detail: "No HTTPS response to inspect.",
    fix: null,
  };
}

/* ------------------------------------------------------------------ */
/* 1. HTTPS available, HTTP → HTTPS redirect                           */
/* ------------------------------------------------------------------ */

export function checkHttpsAvailable({ host, https, http }) {
  const base = { id: "https", category: CAT_TRANSPORT, title: "Website loads over HTTPS", weight: 15 };
  const res = httpsResponse(https);
  if (!res) {
    if (!http?.ok) {
      return { ...base, status: "info", weight: 0, summary: `We couldn't reach a website at ${host} over HTTPS or HTTP.`, detail: `HTTPS: ${https?.error || "no answer"}; HTTP: ${http?.error || "no answer"}`, fix: null };
    }
    return {
      ...base,
      status: "fail",
      summary: "The website only works without encryption, so anything typed into it (contact forms, logins) can be read or changed in transit.",
      detail: `HTTPS: ${https?.error || "no answer"}`,
      data: { code: "no-https" },
      fix: "Turn on HTTPS at the web host. Free, auto-renewing certificates (Let's Encrypt) are standard on almost every host.",
    };
  }
  const final = https.final;
  if (https.downgraded || (final && /^http:/i.test(final.url))) {
    return {
      ...base,
      status: "fail",
      summary: "The secure (HTTPS) address redirects visitors back to an unencrypted http:// page.",
      detail: (https.responses || []).map((r) => `${r.status} ${r.url}`).join(" → "),
      data: { code: "downgrade" },
      fix: "Remove the redirect from https:// to http:// and serve the whole site over HTTPS.",
    };
  }
  const note = res.status >= 400 ? ` (the page answered with HTTP ${res.status}, so the results below are for that response)` : "";
  return { ...base, status: "pass", summary: `The website loads over an encrypted HTTPS connection${note}.`, detail: `${res.status} ${res.url}`, fix: null };
}

export function checkHttpRedirect({ http }) {
  const base = { id: "https-redirect", category: CAT_TRANSPORT, title: "Sends visitors from HTTP to HTTPS", weight: 10 };
  if (!http?.ok) return { ...base, status: "info", weight: 0, summary: "We couldn't reach the website over plain HTTP to test this.", detail: http?.error || "no answer", fix: null };
  const path = http.responses.map((r) => `${r.status} ${r.url}`).join(" → ");
  const final = http.final;
  // Pass when the plain-HTTP chain ends on (or is redirected to) an https:// address.
  const landsOnHttps = /^https:/i.test(final.url) || (http.stopped?.location && /^https:/i.test(http.stopped.location) && final.status >= 300 && final.status < 400);
  if (landsOnHttps) {
    return { ...base, status: "pass", summary: "Visitors who type the address without https:// are moved to the secure version.", detail: `${path}${http.stopped?.location ? ` → ${http.stopped.location}` : ""}`, fix: null };
  }
  return {
    ...base,
    status: "warn",
    summary: "The website still loads without encryption when someone types the address without https://.",
    detail: path,
    data: { code: "no-redirect" },
    fix: "Turn on the hosting provider's automatic HTTP → HTTPS redirect.",
  };
}

/* ------------------------------------------------------------------ */
/* 3. Security headers                                                 */
/* ------------------------------------------------------------------ */

export function checkHsts(res) {
  const base = { id: "hsts", category: CAT_HEADERS, title: "Strict-Transport-Security (HSTS)", weight: 10 };
  if (!res) return { ...base, status: "fail", summary: "Without HTTPS there is no HSTS, so browsers can be tricked onto an unencrypted connection.", detail: "No HTTPS response.", fix: "Turn on HTTPS first, then add a Strict-Transport-Security header." };
  const v = header(res.headers, "strict-transport-security");
  const fix = "Add the header Strict-Transport-Security: max-age=31536000; includeSubDomains (at the host, CDN or security plugin).";
  if (!v) return { ...base, status: "fail", summary: "Browsers aren't told to always use HTTPS for this site, so a first visit on public Wi-Fi can be downgraded.", detail: "Strict-Transport-Security header missing.", data: { code: "missing" }, fix };
  const m = v.match(/max-age\s*=\s*"?(\d+)"?/i);
  const age = m ? Number(m[1]) : null;
  if (age === null || age === 0) return { ...base, status: "fail", summary: "The HSTS header is present but switched off (no max-age, or max-age=0).", detail: short(v), data: { code: "disabled", maxAge: age }, fix };
  if (age < SIX_MONTHS) {
    return { ...base, status: "warn", summary: `HSTS is on, but only for ${Math.round(age / 86400)} days. Six months or more is recommended.`, detail: short(v), data: { code: "short", maxAge: age }, fix: "Raise max-age to at least 15552000 (six months); 31536000 (one year) is typical." };
  }
  return { ...base, status: "pass", summary: "Browsers are told to always use HTTPS for this site.", detail: short(v), data: { maxAge: age }, fix: null };
}

/** The frame-ancestors directive of a CSP string, or null. */
export function frameAncestors(csp) {
  if (!csp) return null;
  const m = String(csp).match(/(?:^|[;,])\s*frame-ancestors\s+([^;,]*)/i);
  return m ? m[1].trim() : null;
}

/** CSP from the header, or failing that from <meta http-equiv="Content-Security-Policy"> in the page. */
function cspSources(res) {
  const headerCsp = header(res.headers, "content-security-policy");
  const reportOnly = header(res.headers, "content-security-policy-report-only");
  const meta = String(res.body || "").match(/<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/i);
  const metaCsp = meta ? ((m) => (m ? m[1] ?? m[2] : null))(meta[0].match(/\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/i)) : null;
  return { headerCsp, reportOnly, metaCsp };
}

export function checkCsp(res) {
  const base = { id: "csp", category: CAT_HEADERS, title: "Content-Security-Policy", weight: 6 };
  if (!res) return noHttpsRow(base);
  const { headerCsp, reportOnly, metaCsp } = cspSources(res);
  const fix = "Add a Content-Security-Policy that lists where scripts may load from. Start in Report-Only mode so nothing breaks, then enforce it.";
  if (headerCsp) {
    const weak = /script-src[^;]*'unsafe-inline'/i.test(headerCsp) || (!/script-src/i.test(headerCsp) && /default-src[^;]*'unsafe-inline'/i.test(headerCsp));
    return { ...base, status: "pass", summary: weak ? "A Content-Security-Policy is set (it still allows inline scripts, which weakens it)." : "A Content-Security-Policy limits where scripts can load from.", detail: short(headerCsp, 300), data: { unsafeInline: weak }, fix: null };
  }
  if (metaCsp) return { ...base, status: "pass", summary: "A Content-Security-Policy is set inside the page.", detail: `<meta> CSP: ${short(metaCsp, 300)}`, data: { source: "meta" }, fix: null };
  if (reportOnly) return { ...base, status: "warn", summary: "A Content-Security-Policy is only in report-only mode, so it doesn't block anything yet.", detail: short(reportOnly, 300), data: { code: "report-only" }, fix: "Once the reports are clean, switch Content-Security-Policy-Report-Only to Content-Security-Policy." };
  return { ...base, status: "warn", summary: "No Content-Security-Policy. It's an extra layer that limits the damage if a plugin or script is ever compromised.", detail: "Content-Security-Policy header missing.", data: { code: "missing" }, fix };
}

export function checkFraming(res) {
  const base = { id: "clickjacking", category: CAT_HEADERS, title: "Clickjacking protection (X-Frame-Options / frame-ancestors)", weight: 8 };
  if (!res) return noHttpsRow(base);
  const fa = frameAncestors(header(res.headers, "content-security-policy"));
  const xfo = header(res.headers, "x-frame-options");
  if (fa && fa !== "*") return { ...base, status: "pass", summary: "Other sites can't embed this site in a hidden frame to trick visitors into clicking.", detail: `CSP frame-ancestors ${fa}${xfo ? `; X-Frame-Options: ${xfo}` : ""}`, fix: null };
  if (xfo && /^\s*(deny|sameorigin)\s*$/i.test(xfo)) return { ...base, status: "pass", summary: "Other sites can't embed this site in a hidden frame to trick visitors into clicking.", detail: `X-Frame-Options: ${xfo}`, fix: null };
  const fix = "Add X-Frame-Options: SAMEORIGIN (or a CSP frame-ancestors 'self' directive).";
  if (xfo || fa) return { ...base, status: "warn", summary: "A framing rule is set, but browsers ignore this value.", detail: xfo ? `X-Frame-Options: ${xfo}` : `CSP frame-ancestors ${fa}`, data: { code: "weak" }, fix };
  return { ...base, status: "fail", summary: "Any website can load this site inside an invisible frame and trick visitors into clicking buttons on it (clickjacking).", detail: "X-Frame-Options and CSP frame-ancestors both missing.", data: { code: "missing" }, fix };
}

export function checkNosniff(res) {
  const base = { id: "nosniff", category: CAT_HEADERS, title: "X-Content-Type-Options", weight: 5 };
  if (!res) return noHttpsRow(base);
  const v = header(res.headers, "x-content-type-options");
  if (v && /nosniff/i.test(v)) return { ...base, status: "pass", summary: "Browsers won't guess file types, which blocks a class of content-injection tricks.", detail: `X-Content-Type-Options: ${v}`, fix: null };
  return { ...base, status: "fail", summary: "Browsers may guess file types on this site, which lets an uploaded file be run as a script.", detail: v ? `X-Content-Type-Options: ${v}` : "X-Content-Type-Options header missing.", data: { code: "missing" }, fix: "Add the header X-Content-Type-Options: nosniff." };
}

export function checkReferrerPolicy(res) {
  const base = { id: "referrer-policy", category: CAT_HEADERS, title: "Referrer-Policy", weight: 3 };
  if (!res) return noHttpsRow(base);
  const v = header(res.headers, "referrer-policy");
  const fix = "Add Referrer-Policy: strict-origin-when-cross-origin.";
  if (!v) return { ...base, status: "warn", summary: "No Referrer-Policy. Modern browsers default to a safe setting, but setting it explicitly protects older ones.", detail: "Referrer-Policy header missing.", data: { code: "missing" }, fix };
  // The last valid token wins in browsers; flag the two that leak full URLs to other sites.
  const last = v.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean).at(-1);
  if (last === "unsafe-url" || last === "no-referrer-when-downgrade") return { ...base, status: "warn", summary: "The Referrer-Policy sends full page addresses to other websites.", detail: `Referrer-Policy: ${v}`, data: { code: "leaky" }, fix };
  return { ...base, status: "pass", summary: "Page addresses aren't leaked to other websites when visitors click links.", detail: `Referrer-Policy: ${v}`, fix: null };
}

export function checkPermissionsPolicy(res) {
  const base = { id: "permissions-policy", category: CAT_HEADERS, title: "Permissions-Policy", weight: 3 };
  if (!res) return noHttpsRow(base);
  const v = header(res.headers, "permissions-policy");
  if (v) return { ...base, status: "pass", summary: "The site limits which browser features (camera, microphone, location) pages can use.", detail: `Permissions-Policy: ${short(v, 300)}`, fix: null };
  return { ...base, status: "warn", summary: "No Permissions-Policy. It's an optional extra that stops embedded scripts from asking for the camera, microphone or location.", detail: "Permissions-Policy header missing.", data: { code: "missing" }, fix: "Add Permissions-Policy: camera=(), microphone=(), geolocation=() (allow only what the site uses)." };
}

/* ------------------------------------------------------------------ */
/* 4. Cookies                                                          */
/* ------------------------------------------------------------------ */

// Cookies that scripts on the page are meant to read (analytics, consent banners, CSRF tokens, UI
// preferences). Missing HttpOnly on these is normal, so it's reported as info only.
const CLIENT_READABLE = /^(_ga|_gid|_gat|_gcl|_fbp|_fbc|_hj|_clck|_clsk|__utm|_pk_|_uet|ajs_|amplitude|mp_|optimizely|cookie_?consent|cookieyes|cky-|cmplz|borlabs|euconsent|optanon|_?x?csrf|xsrf|wp-settings|wp_lang|pll_language|lang$|locale$|currency$|theme$|timezone$|tz$)/i;

/** Parse Set-Cookie header lines into { name, secure, httpOnly, sameSite }. Values are never kept. */
export function parseSetCookies(lines) {
  const list = Array.isArray(lines) ? lines : lines ? [lines] : [];
  const out = [];
  for (const line of list) {
    const [pair, ...attrs] = String(line).split(";");
    const eq = pair.indexOf("=");
    const name = (eq === -1 ? pair : pair.slice(0, eq)).trim();
    if (!name) continue;
    const a = attrs.map((x) => x.trim().toLowerCase());
    const sameSite = a.find((x) => x.startsWith("samesite"));
    out.push({
      name: name.slice(0, 100),
      secure: a.includes("secure"),
      httpOnly: a.includes("httponly"),
      sameSite: sameSite ? (sameSite.split("=")[1] || "").trim() || null : null,
    });
  }
  return out;
}

export function checkCookies({ https, http }) {
  const base = { id: "cookies", category: CAT_CONTENT, title: "Cookie security flags", weight: 8 };
  const chain = httpsResponse(https) ? https : http?.ok ? http : null;
  if (!chain) return noHttpsRow(base);
  const overHttps = chain === https;
  // Cookies set anywhere on the way to the homepage (redirect hops included). Later ones win by name.
  const byName = new Map();
  for (const r of chain.responses) for (const c of parseSetCookies(r.headers?.["set-cookie"])) byName.set(c.name, c);
  const cookies = [...byName.values()];
  if (!cookies.length) return { ...base, status: "pass", summary: "The homepage doesn't set any cookies.", detail: "No Set-Cookie headers.", data: { cookies: [] }, fix: null };

  const problems = [];
  const notes = [];
  let worst = "pass";
  const bump = (s) => (worst = s === "fail" || worst === "fail" ? "fail" : s === "warn" || worst === "warn" ? "warn" : worst);
  for (const c of cookies) {
    const missing = [];
    if (!c.secure) {
      missing.push("Secure");
      bump(overHttps ? "fail" : "warn");
    }
    if (!c.httpOnly) {
      if (CLIENT_READABLE.test(c.name)) notes.push(`${c.name}: no HttpOnly (normal for a cookie scripts need to read)`);
      else {
        missing.push("HttpOnly");
        bump("warn");
      }
    }
    if (!c.sameSite) {
      missing.push("SameSite");
      bump("warn");
    } else if (c.sameSite === "none" && !c.secure) {
      missing.push("Secure (required with SameSite=None)");
      bump("warn");
    }
    if (missing.length) problems.push(`${c.name}: missing ${missing.join(", ")}`);
  }
  const data = { cookies: cookies.map(({ name, secure, httpOnly, sameSite }) => ({ name, secure, httpOnly, sameSite })) };
  const detail = [...problems, ...notes].join("; ") || cookies.map((c) => `${c.name}: Secure, HttpOnly, SameSite=${c.sameSite}`).join("; ");
  if (worst === "pass") {
    return { ...base, status: "pass", summary: `All ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} set by the homepage ${cookies.length === 1 ? "has" : "have"} the right security flags.`, detail, data, fix: null };
  }
  return {
    ...base,
    status: worst,
    summary: worst === "fail"
      ? "Some cookies can be sent over unencrypted connections (no Secure flag), where they can be stolen."
      : "Some cookies are missing recommended security flags.",
    detail,
    data,
    fix: "Set Secure, HttpOnly and SameSite=Lax on the site's cookies (in the CMS, plugin or server settings). Cookie names are listed in the details.",
  };
}

/* ------------------------------------------------------------------ */
/* 5. Mixed content hints                                              */
/* ------------------------------------------------------------------ */

const LINK_RELS = /\b(stylesheet|icon|preload|modulepreload|manifest|apple-touch-icon)\b/i;

/** http:// URLs in src=, <link href> (stylesheets, icons, preloads) and <form action> of an HTML page. */
export function findMixedContent(html) {
  const found = [];
  const s = String(html || "");
  const attr = (tag, name) => {
    const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
    return m ? (m[1] ?? m[2] ?? m[3] ?? "").trim() : null;
  };
  for (const m of s.matchAll(/<(script|img|iframe|frame|audio|video|source|embed|track|input)\b[^>]*>/gi)) {
    const v = attr(m[0], "src");
    if (v && /^http:\/\//i.test(v)) found.push({ tag: m[1].toLowerCase(), url: v });
  }
  for (const m of s.matchAll(/<link\b[^>]*>/gi)) {
    const v = attr(m[0], "href");
    if (v && /^http:\/\//i.test(v) && LINK_RELS.test(attr(m[0], "rel") || "")) found.push({ tag: "link", url: v });
  }
  for (const m of s.matchAll(/<form\b[^>]*>/gi)) {
    const v = attr(m[0], "action");
    if (v && /^http:\/\//i.test(v)) found.push({ tag: "form", url: v });
  }
  return found;
}

export function checkMixedContent(res) {
  const base = { id: "mixed-content", category: CAT_CONTENT, title: "Mixed content (http:// on a secure page)", weight: 5 };
  if (!res || !/^https:/i.test(res.url)) return { ...base, status: "info", weight: 0, summary: "Only checked on pages served over HTTPS.", detail: "No HTTPS page to inspect.", fix: null };
  if (res.status >= 300 && res.status < 400) return { ...base, status: "info", weight: 0, summary: "The homepage redirects somewhere we didn't follow, so there was no page to inspect.", detail: `${res.status} ${res.url}`, fix: null };
  const found = findMixedContent(res.body);
  const note = res.truncated ? " (only the first 1 MB of the page was read)" : "";
  if (!found.length) return { ...base, status: "pass", summary: "No insecure http:// scripts, images, styles or forms were found in the homepage.", detail: `Scanned the homepage HTML${note}.`, fix: null };
  const forms = found.filter((f) => f.tag === "form").length;
  return {
    ...base,
    status: "warn",
    summary: forms
      ? "A form on the secure homepage sends its data to an unencrypted http:// address."
      : "The secure homepage loads some files over unencrypted http://. Browsers block or flag these.",
    detail: `${found.length} hint${found.length === 1 ? "" : "s"}${note}: ${found.slice(0, 5).map((f) => `<${f.tag}> ${short(f.url, 100)}`).join("; ")}${found.length > 5 ? "; …" : ""}`,
    data: { count: found.length, forms },
    fix: "Change these links to https:// (or to relative paths). A search-and-replace plugin or the theme settings usually fixes it in minutes.",
  };
}

/* ------------------------------------------------------------------ */
/* 6. Version disclosure                                               */
/* ------------------------------------------------------------------ */

const VERSION = /\d+\.\d+/;

export function checkVersionDisclosure(res) {
  const base = { id: "version-disclosure", category: CAT_SOFTWARE, title: "Server software versions shown", weight: 4 };
  if (!res) return noHttpsRow(base);
  const shown = [];
  for (const name of ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]) {
    const v = header(res.headers, name);
    if (v && VERSION.test(v)) shown.push(`${name}: ${short(v, 80)}`);
  }
  if (!shown.length) {
    const named = ["server", "x-powered-by"].map((n) => header(res.headers, n) && `${n}: ${short(header(res.headers, n), 80)}`).filter(Boolean);
    return { ...base, status: "pass", summary: "The server doesn't advertise its software version numbers.", detail: named.join("; ") || "No Server or X-Powered-By header.", fix: null };
  }
  return {
    ...base,
    status: "warn",
    summary: "The server announces exact software versions, which makes it easy to look up known weaknesses for those versions.",
    detail: shown.join("; "),
    data: { code: "versions-shown" },
    fix: "Hide version numbers (e.g. Apache ServerTokens Prod, nginx server_tokens off, PHP expose_php = Off) and keep that software updated.",
  };
}

/* ------------------------------------------------------------------ */
/* 7. CMS: WordPress core version                                      */
/* ------------------------------------------------------------------ */

/** WordPress version from <meta name="generator" content="WordPress x.y.z">, plus wp-content hints. */
export function detectWordPress(html) {
  const s = String(html || "");
  let version = null;
  for (const m of s.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = m[0];
    if (!/\bname\s*=\s*["']?generator["']?/i.test(tag)) continue;
    const c = tag.match(/\bcontent\s*=\s*["']?\s*WordPress\s+(\d+\.\d+(?:\.\d+)?)/i);
    if (c) {
      version = c[1];
      break;
    }
  }
  const hints = /\/wp-content\/|\/wp-includes\//i.test(s);
  return { detected: Boolean(version || hints), version };
}

function parseVersion(v) {
  const [maj = 0, min = 0, patch = 0] = String(v).split(".").map((n) => Number(n) || 0);
  return { maj, min, patch };
}
function cmpVersion(a, b) {
  const x = parseVersion(a);
  const y = parseVersion(b);
  return x.maj - y.maj || x.min - y.min || x.patch - y.patch;
}
/** WordPress branches go x.0 … x.9, then (x+1).0, so a branch index is major*10 + minor. */
const branchIndex = (v) => parseVersion(v).maj * 10 + parseVersion(v).min;

export const WP_VERSION_URL = "https://api.wordpress.org/core/version-check/1.7/";
const WP_CACHE_MS = 12 * 60 * 60 * 1000;
let wpCache = null; // { at, value }

export function resetWordPressCache() {
  wpCache = null;
}

/**
 * Latest WordPress release from the free public version-check API (a fixed, trusted URL, so plain
 * fetch is fine here). Cached in memory for 12 hours. Never throws: { ok, latest, versions } or { ok: false, error }.
 */
export async function fetchWordPressVersions({ fetchImpl = globalThis.fetch, timeoutMs = 5000, nowMs = Date.now() } = {}) {
  if (wpCache && nowMs - wpCache.at < WP_CACHE_MS) return wpCache.value;
  try {
    const res = await withTimeout(fetchImpl(WP_VERSION_URL, { headers: { Accept: "application/json", "User-Agent": "OfficeTechHealthCheck/0.3 (+https://officetech.nwimpm.com)" } }), timeoutMs, "WordPress version check");
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const json = await res.json();
    const offers = Array.isArray(json?.offers) ? json.offers : [];
    const versions = [...new Set(offers.flatMap((o) => [o.current, o.version]).filter((v) => typeof v === "string" && /^\d+\.\d+(\.\d+)?$/.test(v)))];
    if (!versions.length) return { ok: false, error: "no versions in the response" };
    const latest = versions.sort(cmpVersion).at(-1);
    const value = { ok: true, latest, versions };
    wpCache = { at: nowMs, value };
    return value;
  } catch (err) {
    return { ok: false, error: err.code || err.message };
  }
}

export async function checkWordPress(res, { wordpressVersions }) {
  const base = { id: "cms-wordpress", category: CAT_SOFTWARE, title: "WordPress core version", weight: 8 };
  if (!res || (res.status >= 300 && res.status < 400)) return { ...base, status: "info", weight: 0, summary: "There was no homepage to inspect for a content management system.", detail: res ? `${res.status} ${res.url}` : "No page.", fix: null };
  const wp = detectWordPress(res.body);
  if (!wp.detected) return { ...base, title: "Content management system", status: "info", weight: 0, summary: "WordPress wasn't detected on the homepage.", detail: "No WordPress generator tag or wp-content paths found.", fix: null };
  if (!wp.version) {
    return { ...base, status: "info", weight: 0, summary: "The site looks like WordPress, but it doesn't publish its version, so it can't be compared from outside.", detail: "wp-content / wp-includes paths found; no generator tag.", data: { cms: "wordpress", version: null }, fix: "Confirm in the WordPress dashboard that core, themes and plugins update automatically." };
  }
  const versions = await wordpressVersions();
  const shown = `Generator tag: WordPress ${wp.version}`;
  if (!versions?.ok) {
    return { ...base, status: "unknown", summary: `The site reports WordPress ${wp.version}, but we couldn't reach WordPress.org to compare it with the latest release.`, detail: `${shown}; version check failed: ${versions?.error || "unknown error"}`, data: { cms: "wordpress", version: wp.version }, fix: null };
  }
  const { latest } = versions;
  const detail = `${shown}; latest release ${latest}`;
  const data = { cms: "wordpress", version: wp.version, latest };
  if (cmpVersion(wp.version, latest) >= 0) return { ...base, status: "pass", summary: `WordPress ${wp.version} is the latest release.`, detail, data, fix: null };
  const behind = branchIndex(latest) - branchIndex(wp.version);
  const fixText = "Back up the site, then update WordPress core (and its plugins and themes) and turn on automatic updates.";
  if (behind > 1) {
    return { ...base, status: "fail", summary: `WordPress ${wp.version} is several releases behind (latest ${latest}). Out-of-date WordPress is the most common way small-business sites get hacked.`, detail, data: { ...data, branchesBehind: behind }, fix: fixText };
  }
  return { ...base, status: "warn", summary: `WordPress ${wp.version} is out of date (latest ${latest}).`, detail, data: { ...data, branchesBehind: behind }, fix: fixText };
}
