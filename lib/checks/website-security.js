// Website Security Check (technician tool). Every check is passive: it only looks at the responses
// to plain GETs of the homepage and its redirects (see fetchChain in lib/net.js), plus the TLS
// certificate. No payloads, no path probing, no crawling.
//
// Grading follows Mozilla HTTP Observatory, the OWASP Secure Headers Project, OWASP ASVS 4.0.3
// (V14.4 headers, V3.4 cookies) and SSL Labs basics, softened where a small office without a
// security team would otherwise be marked down for optional extras. Weights:
//   HTTPS 15 · HTTP → HTTPS redirect 10 · Certificate 15 · HSTS 8 · Cookies 8 · WordPress 8 (when found)
//   Clickjacking 6 · Mixed content 6 · CSP 5 · nosniff 4 · Version disclosure 3 · SRI 3 · Referrer-Policy 2
//   Permissions-Policy 0 (info) · CORS 0 (3 when credentials are opened to another origin) · TLS details 0 (info)
// Hard grade caps (no HTTPS, downgrade, bad certificate → F; no HTTP → HTTPS redirect → C; TLS < 1.2 → B)
// are applied in lib/website-scan.js.

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
/* 2. Certificate and TLS (website tool thresholds; checkSsl is untouched) */
/* ------------------------------------------------------------------ */

const DAY = 24 * 60 * 60 * 1000;
const fmtDate = (iso) => new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });

/** Hostnames the site actually sent visitors to (every fetched URL plus any unfollowed redirect). */
export function hostsVisited(...chains) {
  const hosts = new Set();
  for (const c of chains) {
    for (const r of c?.responses || []) hosts.add(new URL(r.url).hostname);
    if (c?.stopped?.location) {
      try {
        hosts.add(new URL(c.stopped.location).hostname);
      } catch {}
    }
  }
  return hosts;
}

/**
 * Certificate for the apex and www. Website-tool thresholds: fail under 7 days or when invalid,
 * expired or untrusted; warn under 21 days (small offices often have no expiry monitoring).
 * An invalid certificate on www only is a warning when the apex is fine and the site never sends
 * visitors to www.
 */
export function checkCertificate({ host, tls, usesWww }, { now }) {
  const base = { id: "ssl", category: CAT_TRANSPORT, title: "Security certificate (SSL/TLS)", weight: 15 };
  const reachable = (tls || []).filter((r) => r.ok);
  if (!reachable.length) {
    return { ...base, status: "info", weight: 0, summary: "We couldn't reach a secure website at this domain. It may not have a website, or it may be hosted elsewhere.", detail: (tls || []).map((r) => `${r.host}: ${r.error}`).join("; "), fix: null };
  }
  const today = now();
  const detail = reachable
    .map((r) => `${r.host}: ${r.authorized ? "valid" : `INVALID (${r.authorizationError})`}${r.validTo ? `, expires ${fmtDate(r.validTo)}` : ""}${r.issuer ? `, issued by ${r.issuer}` : ""}`)
    .join("; ");
  const bad = reachable.filter((r) => !r.authorized);
  const apex = reachable.find((r) => r.host === host);
  if (bad.length === 1 && bad[0].host === `www.${host}` && apex?.authorized && !usesWww) {
    return {
      ...base,
      status: "warn",
      summary: `The certificate for ${bad[0].host} isn't valid. The site itself doesn't use www, but anyone who types www. will see a browser warning.`,
      detail,
      data: { code: "www-invalid", host: bad[0].host, error: bad[0].authorizationError },
      fix: `Add ${bad[0].host} to the certificate (most hosts do this with one click), or redirect it to ${host}.`,
    };
  }
  if (bad.length) {
    return {
      ...base,
      status: "fail",
      summary: `Visitors to ${bad.map((b) => b.host).join(" and ")} will see a browser security warning (the certificate is invalid, expired or not trusted).`,
      detail,
      data: { code: "invalid", badHosts: bad.map((b) => ({ host: b.host, error: b.authorizationError })) },
      fix: "Install a valid certificate that covers both the main domain and www (free, auto-renewing certificates are standard now).",
    };
  }
  const soonest = reachable
    .filter((r) => r.validTo)
    .map((r) => ({ host: r.host, days: Math.floor((new Date(r.validTo).getTime() - today.getTime()) / DAY) }))
    .sort((a, b) => a.days - b.days)[0];
  if (soonest && soonest.days < 7) {
    return { ...base, status: "fail", summary: `The certificate for ${soonest.host} expires in ${Math.max(soonest.days, 0)} days. Visitors will see security warnings within the week unless it renews.`, detail, data: { code: "expiring-urgent", host: soonest.host, days: soonest.days }, fix: "Renew the certificate now and confirm auto-renew is working." };
  }
  if (soonest && soonest.days < 21) {
    return { ...base, status: "warn", summary: `The certificate for ${soonest.host} expires in ${soonest.days} days. Confirm it renews automatically.`, detail, data: { code: "expiring", host: soonest.host, days: soonest.days }, fix: "Confirm the certificate renews automatically, or renew it now." };
  }
  return { ...base, status: "pass", summary: "The website has a valid security certificate.", detail, fix: null };
}

/** Negotiated protocol and key, from the same inspectTls handshake (no extra connection). Info only. */
export function checkTlsDetails({ host, tls }) {
  const base = { id: "tls-details", category: CAT_TRANSPORT, title: "TLS version and key", weight: 0 };
  const r = (tls || []).find((x) => x.ok && x.host === host) || (tls || []).find((x) => x.ok);
  if (!r) return { ...base, status: "info", summary: "No secure connection to inspect.", detail: "TLS handshake failed.", fix: null };
  const key = r.keyType ? `${r.keyType}${r.keyBits ? ` ${r.keyBits}-bit` : ""} key` : null;
  const detail = [`${r.host}: ${r.protocol || "protocol not reported"}`, key].filter(Boolean).join(", ");
  if (r.protocol && /^(SSLv\d|TLSv1(\.[01])?)$/.test(r.protocol)) {
    return { ...base, status: "fail", summary: `The server only offers ${r.protocol}, which browsers no longer trust. TLS 1.2 or newer is required.`, detail, data: { code: "old-tls", protocol: r.protocol }, fix: "Turn on TLS 1.2 and 1.3 at the host or CDN (and turn off TLS 1.0/1.1)." };
  }
  if (r.keyType === "RSA" && r.keyBits && r.keyBits < 2048) {
    return { ...base, status: "fail", summary: `The certificate uses a ${r.keyBits}-bit RSA key, which is too weak. 2048 bits is the minimum.`, detail, data: { code: "weak-key", keyBits: r.keyBits }, fix: "Reissue the certificate with a 2048-bit (or larger) RSA key, or an EC key." };
  }
  return { ...base, status: "info", summary: r.protocol ? `Connections use ${r.protocol}${key ? ` with an ${key}` : ""}.` : "The TLS version wasn't reported.", detail, data: { protocol: r.protocol || null, keyType: r.keyType || null, keyBits: r.keyBits || null }, fix: null };
}

/* ------------------------------------------------------------------ */
/* 3. Security headers                                                 */
/* ------------------------------------------------------------------ */

export function checkHsts(res, { http } = {}) {
  const base = { id: "hsts", category: CAT_HEADERS, title: "Strict-Transport-Security (HSTS)", weight: 8 };
  if (!res) return { ...base, status: "fail", summary: "Without HTTPS there is no HSTS, so browsers can be tricked onto an unencrypted connection.", detail: "No HTTPS response.", data: { code: "no-https" }, fix: "Turn on HTTPS first, then add a Strict-Transport-Security header." };
  const v = header(res.headers, "strict-transport-security");
  const fix = "Add the header Strict-Transport-Security: max-age=31536000; includeSubDomains (at the host, CDN or security plugin).";
  if (!v) {
    // Browsers ignore HSTS on plain-HTTP responses (RFC 6797 §8.1), so that counts as missing.
    const overHttp = (http?.responses || []).some((r) => /^http:/i.test(r.url) && header(r.headers, "strict-transport-security"));
    return {
      ...base,
      status: "fail",
      summary: overHttp
        ? "HSTS is only sent over plain HTTP, where browsers ignore it, so it isn't protecting anyone."
        : "Browsers aren't told to always use HTTPS for this site, so a first visit on public Wi-Fi can be downgraded.",
      detail: overHttp ? "Strict-Transport-Security sent on the http:// response only; missing on the HTTPS page." : "Strict-Transport-Security header missing.",
      data: { code: overHttp ? "http-only" : "missing" },
      fix,
    };
  }
  const m = v.match(/max-age\s*=\s*"?(\d+)"?/i);
  const age = m ? Number(m[1]) : null;
  if (age === null || age === 0) return { ...base, status: "fail", summary: "The HSTS header is present but switched off (no max-age, or max-age=0).", detail: short(v), data: { code: "disabled", maxAge: age }, fix };
  if (age < SIX_MONTHS) {
    return { ...base, status: "warn", summary: `HSTS is on, but only for ${Math.round(age / 86400)} days. Six months or more is recommended.`, detail: short(v), data: { code: "short", maxAge: age }, fix: "Raise max-age to at least 15552000 (six months); 31536000 (one year) is typical." };
  }
  // includeSubDomains / preload are noted for information only; they don't change the score.
  const includeSubDomains = /includesubdomains/i.test(v);
  const preload = /\bpreload\b/i.test(v);
  const extras = includeSubDomains || preload
    ? ` It also covers ${[includeSubDomains && "subdomains (includeSubDomains)", preload && "the browser preload list (preload)"].filter(Boolean).join(" and ")}.`
    : " (Optional: includeSubDomains extends this to every subdomain.)";
  return { ...base, status: "pass", summary: `Browsers are told to always use HTTPS for this site.${extras}`, detail: short(v), data: { maxAge: age, includeSubDomains, preload }, fix: null };
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

/** Source list of one CSP directive (lower-cased tokens), or null when the directive is absent. */
export function cspDirective(csp, name) {
  for (const part of String(csp || "").split(/[;,]/)) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens[0] && tokens[0].toLowerCase() === name) return tokens.slice(1).map((t) => t.toLowerCase());
  }
  return null;
}

/**
 * How well a CSP restricts scripts (script-src, falling back to default-src):
 * "none" when neither directive is present, "weak" for 'unsafe-inline' without a nonce/hash or a
 * wildcard / bare-scheme source (*, http:, https:), otherwise "strong".
 */
export function cspScriptStrength(csp) {
  const src = cspDirective(csp, "script-src") ?? cspDirective(csp, "default-src");
  if (!src) return { strength: "none", reasons: ["no script-src or default-src"] };
  const reasons = [];
  const nonceOrHash = src.some((t) => /^'(nonce-|sha(256|384|512)-)/.test(t));
  if (src.includes("'unsafe-inline'") && !nonceOrHash) reasons.push("'unsafe-inline' without a nonce or hash");
  const wild = src.filter((t) => t === "*" || t === "http:" || t === "https:");
  if (wild.length) reasons.push(`allows scripts from ${wild.join(" ")}`);
  return { strength: reasons.length ? "weak" : "strong", reasons };
}

export function checkCsp(res) {
  const base = { id: "csp", category: CAT_HEADERS, title: "Content-Security-Policy", weight: 5 };
  if (!res) return noHttpsRow(base);
  const { headerCsp, reportOnly, metaCsp } = cspSources(res);
  const fix = "Add a Content-Security-Policy that lists where scripts may load from. Start in Report-Only mode so nothing breaks, then enforce it.";
  const tighten = "Tighten script-src: list the script hosts the site really uses, and replace 'unsafe-inline' with nonces or hashes.";
  for (const [csp, source] of [[headerCsp, "header"], [metaCsp, "meta"]]) {
    if (!csp) continue;
    const { strength, reasons } = cspScriptStrength(csp);
    const shown = `${source === "meta" ? "<meta> CSP: " : ""}${short(csp, 300)}`;
    const data = { source, strength, unsafeInline: reasons.some((r) => r.includes("unsafe-inline")) };
    if (strength === "strong") return { ...base, status: "pass", summary: `A Content-Security-Policy${source === "meta" ? " (set inside the page)" : ""} limits where scripts can load from.`, detail: shown, data, fix: null };
    if (source === "header" && metaCsp && cspScriptStrength(metaCsp).strength === "strong") continue;
    return {
      ...base,
      status: "warn",
      summary: strength === "none"
        ? "A Content-Security-Policy is set, but it doesn't restrict scripts, so it adds little protection against injected code."
        : `The Content-Security-Policy doesn't really limit scripts (${reasons.join("; ")}).`,
      detail: shown,
      data: { ...data, code: strength === "none" ? "no-script-policy" : "weak" },
      fix: strength === "none" ? fix : tighten,
    };
  }
  if (reportOnly) return { ...base, status: "warn", summary: "A Content-Security-Policy is only in report-only mode, so it doesn't block anything yet.", detail: short(reportOnly, 300), data: { code: "report-only" }, fix: "Once the reports are clean, switch Content-Security-Policy-Report-Only to Content-Security-Policy." };
  return { ...base, status: "warn", summary: "No Content-Security-Policy. It's an extra layer that limits the damage if a plugin or script is ever compromised.", detail: "Content-Security-Policy header missing.", data: { code: "missing" }, fix };
}

export function checkFraming(res) {
  const base = { id: "clickjacking", category: CAT_HEADERS, title: "Clickjacking protection (X-Frame-Options / frame-ancestors)", weight: 6 };
  if (!res) return noHttpsRow(base);
  const fa = frameAncestors(header(res.headers, "content-security-policy"));
  const xfo = header(res.headers, "x-frame-options");
  if (fa && fa !== "*") return { ...base, status: "pass", summary: "Other sites can't embed this site in a hidden frame to trick visitors into clicking.", detail: `CSP frame-ancestors ${fa}${xfo ? `; X-Frame-Options: ${xfo}` : ""}`, fix: null };
  if (xfo && /^\s*(deny|sameorigin)\s*$/i.test(xfo)) return { ...base, status: "pass", summary: "Other sites can't embed this site in a hidden frame to trick visitors into clicking.", detail: `X-Frame-Options: ${xfo}`, fix: null };
  const fix = "Add X-Frame-Options: SAMEORIGIN (or a CSP frame-ancestors 'self' directive).";
  if (xfo || fa) return { ...base, status: "warn", summary: /allow-from/i.test(xfo || "") ? "X-Frame-Options ALLOW-FROM is obsolete and ignored by modern browsers." : "A framing rule is set, but browsers ignore this value.", detail: xfo ? `X-Frame-Options: ${xfo}` : `CSP frame-ancestors ${fa}`, data: { code: "weak" }, fix };
  // Missing is a warning, not a failure: Observatory and OWASP recommend it, but few small-office
  // sites have anything worth clickjacking on the homepage.
  return { ...base, status: "warn", summary: "Any website can load this site inside an invisible frame and trick visitors into clicking buttons on it (clickjacking).", detail: "X-Frame-Options and CSP frame-ancestors both missing.", data: { code: "missing" }, fix };
}

export function checkNosniff(res) {
  const base = { id: "nosniff", category: CAT_HEADERS, title: "X-Content-Type-Options", weight: 4 };
  if (!res) return noHttpsRow(base);
  const v = header(res.headers, "x-content-type-options");
  if (v && /nosniff/i.test(v)) return { ...base, status: "pass", summary: "Browsers won't guess file types, which blocks a class of content-injection tricks.", detail: `X-Content-Type-Options: ${v}`, fix: null };
  return { ...base, status: "warn", summary: "Browsers may guess file types on this site, which lets an uploaded file be run as a script.", detail: v ? `X-Content-Type-Options: ${v}` : "X-Content-Type-Options header missing.", data: { code: "missing" }, fix: "Add the header X-Content-Type-Options: nosniff." };
}

export function checkReferrerPolicy(res) {
  const base = { id: "referrer-policy", category: CAT_HEADERS, title: "Referrer-Policy", weight: 2 };
  if (!res) return noHttpsRow(base);
  const v = header(res.headers, "referrer-policy");
  const fix = "Add Referrer-Policy: strict-origin-when-cross-origin.";
  // Missing is fine: browsers default to strict-origin-when-cross-origin (Observatory: no penalty).
  if (!v) return { ...base, status: "pass", summary: "No Referrer-Policy is set, so browsers use their safe default (strict-origin-when-cross-origin). Setting it explicitly is optional.", detail: "Referrer-Policy header missing; browser default applies.", data: { code: "default" }, fix: null };
  // The last valid token wins in browsers; flag the two that leak full URLs to other sites.
  const last = v.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean).at(-1);
  if (last === "unsafe-url" || last === "no-referrer-when-downgrade") return { ...base, status: "warn", summary: "The Referrer-Policy sends full page addresses to other websites.", detail: `Referrer-Policy: ${v}`, data: { code: "leaky" }, fix };
  return { ...base, status: "pass", summary: "Page addresses aren't leaked to other websites when visitors click links.", detail: `Referrer-Policy: ${v}`, fix: null };
}

/** Info only (weight 0): Observatory doesn't score it and OWASP lists it as optional. */
export function checkPermissionsPolicy(res) {
  const base = { id: "permissions-policy", category: CAT_HEADERS, title: "Permissions-Policy", weight: 0 };
  if (!res) return noHttpsRow(base);
  const v = header(res.headers, "permissions-policy");
  if (v) return { ...base, status: "info", summary: "The site limits which browser features (camera, microphone, location) pages can use.", detail: `Permissions-Policy: ${short(v, 300)}`, fix: null };
  return { ...base, status: "info", summary: "No Permissions-Policy. It's an optional extra that stops embedded scripts from asking for the camera, microphone or location. Optional: add Permissions-Policy: camera=(), microphone=(), geolocation=().", detail: "Permissions-Policy header missing (not scored).", data: { code: "missing" }, fix: "Add Permissions-Policy: camera=(), microphone=(), geolocation=() (allow only what the site uses)." };
}

/** CORS on the homepage. Info unless credentials are opened up to another origin. */
export function checkCors(res, host) {
  const base = { id: "cors", category: CAT_HEADERS, title: "Cross-origin access (CORS)", weight: 0 };
  if (!res) return noHttpsRow(base);
  const acao = header(res.headers, "access-control-allow-origin");
  const creds = /^\s*true\s*$/i.test(header(res.headers, "access-control-allow-credentials") || "");
  if (!acao) return { ...base, status: "info", summary: "The homepage doesn't allow other websites to read it (no CORS headers).", detail: "No Access-Control-Allow-Origin header.", fix: null };
  const origin = acao.trim();
  const detail = `Access-Control-Allow-Origin: ${short(origin, 120)}${creds ? "; Access-Control-Allow-Credentials: true" : ""}`;
  if (origin === "*") {
    return { ...base, status: "info", summary: creds ? "Any website may read the homepage. Browsers refuse to combine * with credentials, so logged-in data isn't exposed." : "Any website may read the homepage (Access-Control-Allow-Origin: *). That's normal for public content.", detail, data: { code: "wildcard" }, fix: null };
  }
  let otherSite = origin === "null";
  try {
    const h = new URL(origin).hostname;
    otherSite = otherSite || !(h === host || h.endsWith(`.${host}`));
  } catch {
    otherSite = true;
  }
  if (creds && otherSite) {
    return {
      ...base,
      weight: 3,
      status: "warn",
      summary: `Another origin (${short(origin, 80)}) may read this site with the visitor's cookies. If the server copies whatever Origin it's sent, any website can read logged-in pages.`,
      detail,
      data: { code: "credentials" },
      fix: "Only allow credentials for a fixed list of your own origins; never echo the request's Origin back.",
    };
  }
  return { ...base, status: "info", summary: `Cross-origin reads are allowed for ${short(origin, 80)}.`, detail, fix: null };
}

/* ------------------------------------------------------------------ */
/* 4. Cookies                                                          */
/* ------------------------------------------------------------------ */

// Cookies that scripts on the page are meant to read (analytics, consent banners, CSRF tokens, UI
// preferences). Missing HttpOnly on these is normal, so it's reported as info only.
// Names that look like session/login cookies: only these are marked down for missing HttpOnly.
export const SESSION_COOKIE = /sess|sid|auth|token|login|wordpress_logged_in|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|laravel_session/i;
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
      if (SESSION_COOKIE.test(c.name) && !CLIENT_READABLE.test(c.name)) {
        missing.push("HttpOnly");
        bump("warn");
      } else notes.push(`${c.name}: no HttpOnly (fine for a cookie that isn't a login/session cookie)`);
    }
    // Missing SameSite alone isn't marked down: browsers treat it as Lax (Observatory: no penalty).
    if (!c.sameSite) notes.push(`${c.name}: no SameSite (browsers default to Lax)`);
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
    // Stable codes for the fix guides (no grading change): Secure missing vs HttpOnly on a session cookie.
    data: { ...data, code: worst === "fail" || problems.some((p) => /Secure/.test(p)) ? "secure-missing" : "httponly-missing" },
    summary: worst === "fail"
      ? "Some cookies can be sent over unencrypted connections (no Secure flag), where they can be stolen."
      : "Some cookies are missing recommended security flags.",
    detail,
    fix: "Set Secure (and HttpOnly on login/session cookies) on the site's cookies (in the CMS, plugin or server settings). Cookie names are listed in the details.",
  };
}

/* ------------------------------------------------------------------ */
/* 5. Mixed content hints                                              */
/* ------------------------------------------------------------------ */

const LINK_RELS = /\b(stylesheet|icon|preload|modulepreload|manifest|apple-touch-icon)\b/i;

// Active content can change the page (scripts, frames, styles, form posts); browsers block it and an
// attacker on the network can rewrite it. Passive content (images, media) only leaks or gets swapped.
const ACTIVE_TAGS = new Set(["script", "iframe", "frame", "embed", "form"]);
const ACTIVE_RELS = /\b(stylesheet|modulepreload)\b/i;

/**
 * http:// URLs in src=, <link href> (stylesheets, icons, preloads) and <form action> of an HTML page.
 * Each hit is { tag, url, active }.
 */
export function findMixedContent(html) {
  const found = [];
  const s = String(html || "");
  const attr = (tag, name) => {
    const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
    return m ? (m[1] ?? m[2] ?? m[3] ?? "").trim() : null;
  };
  for (const m of s.matchAll(/<(script|img|iframe|frame|audio|video|source|embed|track|input)\b[^>]*>/gi)) {
    const v = attr(m[0], "src");
    if (v && /^http:\/\//i.test(v)) found.push({ tag: m[1].toLowerCase(), url: v, active: ACTIVE_TAGS.has(m[1].toLowerCase()) });
  }
  for (const m of s.matchAll(/<link\b[^>]*>/gi)) {
    const v = attr(m[0], "href");
    const rel = attr(m[0], "rel") || "";
    if (v && /^http:\/\//i.test(v) && LINK_RELS.test(rel)) found.push({ tag: "link", url: v, active: ACTIVE_RELS.test(rel) });
  }
  for (const m of s.matchAll(/<form\b[^>]*>/gi)) {
    const v = attr(m[0], "action");
    if (v && /^http:\/\//i.test(v)) found.push({ tag: "form", url: v, active: true });
  }
  return found;
}

export function checkMixedContent(res) {
  const base = { id: "mixed-content", category: CAT_CONTENT, title: "Mixed content (http:// on a secure page)", weight: 6 };
  if (!res || !/^https:/i.test(res.url)) return { ...base, status: "info", weight: 0, summary: "Only checked on pages served over HTTPS.", detail: "No HTTPS page to inspect.", fix: null };
  if (res.status >= 300 && res.status < 400) return { ...base, status: "info", weight: 0, summary: "The homepage redirects somewhere we didn't follow, so there was no page to inspect.", detail: `${res.status} ${res.url}`, fix: null };
  const found = findMixedContent(res.body);
  const note = res.truncated ? " (only the first 1 MB of the page was read)" : "";
  if (!found.length) return { ...base, status: "pass", summary: "No insecure http:// scripts, images, styles or forms were found in the homepage.", detail: `Scanned the homepage HTML${note}.`, fix: null };
  const forms = found.filter((f) => f.tag === "form").length;
  const active = found.filter((f) => f.active);
  const listed = [...active, ...found.filter((f) => !f.active)];
  return {
    ...base,
    status: active.length ? "fail" : "warn",
    summary: forms
      ? "A form on the secure homepage sends its data to an unencrypted http:// address."
      : active.length
        ? "The secure homepage loads scripts, frames or styles over unencrypted http://. Browsers block these, and on an untrusted network they can be swapped for malicious code."
        : "The secure homepage loads some images or media over unencrypted http://. Browsers flag the page as not fully secure.",
    detail: `${found.length} hint${found.length === 1 ? "" : "s"} (${active.length} active)${note}: ${listed.slice(0, 5).map((f) => `<${f.tag}> ${short(f.url, 100)}`).join("; ")}${found.length > 5 ? "; …" : ""}`,
    data: { code: active.length ? "active" : "passive", count: found.length, active: active.length, forms },
    fix: "Change these links to https:// (or to relative paths). A search-and-replace plugin or the theme settings usually fixes it in minutes.",
  };
}

/* ------------------------------------------------------------------ */
/* 6. Version disclosure                                               */
/* ------------------------------------------------------------------ */

const VERSION = /\d+\.\d+/;

export function checkVersionDisclosure(res) {
  const base = { id: "version-disclosure", category: CAT_SOFTWARE, title: "Server software versions shown", weight: 3 };
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
/* Subresource Integrity (SRI)                                          */
/* ------------------------------------------------------------------ */

// Big, well-run script providers. Their tags (analytics, tag managers, payment widgets) change
// constantly and can't carry an integrity hash, so missing SRI on them is informational only.
const MAJOR_SCRIPT_HOSTS = [
  "googletagmanager.com", "google-analytics.com", "google.com", "gstatic.com", "googleapis.com", "googlesyndication.com", "doubleclick.net", "youtube.com",
  "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net", "unpkg.com", "jquery.com", "bootstrapcdn.com", "fontawesome.com",
  "facebook.net", "connect.facebook.net", "microsoft.com", "clarity.ms", "bing.com", "stripe.com", "paypal.com", "paypalobjects.com", "squarespace.com",
  "wix.com", "parastorage.com", "shopify.com", "shopifycdn.com", "hotjar.com", "hs-scripts.com", "hubspot.com", "recaptcha.net", "cookiebot.com", "onetrust.com", "cookielaw.org",
];
const isMajorHost = (h) => MAJOR_SCRIPT_HOSTS.some((d) => h === d || h.endsWith(`.${d}`));

/** <script src> on other hosts than the site (host and its subdomains), with whether they carry integrity=. */
export function findExternalScripts(html, host) {
  const out = [];
  for (const m of String(html || "").matchAll(/<script\b[^>]*>/gi)) {
    const tag = m[0];
    const src = (tag.match(/\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i) || []).slice(1).find((x) => x !== undefined);
    if (!src || !/^(https?:)?\/\//i.test(src.trim())) continue;
    let h;
    try {
      h = new URL(src.trim(), `https://${host}/`).hostname;
    } catch {
      continue;
    }
    if (h === host || h.endsWith(`.${host}`)) continue;
    out.push({ src: src.trim(), host: h, integrity: /\bintegrity\s*=/i.test(tag), major: isMajorHost(h) });
  }
  return out;
}

export function checkSri(res, host) {
  const base = { id: "sri", category: CAT_CONTENT, title: "Subresource Integrity on third-party scripts", weight: 3 };
  if (!res || (res.status >= 300 && res.status < 400)) return { ...base, status: "info", weight: 0, summary: "There was no homepage to inspect for third-party scripts.", detail: res ? `${res.status} ${res.url}` : "No page.", fix: null };
  const scripts = findExternalScripts(res.body, host);
  const missing = scripts.filter((s) => !s.integrity);
  const hosts = (list) => [...new Set(list.map((s) => s.host))].slice(0, 6).join(", ");
  if (!missing.length) {
    return { ...base, status: "pass", summary: scripts.length ? "Every third-party script on the homepage is pinned with an integrity hash." : "The homepage doesn't load scripts from other websites.", detail: scripts.length ? `${scripts.length} external script(s), all with integrity=` : "No external <script src>.", fix: null };
  }
  const minor = missing.filter((s) => !s.major);
  if (!minor.length) {
    return { ...base, status: "info", weight: 0, summary: "Third-party scripts come only from large, well-known providers (analytics, tag managers, payments). Those can't usually be pinned, so this isn't scored.", detail: `Without integrity=: ${hosts(missing)}`, fix: null };
  }
  return {
    ...base,
    status: "warn",
    summary: `The homepage runs scripts from ${minor.length === 1 ? "a smaller third-party site" : "smaller third-party sites"} without an integrity check. If that site is hacked, the attacker's code runs on this site too.`,
    detail: `Without integrity=: ${hosts(minor)}${missing.length > minor.length ? ` (plus well-known: ${hosts(missing.filter((s) => s.major))})` : ""}`,
    data: { code: "missing-integrity", hosts: [...new Set(minor.map((s) => s.host))] },
    fix: "Host those scripts on the site itself, or add integrity= and crossorigin=\"anonymous\" attributes for fixed library versions.",
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
// Only successful lookups are cached. A failure (timeout, HTTP error, bad JSON) is never stored, so
// the next scan simply tries WordPress.org again instead of reporting "couldn't compare" for 12 hours.
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

/**
 * WordPress core vs the latest release: latest = pass; behind on patches or one branch behind = warn;
 * two or more branches behind (e.g. 6.6 when 6.8 is out) = fail; WordPress.org unreachable = couldn't verify.
 */
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
    return { ...base, status: "fail", summary: `WordPress ${wp.version} is several releases behind (latest ${latest}). Out-of-date WordPress is the most common way small-business sites get hacked.`, detail, data: { ...data, code: "branches-behind", branchesBehind: behind }, fix: fixText };
  }
  return { ...base, status: "warn", summary: `WordPress ${wp.version} is out of date (latest ${latest}).`, detail, data: { ...data, code: "outdated", branchesBehind: behind }, fix: fixText };
}
