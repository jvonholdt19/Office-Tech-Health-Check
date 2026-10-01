const DAY = 24 * 60 * 60 * 1000;

function daysUntil(iso, now) {
  return Math.floor((new Date(iso).getTime() - now.getTime()) / DAY);
}

function formatDate(iso) {
  return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
}

/* ------------------------------------------------------------------ */
/* SSL certificate                                                     */
/* ------------------------------------------------------------------ */

export async function checkSsl(domain, { inspectTls, now }) {
  const base = { id: "ssl", category: "Website", title: "Website security certificate (SSL)", weight: 15 };
  const hosts = [domain, `www.${domain}`];
  const results = await Promise.all(hosts.map((h) => inspectTls(h)));
  const reachable = results.map((r, i) => ({ host: hosts[i], ...r })).filter((r) => r.ok);

  if (reachable.length === 0) {
    return {
      ...base,
      status: "info",
      weight: 0,
      summary: "We couldn't reach a secure website at this domain. It may not have a website, or it may be hosted elsewhere.",
      detail: results.map((r, i) => `${hosts[i]}: ${r.error}`).join("; "),
      fix: null,
    };
  }

  const bad = reachable.filter((r) => !r.authorized);
  const today = now();
  const soonest = reachable
    .filter((r) => r.validTo)
    .map((r) => ({ host: r.host, days: daysUntil(r.validTo, today), validTo: r.validTo }))
    .sort((a, b) => a.days - b.days)[0];
  const detail = reachable
    .map((r) => `${r.host}: ${r.authorized ? "valid" : `INVALID (${r.authorizationError})`}${r.validTo ? `, expires ${formatDate(r.validTo)}` : ""}${r.issuer ? `, issued by ${r.issuer}` : ""}`)
    .join("; ");

  if (bad.length > 0) {
    return {
      ...base,
      status: "fail",
      summary: `Visitors to ${bad.map((b) => b.host).join(" and ")} will see a browser security warning. That scares customers away and looks unprofessional.`,
      detail,
      fix: "Install a valid certificate that covers both the main domain and www (free, auto-renewing certificates are standard now).",
    };
  }
  if (soonest && soonest.days < 14) {
    return {
      ...base,
      status: "warn",
      summary: `The website's security certificate expires in ${Math.max(soonest.days, 0)} days. Unless it renews automatically, visitors will soon see security warnings.`,
      detail,
      fix: "Confirm the certificate renews automatically, or renew it now.",
    };
  }
  return { ...base, status: "pass", summary: "The website has a valid security certificate.", detail, fix: null };
}

/* ------------------------------------------------------------------ */
/* HTTP -> HTTPS redirect                                              */
/* ------------------------------------------------------------------ */

export async function checkHttpsRedirect(domain, { probeHttp }) {
  const base = { id: "https-redirect", category: "Website", title: "Forces secure connections (HTTPS)", weight: 10 };
  const r = await probeHttp(domain);
  if (!r.ok) {
    return { ...base, status: "info", weight: 0, summary: "We couldn't reach the website over plain HTTP to test this.", detail: r.error, fix: null };
  }
  const redirectsToHttps = r.status >= 300 && r.status < 400 && /^https:\/\//i.test(r.location || "");
  if (redirectsToHttps) {
    return { ...base, status: "pass", summary: "Visitors are automatically moved to the secure (HTTPS) version of the site.", detail: `HTTP ${r.status} → ${r.location}`, fix: null };
  }
  return {
    ...base,
    status: "warn",
    summary: "The website still loads without encryption when someone types the address without https://, so contact form details can travel unprotected.",
    detail: `HTTP ${r.status}${r.location ? ` → ${r.location}` : ""}`,
    fix: "Turn on the hosting provider's automatic HTTP → HTTPS redirect.",
  };
}

/* ------------------------------------------------------------------ */
/* Domain registration (RDAP)                                          */
/* ------------------------------------------------------------------ */

export function summarizeRdap(data) {
  const events = Array.isArray(data?.events) ? data.events : [];
  const expiry = events.find((e) => /expiration/i.test(e.eventAction))?.eventDate || null;
  const registered = events.find((e) => /^registration$/i.test(e.eventAction))?.eventDate || null;
  const registrarEntity = (data?.entities || []).find((e) => (e.roles || []).includes("registrar"));
  let registrar = null;
  const vcard = registrarEntity?.vcardArray?.[1];
  if (Array.isArray(vcard)) {
    const fn = vcard.find((f) => f[0] === "fn");
    if (fn) registrar = fn[3];
  }
  const statuses = Array.isArray(data?.status) ? data.status : [];
  const transferLocked = statuses.some((s) => /transfer prohibited/i.test(s));
  const dnssec = data?.secureDNS?.delegationSigned === true;
  return { expiry, registered, registrar, transferLocked, dnssec };
}

export async function checkDomainRegistration(domain, { fetchRdap, now }) {
  const base = { id: "domain-registration", category: "Domain", title: "Domain registration", weight: 15 };
  const r = await fetchRdap(domain);
  if (!r.ok) {
    return {
      ...base,
      status: "info",
      weight: 0,
      summary: "We couldn't retrieve public registration details for this domain, so its expiry date needs checking at the registrar.",
      detail: `RDAP lookup failed: ${r.error}`,
      fix: null,
    };
  }
  const info = summarizeRdap(r.data);
  const parts = [];
  if (info.registrar) parts.push(`Registrar: ${info.registrar}`);
  if (info.registered) parts.push(`Registered ${formatDate(info.registered)}`);
  if (info.expiry) parts.push(`Expires ${formatDate(info.expiry)}`);
  parts.push(`Transfer lock: ${info.transferLocked ? "on" : "off"}`);
  parts.push(`DNSSEC: ${info.dnssec ? "on" : "off"}`);
  const detail = parts.join(" · ");

  if (!info.expiry) {
    return { ...base, status: "info", weight: 0, summary: "The registry doesn't publish an expiry date for this domain.", detail, fix: null, registration: info };
  }
  const days = daysUntil(info.expiry, now());
  if (days < 30) {
    return {
      ...base,
      status: "fail",
      summary: `The domain expires in ${Math.max(days, 0)} days. If it lapses, the website and every email address on it stop working, and someone else can register it.`,
      detail,
      fix: "Renew now, turn on auto-renew, and make sure the registrar account belongs to the business, not a former employee or web designer.",
      registration: info,
    };
  }
  if (days < 90 || !info.transferLocked) {
    return {
      ...base,
      status: "warn",
      summary:
        days < 90
          ? `The domain expires in ${days} days. Make sure auto-renew is on and the payment card on file is current.`
          : "The domain isn't locked against transfers, which makes it easier to hijack.",
      detail,
      fix: "Confirm auto-renew, turn on the registrar transfer lock, and check who owns the registrar login.",
      registration: info,
    };
  }
  return {
    ...base,
    status: "pass",
    summary: `The domain is registered until ${formatDate(info.expiry)} and locked against unauthorized transfers.`,
    detail,
    fix: null,
    registration: info,
  };
}
