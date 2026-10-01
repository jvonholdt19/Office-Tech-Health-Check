import { defaultDeps } from "./net.js";
import { checkEmailPlatform, checkSpf, checkDmarc, checkDkim } from "./checks/email.js";
import { checkSsl, checkHttpsRedirect, checkDomainRegistration } from "./checks/web.js";

const STATUS_SCORE = { pass: 1, warn: 0.5, fail: 0 };

export function gradeFor(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/** Weighted score over the checks that count (info checks and weight 0 are ignored). */
export function scoreChecks(checks) {
  const scored = checks.filter((c) => c.weight > 0 && c.status in STATUS_SCORE);
  const possible = scored.reduce((s, c) => s + c.weight, 0);
  if (possible === 0) return null;
  const earned = scored.reduce((s, c) => s + c.weight * STATUS_SCORE[c.status], 0);
  return Math.round((earned / possible) * 100);
}

/** Wrap a check so an unexpected error becomes an "info" row instead of breaking the whole report. */
async function safely(meta, fn) {
  try {
    return await fn();
  } catch (err) {
    return {
      ...meta,
      status: "info",
      weight: 0,
      summary: "This check couldn't be completed right now. Try again in a minute.",
      detail: err?.message || String(err),
      fix: null,
    };
  }
}

export async function runScan(domain, overrides = {}) {
  const deps = { ...defaultDeps, ...overrides };
  const started = Date.now();

  const platform = await safely({ id: "email-platform", category: "Email platform", title: "Email platform" }, () =>
    checkEmailPlatform(domain, deps),
  );
  const provider = platform.provider || { key: "unknown", name: "Unknown" };

  const checks = await Promise.all([
    Promise.resolve(platform),
    safely({ id: "spf", category: "Email security", title: "SPF (approved senders list)" }, () => checkSpf(domain, deps, provider)),
    safely({ id: "dmarc", category: "Email security", title: "DMARC (anti-impersonation policy)" }, () => checkDmarc(domain, deps)),
    safely({ id: "dkim", category: "Email security", title: "DKIM (email signing)" }, () => checkDkim(domain, deps, provider)),
    safely({ id: "domain-registration", category: "Domain", title: "Domain registration" }, () => checkDomainRegistration(domain, deps)),
    safely({ id: "ssl", category: "Website", title: "Website security certificate (SSL)" }, () => checkSsl(domain, deps)),
    safely({ id: "https-redirect", category: "Website", title: "Forces secure connections (HTTPS)" }, () => checkHttpsRedirect(domain, deps)),
  ]);

  const score = scoreChecks(checks);
  const counts = checks.reduce((acc, c) => ((acc[c.status] = (acc[c.status] || 0) + 1), acc), {});
  const fixes = checks.filter((c) => c.fix && (c.status === "fail" || c.status === "warn" || c.id === "email-platform"));

  return {
    domain,
    scannedAt: deps.now().toISOString(),
    durationMs: Date.now() - started,
    provider,
    score,
    grade: score === null ? null : gradeFor(score),
    counts,
    checks: checks.map(({ provider: _p, registration: _r, ...rest }) => rest),
    fixes: fixes.map((c) => ({ id: c.id, title: c.title, status: c.status, fix: c.fix })),
  };
}
