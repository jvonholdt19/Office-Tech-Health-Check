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

/** Wrap a check so an unexpected error becomes a "couldn't verify" row instead of breaking the whole report. */
async function safely(meta, fn) {
  try {
    return await fn();
  } catch (err) {
    return {
      ...meta,
      status: "unknown",
      summary: "This check couldn't be completed right now. Try again in a minute.",
      detail: err?.message || String(err),
      fix: null,
    };
  }
}

export async function runScan(domain, overrides = {}) {
  const deps = { ...defaultDeps, ...overrides };
  const started = Date.now();

  const platform = await safely({ id: "email-platform", category: "Email platform", title: "Email platform", weight: 0 }, () =>
    checkEmailPlatform(domain, deps),
  );
  const provider = platform.provider || { key: "unknown", name: "Unknown" };

  const dmarcP = safely({ id: "dmarc", category: "Email security", title: "DMARC (anti-impersonation policy)", weight: 25 }, () => checkDmarc(domain, deps));
  const [spf, dmarc, registration, ssl, redirect] = await Promise.all([
    safely({ id: "spf", category: "Email security", title: "SPF (approved senders list)", weight: 20 }, () => checkSpf(domain, deps, provider)),
    dmarcP,
    safely({ id: "domain-registration", category: "Domain", title: "Domain registration", weight: 15 }, () => checkDomainRegistration(domain, deps)),
    safely({ id: "ssl", category: "Website", title: "Website security certificate (SSL)", weight: 15 }, () => checkSsl(domain, deps)),
    safely({ id: "https-redirect", category: "Website", title: "Forces secure connections (HTTPS)", weight: 10 }, () => checkHttpsRedirect(domain, deps)),
  ]);
  const dmarcEnforced = dmarc.status === "pass" || (dmarc.status === "warn" && /reject|quarantine/i.test(dmarc.detail || "") && !/p=none/i.test(dmarc.detail || ""));
  const dkim = await safely({ id: "dkim", category: "Email security", title: "DKIM (email signing)", weight: 15 }, () =>
    checkDkim(domain, deps, provider, { dmarcEnforced }),
  );
  const checks = [platform, spf, dmarc, dkim, registration, ssl, redirect];

  const score = scoreChecks(checks);
  // Checks that matter but couldn't be confirmed. They're left out of the score and listed openly.
  const unverified = checks.filter((c) => c.status === "unknown" && c.weight > 0).map((c) => ({ id: c.id, title: c.title }));
  const possible = checks.filter((c) => c.weight > 0 && c.status !== "info").reduce((s, c) => s + c.weight, 0);
  const verified = checks.filter((c) => c.weight > 0 && c.status in STATUS_SCORE).reduce((s, c) => s + c.weight, 0);
  const coverage = possible ? Math.round((verified / possible) * 100) : 0;
  const counts = checks.reduce((acc, c) => ((acc[c.status] = (acc[c.status] || 0) + 1), acc), {});
  const fixes = checks.filter((c) => c.fix && (c.status === "fail" || c.status === "warn" || c.id === "email-platform"));

  return {
    domain,
    scannedAt: deps.now().toISOString(),
    durationMs: Date.now() - started,
    provider,
    score,
    grade: score === null || coverage < 50 ? null : gradeFor(score),
    coverage,
    unverified,
    counts,
    checks: checks.map(({ provider: _p, registration: _r, ...rest }) => rest),
    fixes: fixes.map((c) => ({ id: c.id, title: c.title, status: c.status, fix: c.fix })),
  };
}
