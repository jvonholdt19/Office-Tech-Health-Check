// Public "Quick email security check (preview)" for the lander: SPF, DMARC and the website's HTTPS
// certificate only, graded with the same summarizeChecks/gradeFor as the full scan. The response is
// deliberately minimal (grade + pass/warn/fail per item): no records, details, fixes or Fix Plan.
import { defaultDeps } from "./net.js";
import { safely, summarizeChecks } from "./scan.js";
import { checkEmailPlatform, checkSpf, checkDmarc } from "./checks/email.js";
import { checkSsl } from "./checks/web.js";

export const PREVIEW_ITEMS = [
  { id: "spf", title: "SPF (who may send email as this domain)" },
  { id: "dmarc", title: "DMARC (protection against spoofed email)" },
  { id: "ssl", title: "Website HTTPS (valid security certificate)" },
];

export async function runPreview(domain, overrides = {}) {
  const deps = { ...defaultDeps, ...overrides };
  // The platform (from MX) only tells SPF which include to expect; it isn't returned.
  const platform = await safely({ id: "email-platform", weight: 0 }, () => checkEmailPlatform(domain, deps));
  const provider = platform.provider || { key: "unknown", name: "Unknown" };
  const checks = await Promise.all([
    safely({ id: "spf", category: "Email security", title: "SPF", weight: 20 }, () => checkSpf(domain, deps, provider)),
    safely({ id: "dmarc", category: "Email security", title: "DMARC", weight: 25 }, () => checkDmarc(domain, deps)),
    safely({ id: "ssl", category: "Website", title: "SSL", weight: 15 }, () => checkSsl(domain, deps)),
  ]);
  const { grade } = summarizeChecks(checks);
  const byId = Object.fromEntries(checks.map((c) => [c.id, c]));
  return {
    domain,
    grade,
    // Only id, title and status leave the server.
    items: PREVIEW_ITEMS.map(({ id, title }) => ({ id, title, status: byId[id]?.status || "unknown" })),
  };
}
