// Usage: npm run scan -- acmeaccounting.com   (add --json for raw output)
import { normalizeDomain } from "../lib/domain.js";
import { runScan } from "../lib/scan.js";

const args = process.argv.slice(2);
const input = args.find((a) => !a.startsWith("--"));
const parsed = normalizeDomain(input || "");
if (parsed.error) {
  console.error(parsed.error);
  process.exit(1);
}
const report = await runScan(parsed.domain);
if (args.includes("--json")) {
  console.log(JSON.stringify(report, null, 2));
} else {
  const icon = { pass: "✅", warn: "⚠️ ", fail: "❌", unknown: "❔", info: "ℹ️ " };
  console.log(`\n${report.domain}: grade ${report.grade ?? "n/a"} (${report.score ?? "–"}/100) · ${report.provider.name}\n`);
  for (const c of report.checks) console.log(`${icon[c.status]} ${c.title}\n   ${c.summary}\n   ${c.detail}\n`);
}
