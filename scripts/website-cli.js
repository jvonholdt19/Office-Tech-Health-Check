// Usage: npm run website -- example.com   (add --json for raw output)
import { runWebsiteScan } from "../lib/website-scan.js";

const args = process.argv.slice(2);
const input = args.find((a) => !a.startsWith("--"));
const report = await runWebsiteScan(input || "");
if (report.error) {
  console.error(report.error);
  process.exit(1);
}
if (args.includes("--json")) {
  console.log(JSON.stringify(report, null, 2));
} else {
  const icon = { pass: "✅", warn: "⚠️ ", fail: "❌", unknown: "❔", info: "ℹ️ " };
  console.log(`\n${report.target}: grade ${report.grade ?? "n/a"} (${report.score ?? "–"}/100) · ${report.finalUrl ?? "not reachable"}\n`);
  for (const c of report.checks) console.log(`${icon[c.status]} ${c.title}\n   ${c.summary}\n   ${c.detail}\n`);
}
