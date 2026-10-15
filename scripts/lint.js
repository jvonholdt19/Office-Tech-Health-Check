// Zero-dependency lint: syntax-check every JS file with `node --check`, make sure the JSON config
// parses, and keep the HTML compatible with the strict CSP (no inline scripts, styles or handlers).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname, relative } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const problems = [];
const files = [];
const walk = (dir) => {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (f === "node_modules" || f.startsWith(".")) continue;
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
};
for (const d of ["api", "lib", "public", "scripts", "test"]) walk(join(root, d));

let checked = 0;
for (const f of files.filter((f) => extname(f) === ".js")) {
  try {
    execFileSync(process.execPath, ["--check", f], { stdio: "pipe" });
    checked++;
  } catch (err) {
    problems.push(`${relative(root, f)}: ${String(err.stderr || err.message).trim()}`);
  }
}
for (const f of ["package.json", "vercel.json"]) {
  try {
    JSON.parse(readFileSync(join(root, f), "utf8"));
  } catch (err) {
    problems.push(`${f}: invalid JSON (${err.message})`);
  }
}
for (const f of files.filter((f) => extname(f) === ".html")) {
  const html = readFileSync(f, "utf8");
  const rel = relative(root, f);
  for (const m of html.matchAll(/<script\b[^>]*>/gi)) if (!/\bsrc\s*=/.test(m[0])) problems.push(`${rel}: inline <script> is blocked by the CSP; use a separate .js file`);
  if (/<style\b/i.test(html)) problems.push(`${rel}: <style> is blocked by the CSP; use a .css file`);
  if (/\sstyle\s*=/i.test(html)) problems.push(`${rel}: style="" attributes are blocked by the CSP`);
  if (/\son[a-z]+\s*=/i.test(html)) problems.push(`${rel}: inline event handlers are blocked by the CSP`);
}

if (problems.length) {
  console.error(problems.join("\n"));
  console.error(`\nlint: ${problems.length} problem${problems.length === 1 ? "" : "s"}`);
  process.exit(1);
}
console.log(`lint: ${checked} JS files, 2 JSON files and ${files.filter((f) => extname(f) === ".html").length} HTML files OK`);
