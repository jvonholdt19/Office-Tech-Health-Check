// Rewrites the shared header and footer in every page from scripts/site-chrome.js.
// Run by hand after editing site-chrome.js: `node scripts/sync-chrome.js`. Not part of the build;
// test/branding.test.js fails until the pages match.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PAGES, header, footer, HEADER_RE, FOOTER_RE } from "./site-chrome.js";

const root = fileURLToPath(new URL("../", import.meta.url));
for (const [file, page] of Object.entries(PAGES)) {
  const path = join(root, file);
  let html = readFileSync(path, "utf8");
  if (!HEADER_RE.test(html)) throw new Error(`${file}: no <header class="site-header"> to replace`);
  html = html.replace(HEADER_RE, () => header(page));
  if (FOOTER_RE.test(html)) html = html.replace(FOOTER_RE, () => footer(page));
  else if (html.includes("  </main>\n")) html = html.replace("  </main>\n", () => `  </main>\n\n${footer(page)}\n`);
  else throw new Error(`${file}: no footer and no </main> to put one after`);
  writeFileSync(path, html);
  console.log(`synced ${file}`);
}
