// Builds the legal text in public/terms.html and public/privacy.html from the Markdown sources in
// docs/legal/. Only the block between <!-- LEGAL TEXT START --> and <!-- LEGAL TEXT END --> is
// rewritten, so layout, header and footer never change. To publish an attorney's version: replace
// the .md file and run `node scripts/sync-legal.js`. Not part of the build; test/legal.test.js fails
// until the pages match their sources.
//
// Zero dependencies: a small converter for the Markdown these documents use (# and ## headings,
// paragraphs, "- " lists, "> " notes, **bold**, `code`, [text](link)). Everything is HTML-escaped.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const LEGAL_PAGES = {
  "public/terms.html": "docs/legal/terms-of-service.md",
  "public/privacy.html": "docs/legal/privacy-policy.md",
};

export const START = "<!-- LEGAL TEXT START";
export const END = "<!-- LEGAL TEXT END -->";

const escape = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const slug = (s) => s.toLowerCase().replace(/^\d+\.\s*/, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

/** **bold**, `code` and [text](url) on already-escaped text. Only https:, mailto: and same-site links. */
export function inline(text) {
  return escape(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\(((?:https:\/\/|mailto:|\/)[^)\s]*)\)/g, '<a href="$2">$1</a>');
}

/** Markdown → indented HTML lines. "Last updated: …" becomes <p id="last-updated">. */
export function legalHtml(markdown, indent = "      ") {
  const out = [];
  let para = [];
  let list = null;
  const flushPara = () => {
    if (para.length) out.push(`<p>${inline(para.join(" "))}</p>`);
    para = [];
  };
  const flushList = () => {
    if (list) out.push("<ul>", ...list.map((li) => `  <li>${inline(li)}</li>`), "</ul>");
    list = null;
  };
  for (const raw of markdown.replace(/\r\n/g, "\n").split("\n")) {
    const line = raw.trim();
    if (!line) {
      flushPara();
      flushList();
    } else if (line.startsWith("# ")) {
      flushPara();
      flushList();
      out.push(`<h1 id="legal-title">${inline(line.slice(2))}</h1>`);
    } else if (line.startsWith("## ")) {
      flushPara();
      flushList();
      const title = line.slice(3);
      out.push(`<h2 id="${slug(title)}">${inline(title)}</h2>`);
    } else if (/^last updated:/i.test(line)) {
      flushPara();
      flushList();
      out.push(`<p class="legal-updated" id="last-updated">${inline(line)}</p>`);
    } else if (line.startsWith("> ")) {
      flushPara();
      flushList();
      out.push(`<p class="legal-note" role="note">${inline(line.slice(2))}</p>`);
    } else if (line.startsWith("- ")) {
      flushPara();
      (list ||= []).push(line.slice(2));
    } else {
      flushList();
      para.push(line);
    }
  }
  flushPara();
  flushList();
  return out.map((l) => indent + l).join("\n");
}

/** The page with its legal block replaced by the HTML for `markdown`, keeping the START comment line. */
export function withLegalText(page, markdown, source) {
  const start = page.indexOf(START);
  const end = page.indexOf(END);
  if (start < 0 || end < start) throw new Error("no <!-- LEGAL TEXT START --> … <!-- LEGAL TEXT END --> block");
  const lineStart = page.lastIndexOf("\n", start) + 1;
  const indent = page.slice(lineStart, start);
  const head = `${START}: generated from ${source} by scripts/sync-legal.js. Replace that file and re-run to update. -->`;
  return `${page.slice(0, start)}${head}\n${legalHtml(markdown, indent)}\n${indent}${page.slice(end)}`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const root = fileURLToPath(new URL("../", import.meta.url));
  for (const [page, source] of Object.entries(LEGAL_PAGES)) {
    const path = join(root, page);
    writeFileSync(path, withLegalText(readFileSync(path, "utf8"), readFileSync(join(root, source), "utf8"), source));
    console.log(`synced ${page} from ${source}`);
  }
}
