// The canonical site header and footer. Every page in public/ carries an identical static copy (no
// JS injection, so nothing flashes and the pages work without JS). test/branding.test.js checks
// each page against these functions; `node scripts/sync-chrome.js` rewrites the pages from them.
// Run it by hand after changing anything here or in the tools registry; it isn't part of the build.
//
// The header's Tools menu is generated from the same registry as the dashboard cards
// (public/tools.js), so adding a live tool there adds it to the menu on every page after a sync.
import { TOOLS, CATEGORIES } from "../public/tools.js";
import { CONTACT_EMAIL } from "../lib/config.js";

/**
 * Page kinds:
 * - lander:    public page, "Tech sign in" on the right
 * - dashboard: /tools, the dashboard cards are the tool picker, so the header has only Fix Plan and Sign out
 * - tool:      a tool page (current = the tool's href): Tools menu, Fix Plan, Sign out
 * - plan:      the Fix Plan Builder: Tools menu, Fix Plan (current), Sign out
 */
export const PAGES = {
  "public/index.html": { kind: "lander" },
  "public/tools.html": { kind: "dashboard" },
  "public/tools/email.html": { kind: "tool", current: "/tools/email" },
  "public/tools/website.html": { kind: "tool", current: "/tools/website" },
  "public/tools/domain.html": { kind: "tool", current: "/tools/domain" },
  "public/tools/breach.html": { kind: "tool", current: "/tools/breach" },
  "public/tools/pricing.html": { kind: "tool", current: "/tools/pricing" },
  "public/plan.html": { kind: "plan" },
};

export const PHONE = { href: "tel:+15073604479", text: "507-360-4479" };
export const EMAIL = { href: `mailto:${CONTACT_EMAIL}`, text: CONTACT_EMAIL }; // from lib/config.js

const indent = (lines, n = 2) => lines.map((l) => " ".repeat(n) + l).join("\n");
const current = (yes) => (yes ? ' aria-current="page"' : "");

/** Live tools grouped by category, in CATEGORIES order (empty groups left out). Coming-soon tools never appear. */
export function menuGroups(tools = TOOLS) {
  const live = tools.filter((t) => t.status === "live" && t.href);
  const unknown = live.filter((t) => !CATEGORIES.includes(t.category));
  if (unknown.length) throw new Error(`tools.js: unknown category for ${unknown.map((t) => t.id).join(", ")}`);
  return CATEGORIES.map((category) => ({ category, tools: live.filter((t) => t.category === category) })).filter((g) => g.tools.length);
}

/** The Tools dropdown: a <details> menu, so it opens and closes without JS; tech-session.js adds Escape and click-outside. */
export function toolsMenu(currentHref) {
  const groups = menuGroups().flatMap(({ category, tools }) => {
    const id = `tools-menu-${category.toLowerCase()}`;
    // Admin-only tools (tools.js `admin`) start hidden; tech-session.js shows them for admin sessions.
    const adminGroup = tools.every((t) => t.admin) ? " data-admin hidden" : "";
    return [
      `    <p class="tools-menu-heading" id="${id}"${adminGroup}>${category}</p>`,
      `    <ul aria-labelledby="${id}"${adminGroup}>`,
      ...tools.map((t) =>
        t.feature
          ? // Behind a feature switch: "Coming soon" until GET /api/session says the switch is on
            // (tech-session.js then swaps the label for the link). Without JS it stays "Coming soon".
            `      <li data-feature="${t.feature}"><a href="${t.href}"${current(t.href === currentHref)} hidden>${t.name}</a><span class="tools-menu-soon">${t.name} <span class="soon-tag">Coming soon</span></span></li>`
          : `      <li${t.admin && !adminGroup ? " data-admin hidden" : ""}><a href="${t.href}"${current(t.href === currentHref)}>${t.name}</a></li>`,
      ),
      `    </ul>`,
    ];
  });
  return [
    `<details class="tools-menu">`,
    `  <summary>Tools</summary>`,
    `  <div class="tools-menu-panel">`,
    `    <a class="tools-menu-all" href="/tools">All tools</a>`,
    ...groups,
    `  </div>`,
    `</details>`,
  ];
}

/** Header markup for a page (see PAGES). */
export function header({ kind, current: currentHref }) {
  const tech = kind !== "lander";
  const right = tech
    ? [
        // Both start hidden: until the session check answers the header shows neither, so it never flips
        // between them (tech-session.js shows exactly one).
        // Signed out (the sign-in gate): a way back to the public page.
        `<a class="header-home" id="gate-home" href="/" hidden>Back to home</a>`,
        // Signed in: the nav and Sign out.
        `<nav class="tech-nav" id="tech-nav" aria-label="Technician" hidden>`,
        ...(kind === "dashboard" ? [] : toolsMenu(currentHref).map((l) => `  ${l}`)),
        `  <a href="/plan"${current(kind === "plan")}>Fix Plan</a>`,
        `  <button type="button" class="nav-signout" id="lock-btn" hidden>Sign out</button>`,
        `</nav>`,
      ]
    : [`<a class="l-btn l-btn-ghost signin-btn" href="/tools">Tech sign in</a>`];
  return indent([
    `<header class="site-header${tech ? " no-print" : ""}">`,
    `  <div class="wrap header-inner">`,
    `    <a class="brand" href="${tech ? "/tools" : "/"}">`,
    `      <svg class="brand-mark" width="32" height="32" aria-hidden="true" focusable="false"><use href="/assets/icons.svg#shield-logo"/></svg>`,
    `      <span class="brand-text">`,
    `        <span class="brand-name">Office Tech Health Check</span>`,
    `        <span class="brand-sub">Powered by NWIM Project Management</span>`,
    `      </span>`,
    `    </a>`,
    ...right.map((l) => `    ${l}`),
    `  </div>`,
    `</header>`,
  ]);
}

/** Footer markup: the same contact line everywhere; the lander adds Tech sign in and the public-info note. */
export function footer({ kind }) {
  const tech = kind !== "lander";
  const main = `Office Tech Health Check · Powered by NWIM Project Management · <a href="${PHONE.href}">${PHONE.text}</a> · <a href="${EMAIL.href}">${EMAIL.text}</a>`;
  return indent([
    `<footer class="site-footer${tech ? " no-print" : ""}">`,
    `  <div class="wrap">`,
    tech ? `    <p class="footer-main">${main}</p>` : `    <p class="footer-main">${main} · <a href="/tools">Tech sign in</a></p>`,
    ...(tech ? [] : [`    <p class="footer-note">Checks use public information only. Results are a snapshot and can change.</p>`]),
    `  </div>`,
    `</footer>`,
  ]);
}

export const HEADER_RE = /^ {2}<header class="site-header[^"]*">[\s\S]*?<\/header>$/m;
export const FOOTER_RE = /^ {2}<footer class="site-footer[^"]*">[\s\S]*?<\/footer>$/m;
