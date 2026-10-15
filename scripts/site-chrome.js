// The canonical site header and footer. Every page in public/ carries an identical static copy (no
// JS injection, so nothing flashes and the pages work without JS). test/branding.test.js checks
// each page against these functions; `node scripts/sync-chrome.js` rewrites the pages from them.
// Run it by hand after changing anything here; it isn't part of the build.
//
// The only per-page differences are the parameters below: which kind of page it is (the lander or a
// technician page) and which nav item is the current page.

export const PAGES = {
  "public/index.html": { kind: "lander" },
  "public/tools.html": { kind: "tech", current: "/tools" },
  "public/tools/email.html": { kind: "tech", current: "/tools/email" },
  "public/tools/website.html": { kind: "tech", current: "/tools/website" },
  "public/tools/domain.html": { kind: "tech", current: "/tools/domain" },
  "public/plan.html": { kind: "tech", current: "/plan" },
};

export const NAV = [
  ["/tools", "Tools"],
  ["/tools/email", "Email"],
  ["/tools/website", "Website"],
  ["/tools/domain", "Domain"],
  ["/plan", "Fix Plan"],
];

export const PHONE = { href: "tel:+15073604479", text: "507-360-4479" };
export const EMAIL = { href: "mailto:info@nwimpm.com", text: "info@nwimpm.com" };

const indent = (lines, n = 2) => lines.map((l) => " ".repeat(n) + l).join("\n");

/** Header markup for a page: { kind: "lander" } or { kind: "tech", current: "/tools/email" }. */
export function header({ kind, current }) {
  const tech = kind === "tech";
  const right = tech
    ? [
        // Signed out (the sign-in gate): a way back to the public page. Hidden by tech-session.js once signed in.
        `<a class="header-home" id="gate-home" href="/">Back to home</a>`,
        // Signed in: the tools nav and Sign out. Hidden until the gate unlocks.
        `<nav class="tech-nav" id="tech-nav" aria-label="Tools" hidden>`,
        ...NAV.map(([href, label]) => `  <a href="${href}"${href === current ? ' aria-current="page"' : ""}>${label}</a>`),
        `  <button type="button" class="nav-signout" id="lock-btn" hidden>Sign out</button>`,
        `</nav>`,
      ]
    : [`<a class="l-btn l-btn-ghost signin-btn" href="/tools">Tech sign in</a>`];
  return indent([
    `<header class="site-header${tech ? " no-print" : ""}">`,
    `  <div class="wrap header-inner">`,
    `    <a class="brand" href="${tech ? "/tools" : "/"}">`,
    `      <svg class="brand-mark" width="32" height="32" aria-hidden="true" focusable="false"><use href="/assets/icons.svg#logo"/></svg>`,
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
  const tech = kind === "tech";
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
