// Old scanner links: the email scanner used to live at / and took ?d=acme.com (and ?domain=acme.com).
// These rules send them to the technician tool with the domain spelled out in the destination. The
// same rules are in vercel.json (a test keeps the two identical); the dev server applies them here.
// The value pattern only captures domain characters, so anything else simply shows the lander.
export const OLD_LINK_REDIRECTS = [
  { source: "/", has: [{ type: "query", key: "d", value: "(?<d>[A-Za-z0-9.-]+)" }], destination: "/tools/email?d=:d", permanent: false },
  { source: "/", has: [{ type: "query", key: "domain", value: "(?<domain>[A-Za-z0-9.-]+)" }], destination: "/tools/email?d=:domain", permanent: false },
];

/**
 * Apply the rules to a request URL the way Vercel does: the path must equal `source`, each `has`
 * query value must fully match its pattern, and named groups fill `:name` in the destination.
 * Returns { status, location } or null.
 */
export function oldLinkRedirect(requestUrl, rules = OLD_LINK_REDIRECTS) {
  const url = new URL(requestUrl, "http://localhost");
  for (const rule of rules) {
    if (url.pathname !== rule.source) continue;
    const groups = {};
    const ok = rule.has.every((h) => {
      const value = url.searchParams.get(h.key);
      if (value === null) return false;
      const m = value.match(new RegExp(`^(?:${h.value})$`));
      if (!m) return false;
      Object.assign(groups, m.groups || {});
      return true;
    });
    if (!ok) continue;
    const location = rule.destination.replace(/:([A-Za-z_]\w*)/g, (_, name) => encodeURIComponent(groups[name] ?? ""));
    return { status: rule.permanent ? 308 : 307, location };
  }
  return null;
}
