import { isIP } from "node:net";

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/**
 * Turn whatever someone types ("https://www.Acme.com/contact", "info@acme.com",
 * "acme.com") into a bare registrable-looking hostname, or explain why not.
 * We deliberately refuse IPs, single-label names and internal-looking hosts so
 * the scanner can only be pointed at public internet domains.
 */
export function normalizeDomain(input) {
  if (typeof input !== "string") return { error: "Enter a domain, like acmeaccounting.com." };
  let s = input.trim().toLowerCase();
  if (!s) return { error: "Enter a domain, like acmeaccounting.com." };
  if (s.length > 253 + 20) return { error: "That domain is too long." };

  // Email address -> domain part
  if (s.includes("@") && !s.includes("/")) s = s.split("@").pop();
  // Strip scheme, path, query, port, trailing dot
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  s = s.split(/[/?#]/)[0];
  s = s.replace(/:\d+$/, "").replace(/\.$/, "");
  // Strip a leading www. so we analyse the organisation's domain
  if (s.startsWith("www.")) s = s.slice(4);

  if (isIP(s) || /^\[.*\]$/.test(s)) return { error: "Enter a domain name, not an IP address." };

  const labels = s.split(".");
  if (labels.length < 2) return { error: "That doesn't look like a full domain (e.g. acmeaccounting.com)." };
  if (s.length > 253 || !labels.every((l) => LABEL.test(l))) {
    return { error: "That doesn't look like a valid domain." };
  }
  const tld = labels[labels.length - 1];
  if (!/^(xn--[a-z0-9-]+|[a-z]{2,63})$/.test(tld)) return { error: "That doesn't look like a valid domain." };
  const blocked = ["localhost", "local", "internal", "lan", "home", "corp", "intranet", "test", "invalid", "example"];
  if (blocked.includes(tld)) return { error: "Only public internet domains can be checked." };

  return { domain: s };
}
