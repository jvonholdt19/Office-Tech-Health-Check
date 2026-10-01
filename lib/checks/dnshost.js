import { withTimeout, isNotFound } from "../net.js";

// Where a domain's DNS records are edited, identified from its nameservers.
// `where` is the click path for adding a record, shown in the technician checklist.
export const DNS_HOSTS = [
  { key: "cloudflare", name: "Cloudflare", match: /\.ns\.cloudflare\.com$/, where: "Cloudflare dashboard → select the domain → DNS → Records → Add record" },
  { key: "godaddy", name: "GoDaddy", match: /\.domaincontrol\.com$/, where: "GoDaddy → My Products → the domain → DNS → Add New Record" },
  { key: "namecheap", name: "Namecheap", match: /\.registrar-servers\.com$/, where: "Namecheap → Domain List → Manage → Advanced DNS → Add New Record" },
  { key: "squarespace", name: "Squarespace Domains", match: /(squarespacedns\.com|googledomains\.com)$/, where: "Squarespace → Domains → the domain → DNS → Custom records → Add record" },
  { key: "route53", name: "Amazon Route 53", match: /\.awsdns-\d+\./, where: "AWS console → Route 53 → Hosted zones → the domain → Create record" },
  { key: "azure", name: "Azure DNS", match: /\.azure-dns\./, where: "Azure portal → DNS zones → the domain → + Record set" },
  { key: "microsoft365", name: "Microsoft 365 (DNS hosted by Microsoft)", match: /\.bdm\.microsoftonline\.com$/, where: "Microsoft 365 admin center → Settings → Domains → the domain → DNS records → Add record" },
  { key: "wix", name: "Wix", match: /\.wixdns\.net$/, where: "Wix → Domains → the domain → ⋯ → Manage DNS records → Add record" },
  { key: "ionos", name: "IONOS", match: /\.ui-dns\.(com|org|de|biz)$/, where: "IONOS → Domains & SSL → the domain → DNS → Add record" },
  { key: "networksolutions", name: "Network Solutions", match: /\.worldnic\.com$/, where: "Network Solutions → My Domain Names → Manage → Advanced DNS → Edit" },
  { key: "bluehost", name: "Bluehost", match: /\.bluehost\.com$/, where: "Bluehost → Domains → the domain → DNS → Add record" },
  { key: "hostgator", name: "HostGator", match: /\.hostgator\.com$/, where: "HostGator → Domains → the domain → DNS → Add DNS record" },
  { key: "siteground", name: "SiteGround", match: /\.siteground\.net$/, where: "SiteGround → Site Tools → Domain → DNS Zone Editor" },
  { key: "dnsimple", name: "DNSimple", match: /\.dnsimple\.com$/, where: "DNSimple → the domain → DNS → Add record" },
  { key: "vercel", name: "Vercel DNS", match: /\.vercel-dns\.com$/, where: "Vercel → Domains → the domain → DNS Records → Add" },
];

export function identifyDnsHost(nameservers) {
  for (const ns of nameservers) {
    const host = ns.toLowerCase().replace(/\.$/, "");
    const h = DNS_HOSTS.find((d) => d.match.test(host));
    if (h) return { key: h.key, name: h.name, where: h.where, nameservers };
  }
  return {
    key: "other",
    name: nameservers.length ? `Other (${nameservers[0]})` : "Unknown",
    where: "the DNS provider's control panel (find it by who runs the nameservers listed below)",
    nameservers,
  };
}

/** Never throws: DNS-host detection only improves the instructions; it isn't a scored check. */
export async function detectDnsHost(domain, { resolver }) {
  try {
    const ns = await withTimeout(resolver.resolveNs(domain), 5000, `NS ${domain}`);
    return identifyDnsHost(ns);
  } catch (err) {
    return { key: "unknown", name: "Unknown", where: "the domain's DNS provider", nameservers: [], error: isNotFound(err) ? "no NS records" : err.code || err.message };
  }
}
