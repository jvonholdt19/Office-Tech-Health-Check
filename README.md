# Office Tech Health Check

A free, 30-second report card for a small business's domain. Enter `yourbusiness.com` and it checks, using only public records:

| Area | Check | Weight |
|---|---|---|
| Email platform | Google Workspace / Microsoft 365 / hosting email (from MX records) | info |
| Email security | SPF: exists, single record, no `+all`/`?all`, ≤10 DNS lookups, includes the platform | 20 |
| Email security | DMARC: exists, policy `quarantine`/`reject`, `pct=100`, reporting address | 25 |
| Email security | DKIM: signing key at the platform's usual selector (best effort) | 15 |
| Domain | Registration via RDAP: expiry, transfer lock, registrar, DNSSEC | 15 |
| Website | SSL certificate valid for apex and `www`, not expiring within 14 days | 15 |
| Website | `http://` redirects to `https://` | 10 |

Pass = full points, warning = half, fail = 0. Not-applicable checks (no website, no email) are left out. Checks that *couldn't be verified* (lookup failed, custom DKIM selector) are also left out of the score, but are listed on the report with the % of checks the grade is based on. No grade is shown below 50% coverage. Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F.

The weights are our own judgment, not an industry standard. The pass/warn/fail findings follow RFC 7208 (SPF), RFC 7489 (DMARC), RFC 6376 (DKIM), RFC 7505 (null MX) and RFC 9083 (RDAP).

## Stack

There are no dependencies.
- `public/`: static page (HTML, CSS and vanilla JS)
- `api/scan.js`: a Vercel Node.js serverless function, `GET /api/scan?domain=acme.com`
- `lib/`: the checks, written as plain Node modules (`node:dns`, `node:tls`, `node:http`, `fetch`)

## Run locally

```bash
npm run dev                          # http://localhost:3000
npm run scan -- acmeaccounting.com   # CLI report (add --json for raw output)
npm test                             # 38 unit tests, no network needed
```

## Deploy

Import the GitHub repo into Vercel with the Framework Preset set to **Other**. No build command or environment variables are needed.

## Fix Plan Builder (private)

`/plan` turns a scan into **two documents**: a client-facing fix plan (plain English, phases, prices, package total, timeline, what access is needed) and a **technician checklist** (exact DNS records with copy buttons, click paths for the client's DNS host, provider-specific DKIM steps, verification and follow-ups).

Rules the generator follows:
- It only proposes fixes for checks the report marked **At risk** or **Needs attention**. Passing checks are never charged for.
- Checks marked **Couldn't verify** become free "confirm at kickoff" items.
- SPF repairs keep every existing sender, merge duplicate records, add the email platform and end in `~all`.
- DMARC is staged: `p=none` with reports, then `quarantine`, then `reject`.

**Setup (one time):**
1. Vercel → Project → Settings → Environment Variables → add `PLAN_PASSCODE` (8+ characters) → redeploy. Until it's set, `/api/plan` stays locked (503).
2. Edit prices, the package, the monthly offer and branding in `lib/config.js`.
3. DMARC reports for clients go to `BUSINESS.dmarcReportAddress` (default `dmarc@nwimpm.com`). In Cloudflare, nwimpm.com:
   - Email Routing → add a rule for `dmarc@nwimpm.com`, sending to a mailbox of your choice.
   - DNS → add TXT `*._report._dmarc` with value `v=DMARC1`. This one wildcard record authorizes reports from every client domain.

## Customize

- **Booking link:** set `CONFIG.ctaUrl` at the top of `public/app.js` (Calendly, Cal.com or `mailto:`).
- **Branding:** the name appears in `public/index.html` (title, header, footer). Colors are CSS variables at the top of `public/styles.css`.

## Roadmap

- v2: an AI-written executive summary (Claude) and an emailed PDF report
- Save scans to Supabase as a lead list, plus a monthly re-scan for retainer clients
- Extra checks: MTA-STS, BIMI, Microsoft 365 tenant detection, blocklist lookups
- A shared rate limit (the current one is per instance only)
