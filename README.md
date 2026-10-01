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

Pass = full points, warning = half, fail = 0. Checks that can't run (no website, registry without RDAP) are left out of the score. Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F.

## Stack

There are no dependencies.
- `public/`: static page (HTML, CSS and vanilla JS)
- `api/scan.js`: a Vercel Node.js serverless function, `GET /api/scan?domain=acme.com`
- `lib/`: the checks, written as plain Node modules (`node:dns`, `node:tls`, `node:http`, `fetch`)

## Run locally

```bash
npm run dev                          # http://localhost:3000
npm run scan -- acmeaccounting.com   # CLI report (add --json for raw output)
npm test                             # 16 unit tests, no network needed
```

## Deploy

Import the GitHub repo into Vercel with the Framework Preset set to **Other**. No build command or environment variables are needed.

## Customize

- **Booking link:** set `CONFIG.ctaUrl` at the top of `public/app.js` (Calendly, Cal.com or `mailto:`).
- **Branding:** the name appears in `public/index.html` (title, header, footer). Colors are CSS variables at the top of `public/styles.css`.

## Roadmap

- v2: an AI-written executive summary (Claude) and an emailed PDF report
- Save scans to Supabase as a lead list, plus a monthly re-scan for retainer clients
- Extra checks: MTA-STS, BIMI, Microsoft 365 tenant detection, blocklist lookups
- A shared rate limit (the current one is per instance only)
