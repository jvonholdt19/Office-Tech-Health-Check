# Office Tech Health Check

IT and security health checks for small offices, by NWIM Project Management.

| Route | Who | What |
|---|---|---|
| `/` | Public | Lander with a limited **Quick email security check (preview)**: grade plus pass/warn/fail for SPF, DMARC and HTTPS (`GET /api/preview`). `noindex`. |
| `/tools` | Technicians | Dashboard (access-code sign-in) |
| `/tools/email` | Technicians | **Email Security Check**: the full email and domain scanner below (`GET /api/scan`) |
| `/tools/website` | Technicians | **Website Security Check** (`GET /api/website`) |
| `/tools/domain` | Technicians | **Domain Health** (`GET /api/domain`) |
| `/plan` | Technicians | Fix Plan Builder |

Old scanner links (`/?d=acme.com`, `/?domain=acme.com`) redirect (307) to `/tools/email?d=acme.com` (rules in `lib/redirects.js`, mirrored in `vercel.json`), so signed-out visitors land on the sign-in gate and the domain is filled in after sign-in.

The Email Security Check looks at, using only public records:

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
- `public/`: static pages (HTML, CSS and vanilla JS)
- `api/*.js`: Vercel Node.js serverless functions (`/api/preview` is public; `/api/scan`, `/api/website`, `/api/domain`, `/api/plan`, `/api/verify` need a technician session)
- `lib/`: the checks, written as plain Node modules (`node:dns`, `node:tls`, `node:http`, `fetch`)

## Run locally

```bash
npm run dev                          # http://localhost:3000
npm run scan -- acmeaccounting.com   # CLI report (add --json for raw output)
npm run website -- acmeaccounting.com  # Website Security Check from the CLI (add --json)
npm test                             # unit tests, no network needed
npm run lint                         # zero-dependency lint: node --check + CSP-safe HTML
npm run build                        # lint + tests
```

## Client DNS records and dry run (private, on /plan)

- **Upload the client's records:** export the zone from their DNS host (zone file, CSV or Route 53 JSON) and upload or paste it on `/plan`. The checks run against the file (custom-named DKIM keys become visible) and it's compared with live DNS to catch an out-of-date export. Uploads are used for that one request and never stored.
- **Dry run:** every plan applies its day-one changes to a copy of the records and re-runs every check. It is **blocked** if anything gets worse, SPF goes over 10 lookups or includes a dead service, a sender would be dropped, DMARC would tighten on day one or lose the client's report address, or any non-email record would change. It says **check before applying** when something (e.g. live DNS) couldn't be confirmed.
- **Export and verify:** download only the day-one changes (zone format or CSV, never a full zone), then use **Verify live** to tick off each change once it's published.

## Deploy

Import the GitHub repo into Vercel with the Framework Preset set to **Other**. No build command is needed beyond `npm run build` (lint + tests), which Vercel runs automatically. Every API, including the public preview (rate limits), needs the variables listed under [Technician access and environment variables](#technician-access-and-environment-variables).

## Technician tools (private, /tools)

`/tools` is a dashboard of technician tools behind the same sign-in as `/plan`. The cards come from the `TOOLS` registry in `public/tools.js` (`{ id, name, blurb, href, status: "live" | "soon" }`); moving a tool means changing its `href` there. Live today: the Email Security Check (`/tools/email`), Domain Health (`/tools/domain`) and the Website Security Check (`/tools/website`).

**Website Security Check** makes plain GETs to the homepage over HTTPS and HTTP and follows up to 5 redirects by hand. Every hop is re-resolved and vetted (private, loopback, link-local and metadata addresses are refused) and limited to http(s), default ports, no IP literals and the exact host entered plus its `www.` variant (`acme.com` ↔ `www.acme.com`). A redirect anywhere else, other subdomains included, is reported as an off-site redirect and not followed. `/tools/website?t=acme.com` only pre-fills the field; a scan runs only when the technician presses **Check website**. It never probes other paths or sends payloads.

Grading follows Mozilla HTTP Observatory, the OWASP Secure Headers Project, OWASP ASVS 4.0.3 (V14.4 headers, V3.4 cookies) and SSL Labs basics, softened where a small office would otherwise be marked down for optional extras.

| Area | Check | Weight | Pass / warn / fail |
|---|---|---|---|
| Encryption | Website loads over HTTPS | 15 | Fail: HTTP only, or https → http downgrade |
| Encryption | HTTP → HTTPS redirect | 10 | Warn: plain HTTP isn't redirected |
| Encryption | Certificate (apex and www) | 15 | Fail: invalid, expired, untrusted, or under 7 days left. Warn: under 21 days, or invalid on www only when the site never uses www |
| Encryption | TLS version and key (same handshake) | 0 (info) | Fail (not scored, caps grade): TLS 1.0/1.1 only, or RSA under 2048 bits |
| Browser protections | HSTS | 8 | Pass: max-age ≥ 6 months (includeSubDomains/preload noted, no score change). Warn: shorter. Fail: missing, max-age=0, or sent over plain HTTP only |
| Browser protections | X-Frame-Options or CSP `frame-ancestors` | 6 | Warn: missing, `ALLOW-FROM` (obsolete) or `*` |
| Browser protections | Content-Security-Policy | 5 | Pass: restricts scripts. Warn: missing, report-only, no script-src/default-src, `'unsafe-inline'` without nonce/hash, or `*` / `http:` / `https:` sources. A `<meta>` CSP counts only if it restricts scripts |
| Browser protections | X-Content-Type-Options: nosniff | 4 | Warn: missing |
| Browser protections | Referrer-Policy | 2 | Pass: missing (browser default is safe) or a safe value. Warn: `unsafe-url`, `no-referrer-when-downgrade` |
| Browser protections | Permissions-Policy | 0 (info) | Advice only |
| Browser protections | CORS | 0 (3 when warned) | Info: none or `*`. Warn: credentials allowed for another origin or `null` |
| Page content | Cookie flags (names only, never values) | 8 | Fail: no `Secure` on HTTPS. Warn: no `HttpOnly` on a session-looking cookie. Missing `SameSite` alone is info (browsers default to Lax) |
| Page content | Mixed content | 6 | Fail: http:// scripts, iframes, stylesheets or form actions. Warn: http:// images, audio, video |
| Page content | Subresource Integrity on third-party scripts | 3 | Warn: a script from a smaller third-party host without `integrity=`. Info: only well-known providers (analytics, tag managers, CDNs) |
| Software | Version numbers in Server / X-Powered-By | 3 | Warn |
| Software | WordPress core vs api.wordpress.org (only when WordPress is detected) | 8 | Warn: behind on patches or one branch behind. Fail: two or more branches behind |

Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F (the same scale as the email scan). On top of that, **hard caps** limit the grade without changing the score number:

| Condition | Grade at most |
|---|---|
| No working HTTPS, an https → http downgrade, or an invalid/expired/untrusted certificate | F |
| TLS older than 1.2 only | B |
| Plain HTTP not redirected to HTTPS | C |

The report lists the caps that applied in `data.cappedBy` (with `data.uncappedGrade`), and the page shows "Grade capped at … because …". `security.txt` and other paths are deliberately not fetched (that would be path probing).

**How to fix guides.** Every warning or failure in the report carries a guide (`check.guide`, attached server-side from `lib/fix-guides.js`; passing checks carry none). A guide gives a plain-English "why it matters", difficulty and time, a risk box where a change can break things (HSTS, CSP, framing, cookies, TLS, WordPress updates), steps per platform (Cloudflare, WordPress, Apache, Nginx, IIS, and website builders, with an honest "possible / partly / usually not possible"), copyable snippets, a ready-to-send message for the web host or developer, how to verify, and the official sources each step was checked against. The "Platform for this client" picker shows (and prints) only that platform. **Save as PDF** expands every guide for printing.

## Public preview (/)

The lander's preview calls `GET /api/preview?domain=` and returns only `{ domain, grade, items: [{ id, title, status }] }` for SPF, DMARC and the website certificate, graded with the same scoring as the full check. No records, details, fixes or Fix Plan. Limits are durable (Supabase `rate_limit_hit`), and the endpoint fails closed (503) if the store is unavailable:

| Limit | Value |
|---|---|
| Per client (`x-real-ip`, set by Vercel; IPv6 by /64 prefix) | 5 per 10 minutes and 20 per day |
| Per domain (all visitors) | 3 per 10 minutes |
| Global | 300 per hour |

The per-client limits are checked first and on their own: a request they refuse never touches the per-domain or global counters, so one client can't use up the global cap or lock a domain for others. A `preview_scan` audit event (`ip`, `domain`, `grade` only) is written at most once per client per hour, so audit volume stays bounded.

## Domain Health (private, /tools/domain)

Passive only: DNS lookups, the registry's RDAP record, and SOA/DNSKEY questions sent to the domain's own nameservers (UDP 53, public IPs only, at most 6 nameservers, 3 s each; `lib/dnswire.js`). No HTTP to the domain, no port scans, no zone transfers.

| Check | Weight | Pass / warn / fail | Basis |
|---|---|---|---|
| Renewal date (RDAP) | 20 | Fail under 14 days or expired; warn under 60 | ICANN ERRP (reminders ~1 month and ~1 week before expiry) |
| Transfer lock and status | 10 | Pass with client/server transfer prohibited; warn without; fail on redemption period, pending delete or hold | ICANN EPP status codes, RFC 5731, RFC 8056 |
| Nameservers | 15 | Fail with fewer than 2 or one that doesn't resolve; warn when one isn't authoritative (lame) | RFC 1034 §4.1, RFC 2182, RFC 1912 §2.8, RFC 8499 |
| Mail servers (MX) | 10 | Fail when an MX host doesn't resolve or is private; null MX / no MX is info | RFC 5321 §5, RFC 7505 |
| Email authentication | 10 | Warn when SPF or DMARC is missing (presence only; links to the Email Security Check) | RFC 7208, RFC 7489 |
| Dangling CNAME | 10 | Fail when www/mail/shop/blog/apex points at a service can-i-take-over-xyz lists as vulnerable with an NXDOMAIN fingerprint (Azure, AWS Elastic Beanstalk, Discourse) and the target is NXDOMAIN; warn for other NXDOMAIN targets | can-i-take-over-xyz |
| SOA | 5 | Warn on serial mismatch between nameservers; timers outside RFC 1912 guidance are info only | RFC 1912 §2.2, RFC 2308 |
| CAA | 3 | Pass when present; none is info | RFC 8659 |
| DNSSEC | 0 | Info when unsigned; fail when the registry has a DS but the nameservers serve no DNSKEY | RFC 4033 |

Caps: expired, redemption period or pending delete → F; a nameserver that doesn't resolve → at most D. The email scanner's own registration check keeps its 30/90-day thresholds. Every warning or failure carries a guide for registrars (GoDaddy, Namecheap, Cloudflare Registrar) and DNS hosts (Cloudflare, Microsoft 365, Google Workspace), using only steps confirmed on each vendor's own help pages. `domain_scan` is audited like `website_scan`, and each domain can be checked at most 3 times a minute.

## Fix Plan Builder (private)

`/plan` turns a scan into **two documents**: a client-facing fix plan (plain English, phases, prices, package total, timeline, what access is needed) and a **technician checklist** (exact DNS records with copy buttons, click paths for the client's DNS host, provider-specific DKIM steps, verification and follow-ups).

Rules the generator follows:
- It only proposes fixes for checks the report marked **At risk** or **Needs attention**. Passing checks are never charged for.
- Checks marked **Couldn't verify** become free "confirm at kickoff" items.
- SPF repairs keep every existing sender, merge duplicate records, add the email platform and end in `~all`.
- DMARC is staged: `p=none` with reports, then `quarantine`, then `reject`.

**Setup (one time):** see [Technician access and environment variables](#technician-access-and-environment-variables) below, then:
1. Edit prices, the package, the monthly offer and branding in `lib/config.js`.
2. DMARC reports for clients go to `BUSINESS.dmarcReportAddress` (default `dmarc@nwimpm.com`). In Cloudflare, nwimpm.com:
   - Email Routing → add a rule for `dmarc@nwimpm.com`, sending to a mailbox of your choice.
   - DNS → add TXT `*._report._dmarc` with value `v=DMARC1`. This one wildcard record authorizes reports from every client domain.

## Accuracy rules (RFCs)

- **SPF (RFC 7208):** lookups are counted exactly as §4.6.4 defines them: every `include`, `a`, `mx`, `ptr`, `exists` and `redirect` each time it's evaluated, following includes and redirects with loop detection (`redirect` is ignored when the record has `all`, §6.1). Void lookups (no answer) over 2 fail; an `mx` with over 10 names, unknown mechanisms and repeated `redirect=`/`exp=` are permanent errors; `ptr` is flagged (§5.5). If any lookup fails the count is shown as "at least N", never as exact.
- **SPF proposals** are merge-safe: one record, every existing term kept in order, the platform include placed before `all`, `exp=` kept, `-all` kept if present (else `~all`). Only `ptr` and true duplicates are removed, each with a reason. Long records are split into 255-byte strings. A proposal needing over 10 lookups, over 2 void lookups, or whose count couldn't be verified can't be copied without an explicit override.
- **DMARC (RFC 7489):** the record must start with exactly `v=DMARC1`, `p` is required; `sp`, `adkim`, `aspf`, `pct` (0–100) and `rua`/`ruf` (`mailto:` only) are validated. External report addresses must be authorized with `<domain>._report._dmarc.<destination>` (§7.1); the plan checks our own report address the same way. Merges keep every client tag.
- **DKIM (RFC 6376, RFC 8301, RFC 8463):** keys are decoded to read their real size: under 1024 bits fails, 1024 warns (2048 recommended), 2048+ passes; Ed25519 is accepted; `t=y` warns.
- **MX:** Google Workspace is recognised by its exact documented MX names only; Google mixed with other mail servers warns. The plan never proposes deleting an MX record.

## Safety guards (server-side)

Every plan is turned into a **change set** (before/after values for each changed name and type) and checked in `lib/guards.js`. A change set is blocked if it would remove an MX, NS, SOA, A/AAAA/CNAME, a non-SPF/DMARC TXT record or a DKIM selector; leave two SPF or two DMARC records; drop an SPF mechanism without a listed reason; or touch more than 5 records (`too-broad`). An upload that differs from live DNS is blocked (`upload-mismatch`) until the technician ticks **I confirm the export is current**. A partial-looking export gets a warning.

The technician reviews a Before | After diff, presses **Confirm changes** and types the domain. `/api/plan/confirm` rebuilds the plan, recomputes the change-set hash and the guards, logs the confirmation, and only then are the **Copy value** buttons and downloads unlocked. **This tool never writes to a DNS provider or registrar.** Uploaded zones are never stored; only their SHA-256, size and format are logged.

Website checks resolve the host first and refuse private, loopback, link-local, CGNAT, multicast and IPv4-mapped addresses, then connect to the vetted IP.

## Technician access and environment variables

`/plan` and its APIs are for technicians only. Sign-in is checked on the server and kept in a signed, `HttpOnly; Secure; SameSite=Strict` cookie for 8 hours. Nothing secret is stored in the browser.

Set these in Vercel → Project → Settings → Environment Variables (server-side only; never prefix them with `NEXT_PUBLIC_` or put them in `public/`), then redeploy:

| Variable | What it is |
|---|---|
| `TECH_ACCESS_CODE` | The technician access code (8+ characters). |
| `SESSION_SECRET` | Random string of at least 32 characters used to sign session cookies, e.g. `openssl rand -base64 48`. Changing it signs everyone out. |
| `SUPABASE_URL` | Your Supabase project URL (`https://<project>.supabase.co`). |
| `SUPABASE_SERVICE_ROLE_KEY` | The project's service-role (secret) key. Used only by the serverless functions. |

The technician endpoints **fail closed** (503) until `SESSION_SECRET` (32+ characters), an access code and both Supabase variables are set.

**Supabase (rate limits and audit log):** run `supabase/migrations/20261013000000_dns_scanner.sql` once (Supabase dashboard → SQL Editor, or `supabase db push`). It creates the `rate_limit` and `audit_log` tables with row level security on and no `anon`/`authenticated` policies, plus the `rate_limit_hit` and `audit_append` functions (service role only). Limits: 5 failed sign-ins per IP per 15 minutes, 20 failed sign-ins overall per hour, 30 plan/verify/confirm requests per session per 10 minutes. The audit log keeps the newest 5000 events: `login_success`, `login_failure`, `logout`, `plan_build`, `plan_confirm`, `verify`, `scan`, `website_scan`, `domain_scan` (target plus score, grade, counts and duration only), and `preview_scan` (at most once per IP per hour: ip, domain, grade). `/api/website` also limits each target site to 3 checks per minute across all sessions.

**Migrating from `PLAN_PASSCODE`:** `PLAN_PASSCODE` is still accepted as the access code while `TECH_ACCESS_CODE` isn't set. To migrate: add `TECH_ACCESS_CODE`, `SESSION_SECRET`, `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`, run the migration, redeploy, sign in once to check, then delete `PLAN_PASSCODE`. The old `x-plan-passcode` header no longer works.

`npm run dev` uses an in-memory store when the Supabase variables aren't set, so the technician pages can be tried locally (`SESSION_SECRET=… TECH_ACCESS_CODE=… npm run dev`).

## Customize

- **Contact details:** the phone number and email on the lander are in `public/index.html` (call to action and footer).
- **Branding:** the name appears in `public/index.html` (title, header, footer). Colors are CSS variables at the top of `public/styles.css`.

## Roadmap

- v2: an AI-written executive summary (Claude) and an emailed PDF report
- Save scans to Supabase as a lead list, plus a monthly re-scan for retainer clients
- Extra checks: MTA-STS, BIMI, Microsoft 365 tenant detection, blocklist lookups
