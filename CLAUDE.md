# Office Tech Health Check

Zero-dependency Node app: static page in `public/`, Vercel function in `api/scan.js`, checks in `lib/`. See README.md.

## Workflow (owner's standing rule)

1. Build every change on a feature branch, never directly on `main`.
2. Check it before reporting done: run `npm test` (must pass), and run the change for real
   where possible (`npm run dev`, `npm run scan -- <domain>`). Push the branch so Vercel builds
   a preview deployment.
3. Stop and wait. Merge or push to `main` only when the owner explicitly asks.
   `main` is production: every push to it deploys to office-tech-health-check.vercel.app.
