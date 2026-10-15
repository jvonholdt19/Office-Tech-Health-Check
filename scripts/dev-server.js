// Local preview without the Vercel CLI: serves /public (with clean URLs, like Vercel) and routes /api/* to the functions.
import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import handler from "../api/scan.js";
import planHandler from "../api/plan.js";
import verifyHandler from "../api/verify.js";
import sessionHandler from "../api/session.js";
import confirmHandler from "../api/plan-confirm.js";
import websiteHandler from "../api/website.js";
import { setStoreForTests, memoryStore } from "../lib/store.js";

// Local preview only: without Supabase credentials, keep rate limits and the audit log in memory so
// the technician pages can be tried out. Deployed functions never do this; they fail closed.
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.warn("[dev] Supabase isn't configured: using an in-memory store for rate limits and the audit log.");
  setStoreForTests(memoryStore());
}

const root = fileURLToPath(new URL("../public/", import.meta.url));
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".ico": "image/x-icon" };
const port = Number(process.env.PORT || 3000);

http
  .createServer(async (req, res) => {
    const { pathname } = new URL(req.url, "http://localhost");
    if (pathname === "/api/scan") return handler(req, res);
    if (pathname === "/api/plan") return planHandler(req, res);
    if (pathname === "/api/verify") return verifyHandler(req, res);
    if (pathname === "/api/session") return sessionHandler(req, res);
    if (pathname === "/api/plan/confirm") return confirmHandler(req, res);
    if (pathname === "/api/website") return websiteHandler(req, res);
    // cleanUrls: /plan → plan.html, /tools → tools.html, /tools/website → tools/website.html
    const rel = pathname === "/" ? "index.html" : extname(pathname) ? pathname : `${pathname.replace(/\/+$/, "")}.html`;
    const file = normalize(join(root, rel));
    if (!file.startsWith(root)) {
      res.writeHead(403).end();
      return;
    }
    try {
      const body = await readFile(file);
      res.writeHead(200, { "Content-Type": types[extname(file)] || "application/octet-stream" }).end(body);
    } catch {
      res.writeHead(404).end("Not found");
    }
  })
  .listen(port, () => console.log(`Office Tech Health Check running at http://localhost:${port}`));
