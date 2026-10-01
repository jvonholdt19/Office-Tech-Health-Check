// Local preview without the Vercel CLI: serves /public and routes /api/scan to the function.
import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import handler from "../api/scan.js";
import planHandler from "../api/plan.js";

const root = fileURLToPath(new URL("../public/", import.meta.url));
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".ico": "image/x-icon" };
const port = Number(process.env.PORT || 3000);

http
  .createServer(async (req, res) => {
    const { pathname } = new URL(req.url, "http://localhost");
    if (pathname === "/api/scan") return handler(req, res);
    if (pathname === "/api/plan") return planHandler(req, res);
    if (pathname === "/plan") req.url = "/plan.html";
    const file = normalize(join(root, pathname === "/" ? "index.html" : pathname === "/plan" ? "plan.html" : pathname));
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
