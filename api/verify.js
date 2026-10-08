import { normalizeDomain } from "../lib/domain.js";
import { defaultDeps } from "../lib/net.js";
import { verifyLive } from "../lib/verify.js";
import { authorize, send, readJson } from "../lib/private-api.js";

// Private endpoint: POST /api/verify { domain, changes } → checks each day-one change against public DNS.
export default async function handler(req, res) {
  if (req.method !== "POST") return send(res, 405, { error: "Use POST" }, { Allow: "POST" });
  if (!authorize(req, res, { limit: 30 })) return;
  let body;
  try {
    body = await readJson(req, 200_000);
  } catch (err) {
    return send(res, err.status || 400, { error: "Couldn't read the request." });
  }
  const parsed = normalizeDomain(body.domain || "");
  if (parsed.error) return send(res, 400, { error: parsed.error });
  try {
    return send(res, 200, await verifyLive(parsed.domain, body.changes, defaultDeps));
  } catch (err) {
    return send(res, 400, { error: err.message || "Couldn't verify." });
  }
}
