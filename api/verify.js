import { normalizeDomain } from "../lib/domain.js";
import { defaultDeps } from "../lib/net.js";
import { verifyLive } from "../lib/verify.js";
import { authorize, send, readJson } from "../lib/private-api.js";
import { audit } from "../lib/audit.js";

// Private endpoint: POST /api/verify { domain, changes } → checks each day-one change against public DNS.
export default async function handler(req, res) {
  if (req.method !== "POST") return send(res, 405, { error: "Use POST" }, { Allow: "POST" });
  const auth = await authorize(req, res);
  if (!auth) return;
  let body;
  try {
    body = await readJson(req, 200_000);
  } catch (err) {
    return send(res, err.status || 400, { error: "Couldn't read the request." });
  }
  const parsed = normalizeDomain(body.domain || "");
  if (parsed.error) return send(res, 400, { error: parsed.error });
  try {
    const result = await verifyLive(parsed.domain, body.changes, defaultDeps);
    await audit("verify", { sid: auth.sid, ip: auth.ip, ua: auth.ua, domain: parsed.domain, checked: result.results.length, allDone: result.allDone }, auth.store);
    return send(res, 200, result);
  } catch (err) {
    return send(res, 400, { error: err.message || "Couldn't verify." });
  }
}
