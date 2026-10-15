import { authorizeAdmin } from "../lib/admin.js";
import { send } from "../lib/private-api.js";
import { pricingSheet } from "../lib/pricing.js";

// Private, admins only (lib/admin.js): GET /api/pricing → every price and offer from lib/config.js
// for the /tools/pricing sheet. Never linked from the public lander or client plans.
export default async function handler(req, res) {
  if (req.method !== "GET") return send(res, 405, { error: "Use GET /api/pricing" }, { Allow: "GET" });
  const ctx = await authorizeAdmin(req, res);
  if (!ctx) return;
  return send(res, 200, pricingSheet());
}
