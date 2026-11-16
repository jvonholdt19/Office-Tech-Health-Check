// DMARC Tracker Cron: daily recheck of all tracked domains.
// Called by Vercel Cron (configured in vercel.json).

import { recheckAllTrackedDomains, getTrackerStore } from "../../lib/dmarc-tracker.js";
import { defaultDeps } from "../../lib/net.js";
import { getStore } from "../../lib/store.js";

export default async function handler(req, res) {
  // Verify this is a cron request from Vercel (fail closed: require CRON_SECRET)
  const authHeader = req.headers["authorization"];
  const cronSecret = process.env.CRON_SECRET;
  
  if (!cronSecret) {
    console.error("[dmarc-recheck] CRON_SECRET not set, refusing to run");
    return res.status(401).json({ error: "CRON_SECRET must be set in Vercel environment variables" });
  }
  
  if (authHeader !== `Bearer ${cronSecret}`) {
    console.error("[dmarc-recheck] Invalid authorization header");
    return res.status(401).json({ error: "Unauthorized" });
  }

  const store = getTrackerStore();
  if (!store) {
    return res.status(503).json({ error: "Store not available" });
  }

  try {
    const results = await recheckAllTrackedDomains(store, defaultDeps);
    
    const summary = {
      total: results.length,
      successful: results.filter((r) => r.success).length,
      failed: results.filter((r) => !r.success).length,
      canAdvance: results.filter((r) => r.success && r.canAdvance).length,
    };
    
    await getStore()?.audit({
      event: "dmarc_tracker_cron",
      data: summary,
    });
    
    return res.status(200).json({
      success: true,
      summary,
      results,
    });
  } catch (err) {
    console.error("[dmarc-recheck]", err);
    return res.status(500).json({ error: err.message });
  }
}
