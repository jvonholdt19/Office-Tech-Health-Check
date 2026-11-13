// DMARC Tracker API: manage staged DMARC rollout for client domains.
// GET: list tracked domains, POST: add/update/advance/remove domains.

import { authorize, send } from "../lib/private-api.js";
import { getStore } from "../lib/store.js";
import {
  listTrackedDomains,
  addTrackedDomain,
  updateTrackedDomainCheck,
  advanceTrackedDomain,
  removeTrackedDomain,
  checkDmarcAdvancement,
  getDmarcRecordForStage,
  DMARC_STAGES,
  getTrackerStore,
} from "../lib/dmarc-tracker.js";
import { defaultDeps } from "../lib/net.js";
import { normalizeDomain } from "../lib/domain.js";

export default async function handler(req, res) {
  const auth = await authorize(req, res);
  if (!auth) return;

  const store = getTrackerStore();
  if (!store) {
    return send(res, 503, { error: "Service unavailable" });
  }

  try {
    // GET: list all tracked domains
    if (req.method === "GET") {
      const domains = await listTrackedDomains(store);
      
      // Enrich with stage information
      const enriched = domains.map((d) => ({
        ...d,
        stageInfo: DMARC_STAGES[d.stage],
        daysInStage: d.stage_started_at
          ? Math.floor((Date.now() - new Date(d.stage_started_at).getTime()) / (1000 * 60 * 60 * 24))
          : 0,
      }));
      
      return send(res, 200, {
        domains: enriched,
        stages: DMARC_STAGES,
      });
    }

    // POST: add, check, advance, or remove
    if (req.method === "POST") {
      const { action, domain, id, skipToStage, note } = req.body;

      if (action === "add") {
        const parsed = normalizeDomain(domain);
        if (parsed.error) {
          return send(res, 400, { error: parsed.error });
        }

        const trackerId = await addTrackedDomain(
          store,
          parsed.domain,
          auth.sid,
          note || null
        );

        await getStore().audit({
          event: "dmarc_tracker_add",
          sid: auth.sid,
          domain: parsed.domain,
          data: { trackerId, note },
        });

        return send(res, 200, {
          success: true,
          trackerId,
          domain: parsed.domain,
        });
      }

      if (action === "check") {
        if (!id) {
          return send(res, 400, { error: "id required" });
        }

        // Get the tracker entry
        const domains = await listTrackedDomains(store);
        const tracker = domains.find((d) => d.id === id);
        if (!tracker) {
          return send(res, 404, { error: "Tracker not found" });
        }

        // Run the advancement check
        const checkResult = await checkDmarcAdvancement(
          tracker.domain,
          tracker.stage,
          tracker.stage_started_at,
          defaultDeps
        );

        // Update the tracker
        await updateTrackedDomainCheck(
          store,
          id,
          {
            checkedAt: new Date().toISOString(),
            dmarcPolicy: checkResult.currentPolicy,
            daysInStage: checkResult.daysInStage,
          },
          checkResult.canAdvance,
          checkResult.reason
        );

        await getStore().audit({
          event: "dmarc_tracker_check",
          sid: auth.sid,
          domain: tracker.domain,
          data: { id, canAdvance: checkResult.canAdvance },
        });

        return send(res, 200, {
          success: true,
          domain: tracker.domain,
          check: checkResult,
        });
      }

      if (action === "advance") {
        if (!id) {
          return send(res, 400, { error: "id required" });
        }

        const domains = await listTrackedDomains(store);
        const tracker = domains.find((d) => d.id === id);
        if (!tracker) {
          return send(res, 404, { error: "Tracker not found" });
        }

        // Verify eligibility (unless forcing with skipToStage)
        if (!skipToStage && !tracker.can_advance) {
          return send(res, 400, {
            error: "Domain is not ready to advance",
            reason: tracker.advance_note,
          });
        }

        await advanceTrackedDomain(
          store,
          id,
          skipToStage || null,
          auth.sid,
          note || null
        );

        await getStore().audit({
          event: "dmarc_tracker_advance",
          sid: auth.sid,
          domain: tracker.domain,
          data: {
            id,
            fromStage: tracker.stage,
            toStage: skipToStage || tracker.stage + 1,
            skipped: !!skipToStage,
            note,
          },
        });

        return send(res, 200, {
          success: true,
          domain: tracker.domain,
          newStage: skipToStage || tracker.stage + 1,
        });
      }

      if (action === "remove") {
        if (!id) {
          return send(res, 400, { error: "id required" });
        }

        const domains = await listTrackedDomains(store);
        const tracker = domains.find((d) => d.id === id);
        if (!tracker) {
          return send(res, 404, { error: "Tracker not found" });
        }

        await removeTrackedDomain(store, id);

        await getStore().audit({
          event: "dmarc_tracker_remove",
          sid: auth.sid,
          domain: tracker.domain,
          data: { id },
        });

        return send(res, 200, {
          success: true,
          domain: tracker.domain,
        });
      }

      return send(res, 400, { error: "Invalid action" });
    }

    return send(res, 405, { error: "Method not allowed" });
  } catch (err) {
    console.error("[dmarc-tracker]", err);
    return send(res, 500, { error: err.message });
  }
}
