// DMARC Tracker: staged rollout monitoring for client domains.
// Feature 2: Track domains through p=none → p=quarantine → p=reject stages.

import { withTimeout } from "./net.js";
import { checkDmarc, checkSpf } from "./checks/email.js";
import { recommendDmarc } from "./plan.js";

// Stage definitions
export const DMARC_STAGES = {
  1: { name: "Monitor (p=none)", policy: "none", minWaitDays: 14 },
  2: { name: "Quarantine (p=quarantine)", policy: "quarantine", minWaitDays: 14 },
  3: { name: "Reject (p=reject)", policy: "reject", minWaitDays: null },
};

/**
 * Check if a domain is ready to advance to the next DMARC stage.
 * Returns { canAdvance: boolean, reason: string, nextPolicy: string, nextRecord: string }
 */
export async function checkDmarcAdvancement(domain, currentStage, stageStartedAt, deps) {
  const stage = DMARC_STAGES[currentStage];
  if (!stage) return { canAdvance: false, reason: "Invalid stage" };
  if (currentStage === 3) return { canAdvance: false, reason: "Already at final stage (p=reject)" };

  const nextStage = DMARC_STAGES[currentStage + 1];
  const now = deps.now ? deps.now() : new Date();
  const stageStart = new Date(stageStartedAt);
  const daysInStage = Math.floor((now - stageStart) / (1000 * 60 * 60 * 24));
  
  // Check minimum wait time
  if (stage.minWaitDays && daysInStage < stage.minWaitDays) {
    return {
      canAdvance: false,
      reason: `Need to wait ${stage.minWaitDays - daysInStage} more days in ${stage.name} (minimum ${stage.minWaitDays} days)`,
      daysRemaining: stage.minWaitDays - daysInStage,
    };
  }

  // Check current DNS records
  let dmarcCheck, spfCheck;
  try {
    [dmarcCheck, spfCheck] = await Promise.all([
      checkDmarc(domain, deps),
      checkSpf(domain, deps, { key: "unknown" }),
    ]);
  } catch (err) {
    return {
      canAdvance: false,
      reason: `DNS check failed: ${err.message}`,
      error: err.message,
    };
  }

  // Verify DMARC record matches expected policy for current stage
  const expectedPolicy = stage.policy;
  const currentPolicy = dmarcCheck.data?.tags?.p?.toLowerCase();
  
  if (currentPolicy !== expectedPolicy) {
    return {
      canAdvance: false,
      reason: `DMARC policy is ${currentPolicy || "missing"}, expected ${expectedPolicy}. Publish the correct record for ${stage.name} before advancing.`,
      currentPolicy,
      expectedPolicy,
    };
  }

  // Check for SPF failures (if SPF is failing, don't advance)
  if (spfCheck.status === "fail") {
    return {
      canAdvance: false,
      reason: "SPF check is failing. Fix SPF before advancing DMARC to enforcement.",
      spfStatus: spfCheck.status,
      spfIssue: spfCheck.summary,
    };
  }

  // All checks passed
  const reportAddress = dmarcCheck.data?.tags?.rua || null;
  const nextRecord = recommendDmarc(nextStage.policy, reportAddress, dmarcCheck.data?.tags);
  
  return {
    canAdvance: true,
    reason: `Ready to advance to ${nextStage.name}`,
    daysInStage,
    currentPolicy,
    nextPolicy: nextStage.policy,
    nextRecord: nextRecord.value,
    nextStage: currentStage + 1,
  };
}

/**
 * Get the DMARC record value for a specific stage.
 */
export function getDmarcRecordForStage(stage, reportAddress, existingTags = null) {
  const stageInfo = DMARC_STAGES[stage];
  if (!stageInfo) return null;
  
  const rec = recommendDmarc(stageInfo.policy, reportAddress, existingTags);
  return rec ? rec.value : null;
}

/**
 * List all tracked domains with their current status.
 */
export async function listTrackedDomains(store) {
  if (!store) throw new Error("Store not available");
  
  // Direct SQL query to list all tracked domains
  const query = `
    SELECT 
      id, domain, stage, stage_started_at, last_check_at, 
      last_check_result, can_advance, advance_note, 
      created_at, updated_at, notes
    FROM public.dmarc_tracker
    ORDER BY 
      can_advance DESC, 
      stage ASC, 
      updated_at DESC
  `;
  
  // For Supabase store, we need to query via the REST API
  const url = `${store.url}/rest/v1/dmarc_tracker?select=*&order=can_advance.desc,stage.asc,updated_at.desc`;
  const headers = {
    apikey: store.key,
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (/^eyJ/.test(store.key)) {
    headers.Authorization = `Bearer ${store.key}`;
  }
  
  const res = await withTimeout(
    fetch(url, { method: "GET", headers }),
    5000,
    "List tracked domains"
  );
  
  if (!res.ok) {
    throw new Error(`Failed to list tracked domains: HTTP ${res.status}`);
  }
  
  const rows = await res.json();
  return rows;
}

/**
 * Add a domain to tracking.
 */
export async function addTrackedDomain(store, domain, createdBy, notes = null) {
  if (!store) throw new Error("Store not available");
  
  // Use the Supabase RPC function
  const result = await store.rpc("dmarc_tracker_add", {
    p_domain: domain.toLowerCase(),
    p_created_by: createdBy,
    p_notes: notes,
  });
  
  return result;
}

/**
 * Update check result for a tracked domain.
 */
export async function updateTrackedDomainCheck(store, id, result, canAdvance, advanceNote) {
  if (!store) throw new Error("Store not available");
  
  await store.rpc("dmarc_tracker_update_check", {
    p_id: id,
    p_result: result,
    p_can_advance: canAdvance,
    p_advance_note: advanceNote,
  });
}

/**
 * Advance a tracked domain to the next stage.
 */
export async function advanceTrackedDomain(store, id, skipToStage = null, confirmedBy = null, note = null) {
  if (!store) throw new Error("Store not available");
  
  await store.rpc("dmarc_tracker_advance", {
    p_id: id,
    p_skip_to_stage: skipToStage,
    p_confirmed_by: confirmedBy,
    p_note: note,
  });
}

/**
 * Remove a domain from tracking.
 */
export async function removeTrackedDomain(store, id) {
  if (!store) throw new Error("Store not available");
  
  await store.rpc("dmarc_tracker_remove", {
    p_id: id,
  });
}

/**
 * Recheck all tracked domains and update their advancement eligibility.
 * This is the function that would be called by a cron job.
 */
export async function recheckAllTrackedDomains(store, deps) {
  if (!store) throw new Error("Store not available");
  
  // For Supabase, we need to directly modify the store interface to support listing
  // For now, we'll use a workaround by extending the store
  const domains = await listTrackedDomains({ url: process.env.SUPABASE_URL, key: process.env.SUPABASE_SERVICE_ROLE_KEY });
  
  const results = [];
  for (const tracker of domains) {
    try {
      const check = await checkDmarcAdvancement(
        tracker.domain,
        tracker.stage,
        tracker.stage_started_at,
        deps
      );
      
      await updateTrackedDomainCheck(
        store,
        tracker.id,
        {
          checkedAt: new Date().toISOString(),
          dmarcPolicy: check.currentPolicy,
          daysInStage: check.daysInStage,
        },
        check.canAdvance,
        check.reason
      );
      
      results.push({
        domain: tracker.domain,
        success: true,
        canAdvance: check.canAdvance,
        reason: check.reason,
      });
    } catch (err) {
      results.push({
        domain: tracker.domain,
        success: false,
        error: err.message,
      });
    }
  }
  
  return results;
}

/**
 * Helper: get store interface from env vars (for use in API endpoints).
 */
export function getTrackerStore() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  
  if (!url || !key) return null;
  
  // Return a store-like object that can call RPCs
  return {
    url,
    key,
    async rpc(fn, body) {
      const headers = {
        apikey: key,
        "Content-Type": "application/json",
        Accept: "application/json",
      };
      if (/^eyJ/.test(key)) {
        headers.Authorization = `Bearer ${key}`;
      }
      
      const res = await withTimeout(
        fetch(`${url}/rest/v1/rpc/${fn}`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        }),
        5000,
        `DMARC tracker ${fn}`
      );
      
      if (!res.ok) {
        throw new Error(`DMARC tracker ${fn} HTTP ${res.status}`);
      }
      
      const text = await res.text();
      return text ? JSON.parse(text) : null;
    },
  };
}
