// DMARC Tracker tests
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DMARC_STAGES,
  checkDmarcAdvancement,
  getDmarcRecordForStage,
} from "../lib/dmarc-tracker.js";

const NOW = new Date("2026-03-15T12:00:00Z");

test("DMARC_STAGES defines three stages", () => {
  assert.strictEqual(Object.keys(DMARC_STAGES).length, 3);
  assert.deepStrictEqual(DMARC_STAGES[1], {
    name: "Monitor (p=none)",
    policy: "none",
    minWaitDays: 14,
  });
  assert.deepStrictEqual(DMARC_STAGES[2], {
    name: "Quarantine (p=quarantine)",
    policy: "quarantine",
    minWaitDays: 14,
  });
  assert.deepStrictEqual(DMARC_STAGES[3], {
    name: "Reject (p=reject)",
    policy: "reject",
    minWaitDays: null,
  });
});

test("checkDmarcAdvancement rejects advancement before minimum wait", async () => {
  const domain = "example.com";
  const currentStage = 1;
  const stageStartedAt = new Date("2026-03-10T12:00:00Z"); // 5 days ago
  
  const deps = {
    now: () => NOW,
    resolver: {
      resolveTxt: async (d) => {
        if (d === `_dmarc.${domain}`) return [["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]];
        if (d === domain) return [["v=spf1 include:_spf.google.com ~all"]];
        return [];
      },
    },
  };
  
  const result = await checkDmarcAdvancement(domain, currentStage, stageStartedAt, deps);
  
  assert.strictEqual(result.canAdvance, false);
  assert.ok(result.reason.includes("wait"));
  assert.ok(result.reason.includes("9 more days"));
  assert.strictEqual(result.daysRemaining, 9);
});

test("checkDmarcAdvancement allows advancement after wait with matching policy", async () => {
  const domain = "example.com";
  const currentStage = 1;
  const stageStartedAt = new Date("2026-02-25T12:00:00Z"); // 18 days ago
  
  const deps = {
    now: () => NOW,
    resolver: {
      resolveTxt: async (d) => {
        if (d === `_dmarc.${domain}`) return [["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]];
        if (d === domain) return [["v=spf1 include:_spf.google.com ~all"]];
        return [];
      },
    },
  };
  
  const result = await checkDmarcAdvancement(domain, currentStage, stageStartedAt, deps);
  
  assert.strictEqual(result.canAdvance, true);
  assert.ok(result.reason.includes("Ready"));
  assert.strictEqual(result.currentPolicy, "none");
  assert.strictEqual(result.nextPolicy, "quarantine");
  assert.strictEqual(result.nextStage, 2);
  assert.ok(result.nextRecord);
  assert.ok(result.nextRecord.includes("p=quarantine"));
});

test("checkDmarcAdvancement blocks advancement when policy doesn't match", async () => {
  const domain = "example.com";
  const currentStage = 1;
  const stageStartedAt = new Date("2026-02-25T12:00:00Z"); // 18 days ago
  
  const deps = {
    now: () => NOW,
    resolver: {
      resolveTxt: async (d) => {
        if (d === `_dmarc.${domain}`) return [["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"]];
        if (d === domain) return [["v=spf1 include:_spf.google.com ~all"]];
        return [];
      },
    },
  };
  
  const result = await checkDmarcAdvancement(domain, currentStage, stageStartedAt, deps);
  
  assert.strictEqual(result.canAdvance, false);
  assert.ok(result.reason.includes("expected none"));
  assert.strictEqual(result.currentPolicy, "quarantine");
  assert.strictEqual(result.expectedPolicy, "none");
});

test("checkDmarcAdvancement blocks advancement when SPF is failing", async () => {
  const domain = "example.com";
  const currentStage = 1;
  const stageStartedAt = new Date("2026-02-25T12:00:00Z"); // 18 days ago
  
  const deps = {
    now: () => NOW,
    resolver: {
      resolveTxt: async (d) => {
        if (d === `_dmarc.${domain}`) return [["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]];
        if (d === domain) return [["v=spf1 +all"]]; // Bad SPF
        return [];
      },
    },
  };
  
  const result = await checkDmarcAdvancement(domain, currentStage, stageStartedAt, deps);
  
  assert.strictEqual(result.canAdvance, false);
  assert.ok(result.reason.includes("SPF"));
  assert.strictEqual(result.spfStatus, "fail");
});

test("checkDmarcAdvancement rejects advancement at final stage", async () => {
  const domain = "example.com";
  const currentStage = 3;
  const stageStartedAt = new Date("2026-02-25T12:00:00Z");
  
  const deps = {
    now: () => NOW,
    resolver: {
      resolveTxt: async () => [],
    },
  };
  
  const result = await checkDmarcAdvancement(domain, currentStage, stageStartedAt, deps);
  
  assert.strictEqual(result.canAdvance, false);
  assert.ok(result.reason.includes("final stage"));
});

test("getDmarcRecordForStage generates correct records", () => {
  const reportAddress = "dmarc@example.com";
  
  const rec1 = getDmarcRecordForStage(1, reportAddress);
  assert.ok(rec1);
  assert.ok(rec1.includes("v=DMARC1"));
  assert.ok(rec1.includes("p=none"));
  assert.ok(rec1.includes("rua=mailto:dmarc@example.com"));
  
  const rec2 = getDmarcRecordForStage(2, reportAddress);
  assert.ok(rec2);
  assert.ok(rec2.includes("p=quarantine"));
  
  const rec3 = getDmarcRecordForStage(3, reportAddress);
  assert.ok(rec3);
  assert.ok(rec3.includes("p=reject"));
  
  const invalid = getDmarcRecordForStage(99, reportAddress);
  assert.strictEqual(invalid, null);
});

test("getDmarcRecordForStage preserves existing tags", () => {
  const reportAddress = "dmarc@example.com";
  const existingTags = {
    p: "none",
    rua: "mailto:client@example.com",
    ruf: "mailto:forensic@example.com",
    sp: "none",
    adkim: "r",
    aspf: "r",
  };
  
  const rec = getDmarcRecordForStage(2, reportAddress, existingTags);
  assert.ok(rec);
  assert.ok(rec.includes("p=quarantine"));
  assert.ok(rec.includes("rua=mailto:client@example.com,mailto:dmarc@example.com"));
  assert.ok(rec.includes("ruf=mailto:forensic@example.com"));
  assert.ok(rec.includes("sp=none"));
  assert.ok(rec.includes("adkim=r"));
  assert.ok(rec.includes("aspf=r"));
});
