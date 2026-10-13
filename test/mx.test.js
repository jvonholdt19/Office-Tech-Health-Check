// MX / Google Workspace detection (https://support.google.com/a/answer/174125).
import { test } from "node:test";
import assert from "node:assert/strict";
import { identifyProvider, checkEmailPlatform, googleMxSetup } from "../lib/checks/email.js";
import { buildPlan } from "../lib/plan.js";
import { runScan } from "../lib/scan.js";
import { fakeDeps } from "./fakes.js";

const d = "acme.com";
const LEGACY = [
  { exchange: "aspmx.l.google.com", priority: 1 },
  { exchange: "alt1.aspmx.l.google.com", priority: 5 },
  { exchange: "alt2.aspmx.l.google.com", priority: 5 },
  { exchange: "alt3.aspmx.l.google.com", priority: 10 },
  { exchange: "alt4.aspmx.l.google.com", priority: 10 },
];

test("smtp.google.com at priority 1 is Google Workspace and ok", async () => {
  const r = await checkEmailPlatform(d, fakeDeps({ mx: { [d]: [{ exchange: "smtp.google.com.", priority: 1 }] } }));
  assert.equal(r.provider.key, "google");
  assert.equal(r.status, "info");
  assert.equal(r.data.code, "ok");
  assert.equal(r.data.googleSetup, "single");
});

test("the legacy ASPMX set is ok, noted as legacy and still supported", async () => {
  const r = await checkEmailPlatform(d, fakeDeps({ mx: { [d]: [...LEGACY, { exchange: "aspmx2.googlemail.com", priority: 10 }] } }));
  assert.equal(r.status, "info");
  assert.equal(r.data.code, "ok");
  assert.equal(r.data.googleSetup, "legacy");
  assert.equal(r.data.note, "legacy set, still supported");
});

test("Google mixed with other mail servers warns, and the plan never deletes an MX", async () => {
  const mx = [{ exchange: "smtp.google.com", priority: 1 }, { exchange: "mail.oldhost.example", priority: 10 }];
  const r = await checkEmailPlatform(d, fakeDeps({ mx: { [d]: mx } }));
  assert.equal(r.status, "warn");
  assert.equal(r.data.code, "mixed-mx");
  const plan = buildPlan(await runScan(d, fakeDeps({ mx: { [d]: mx } })));
  assert.ok(plan.verifyItems.some((v) => /mixed/.test(v.title) && v.steps.some((s) => /mail\.oldhost\.example/.test(s))));
  for (const it of plan.items) for (const rec of it.records) assert.notEqual(rec.type, "MX");
});

test("lookalike hosts are not Google", () => {
  for (const host of ["evilgoogle.com.attacker.net", "smtp.google.com.attacker.net", "aspmx.l.google.com.evil.example", "alt9.aspmx.l.google.com", "mx.google.com", "aspmx6.googlemail.com"]) {
    assert.notEqual(identifyProvider([{ exchange: host, priority: 1 }]).key, "google", host);
  }
  assert.equal(googleMxSetup([{ exchange: "mail.acme.com", priority: 1 }]), null);
});
