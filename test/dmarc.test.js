// DMARC accuracy against RFC 7489: record validity (§6.3–6.4), tag checks, external report authorization (§7.1).
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkDmarc, validateDmarc, parseReportUris } from "../lib/checks/email.js";
import { recommendDmarc, safetyCheckPlan } from "../lib/plan.js";
import { fakeDeps, fakeResolver } from "./fakes.js";

const d = "acme.com";
const dmarc = (value, extra = {}) => checkDmarc(d, fakeDeps({ txt: { [`_dmarc.${d}`]: [value], ...extra } }));

test("v=DMARC10 is rejected; the version must be exactly DMARC1 and first", async () => {
  const r = await dmarc("v=DMARC10; p=reject; rua=mailto:x@acme.com");
  assert.equal(r.status, "fail");
  assert.ok(r.data.codes.includes("bad-version"));
  assert.ok(validateDmarc("v=DMARC1;p=reject").errors.length === 0);
  assert.ok(validateDmarc("v=DMARC1").errors.some((e) => e.code === "missing-policy"));
  assert.ok(validateDmarc("p=reject; v=DMARC1").errors.some((e) => e.code === "bad-version"));
});

test("p missing or invalid fails", async () => {
  let r = await dmarc("v=DMARC1; rua=mailto:x@acme.com");
  assert.equal(r.status, "fail");
  assert.ok(r.data.codes.includes("missing-policy"));
  r = await dmarc("v=DMARC1; p=block; rua=mailto:x@acme.com");
  assert.equal(r.status, "fail");
  assert.ok(r.data.codes.includes("invalid-policy"));
});

test("pct that isn't 0–100 warns and is treated as 100", async () => {
  for (const pct of ["abc", "150"]) {
    const r = await dmarc(`v=DMARC1; p=reject; pct=${pct}; rua=mailto:x@acme.com`);
    assert.equal(r.status, "warn", pct);
    assert.equal(r.data.pct, 100);
    assert.ok(r.data.codes.includes("invalid-pct"));
  }
  assert.equal((await dmarc("v=DMARC1; p=reject; pct=100; rua=mailto:x@acme.com")).status, "pass");
});

test("sp, adkim and aspf are validated", () => {
  const codes = validateDmarc("v=DMARC1; p=none; sp=maybe; adkim=x; aspf=s").warnings.map((w) => w.code);
  assert.deepEqual(codes.sort(), ["invalid-adkim", "invalid-sp"]);
});

test("a non-mailto rua warns; the !size suffix is accepted", async () => {
  const r = await dmarc("v=DMARC1; p=reject; rua=https://reports.example/acme");
  assert.equal(r.status, "warn");
  assert.ok(r.data.codes.includes("invalid-rua"));
  const uris = parseReportUris("mailto:a@acme.com!10m, mailto:b@acme.com");
  assert.deepEqual(uris.map((u) => [u.valid, u.address, u.size]), [[true, "a@acme.com", "!10m"], [true, "b@acme.com", null]]);
});

test("external rua needs <domain>._report._dmarc.<dest> (RFC 7489 §7.1)", async () => {
  let r = await dmarc("v=DMARC1; p=reject; rua=mailto:reports@vendor.example");
  assert.equal(r.status, "warn");
  assert.ok(r.data.codes.includes("external-rua-unauthorized"));
  assert.deepEqual(r.data.reportAuthorization, [{ tag: "rua", address: "reports@vendor.example", domain: "vendor.example", authorized: false }]);

  r = await dmarc("v=DMARC1; p=reject; rua=mailto:reports@vendor.example", { "acme.com._report._dmarc.vendor.example": ["v=DMARC1"] });
  assert.equal(r.status, "pass");
  assert.equal(r.data.reportAuthorization[0].authorized, true);

  r = await dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@mail.acme.com");
  assert.equal(r.status, "pass", "same organizational domain needs no authorization");
});

test("the plan checks our own report address is authorized before recommending it", async () => {
  const plan = {
    domain: d,
    business: { dmarcReportAddress: "dmarc@nwimpm.com" },
    items: [{ id: "dmarc", title: "DMARC", steps: [], records: [] }],
  };
  const reachable = { "_spf.google.com": ["v=spf1 ip4:74.125.0.0/16 ~all"] };
  let p = await safetyCheckPlan(structuredClone(plan), { resolver: fakeResolver({ txt: reachable }) });
  assert.equal(p.reportAuthorization.authorized, false);
  assert.match(p.items[0].steps[0], /acme\.com\._report\._dmarc\.nwimpm\.com/);
  p = await safetyCheckPlan(structuredClone(plan), { resolver: fakeResolver({ txt: { ...reachable, "acme.com._report._dmarc.nwimpm.com": ["v=DMARC1"] } }) });
  assert.equal(p.reportAuthorization.authorized, true);
});

test("the merge keeps every client tag, changes only p, and drops pct only when enforcing", () => {
  const tags = validateDmarc("v=DMARC1; p=none; pct=50; sp=quarantine; rua=mailto:a@acme.com!10m; ruf=mailto:f@acme.com; adkim=s; aspf=r; ri=3600; rf=afrf; fo=d; np=reject").tags;
  const monitor = recommendDmarc("none", "dmarc@nwimpm.com", tags);
  assert.equal(monitor.value, "v=DMARC1; p=none; pct=50; sp=quarantine; rua=mailto:a@acme.com!10m,mailto:dmarc@nwimpm.com; ruf=mailto:f@acme.com; adkim=s; aspf=r; ri=3600; rf=afrf; fo=d; np=reject");
  const enforce = recommendDmarc("quarantine", "dmarc@nwimpm.com", tags);
  assert.equal(enforce.value, "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:a@acme.com!10m,mailto:dmarc@nwimpm.com; ruf=mailto:f@acme.com; adkim=s; aspf=r; ri=3600; rf=afrf; fo=d; np=reject");
  const removed = enforce.changes.filter((c) => c.op === "remove");
  assert.deepEqual(removed.map((c) => c.term), ["pct=50"]);
  assert.ok(removed[0].reason);
  assert.ok(enforce.changes.some((c) => c.op === "convert" && c.term === "p=none → p=quarantine"));
  // Our address isn't added twice.
  assert.equal(recommendDmarc("none", "dmarc@nwimpm.com", { v: "DMARC1", p: "none", rua: "mailto:dmarc@nwimpm.com" }).value, "v=DMARC1; p=none; rua=mailto:dmarc@nwimpm.com; fo=1");
});
