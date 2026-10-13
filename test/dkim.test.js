// DKIM key checks: RFC 6376 §3.6.1 tags, RFC 8301 §3.2 key length, RFC 8463 Ed25519.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { analyzeDkimKey, checkDkim } from "../lib/checks/email.js";
import { buildPlan } from "../lib/plan.js";
import { runScan } from "../lib/scan.js";
import { fakeDeps } from "./fakes.js";

const rsa = (bits) => generateKeyPairSync("rsa", { modulusLength: bits }).publicKey.export({ type: "spki", format: "der" }).toString("base64");
// RFC 8463: an Ed25519 DKIM key is the raw 32-byte public key, not a SubjectPublicKeyInfo.
const ed25519 = () => generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("base64");
const K512 = rsa(512);
const K1024 = rsa(1024);
const K2048 = rsa(2048);
const google = { key: "google", name: "Google Workspace" };
const d = "acme.com";

test("RSA key length is read from the key itself and graded (RFC 8301)", () => {
  assert.deepEqual([analyzeDkimKey(`v=DKIM1; k=rsa; p=${K512}`).status, analyzeDkimKey(`v=DKIM1; k=rsa; p=${K512}`).bits], ["fail", 512]);
  const k1024 = analyzeDkimKey(`v=DKIM1; k=rsa; p=${K1024}`);
  assert.equal(k1024.status, "warn");
  assert.equal(k1024.bits, 1024);
  assert.match(k1024.issues[0].message, /2048-bit recommended; Google Workspace supports 2048/);
  assert.deepEqual([analyzeDkimKey(`v=DKIM1; k=rsa; p=${K2048}`).status, analyzeDkimKey(`p=${K2048}`).bits], ["pass", 2048], "k defaults to rsa");
});

test("Ed25519 keys are accepted", () => {
  const r = analyzeDkimKey(`v=DKIM1; k=ed25519; p=${ed25519()}`);
  assert.equal(r.status, "pass");
  assert.equal(r.keyType, "ed25519");
});

test("tag rules: v must be first and DKIM1, k must be rsa or ed25519, t=y warns, empty p is revoked", () => {
  assert.equal(analyzeDkimKey(`k=rsa; v=DKIM1; p=${K2048}`).status, "fail");
  assert.equal(analyzeDkimKey(`v=DKIM2; p=${K2048}`).status, "fail");
  assert.equal(analyzeDkimKey(`v=DKIM1; k=dsa; p=${K2048}`).status, "fail");
  const testing = analyzeDkimKey(`v=DKIM1; t=y; p=${K2048}`);
  assert.equal(testing.status, "warn");
  assert.equal(testing.testing, true);
  assert.equal(analyzeDkimKey(`v=DKIM1; t=s:y; p=${K2048}`).testing, true);
  assert.equal(analyzeDkimKey("v=DKIM1; p=").revoked, true);
  assert.equal(analyzeDkimKey("v=DKIM1; k=rsa; p=MIIBIjAN").status, "warn", "a cut-off key is reported");
});

test("checkDkim grades each selector it finds and reports key sizes", async () => {
  let r = await checkDkim(d, fakeDeps({ txt: { [`google._domainkey.${d}`]: [`v=DKIM1; k=rsa; p=${K2048}`] } }), google);
  assert.equal(r.status, "pass");
  assert.deepEqual(r.data.keys.map((k) => [k.selector, k.bits]), [["google", 2048]]);
  assert.match(r.detail, /google \(2048-bit RSA\)/);

  r = await checkDkim(d, fakeDeps({ txt: { [`google._domainkey.${d}`]: [`v=DKIM1; k=rsa; p=${K1024}`] } }), google);
  assert.equal(r.status, "warn");
  assert.equal(r.data.code, "key-warning");

  r = await checkDkim(d, fakeDeps({ txt: { [`google._domainkey.${d}`]: [`v=DKIM1; k=rsa; p=${K512}`] } }), google);
  assert.equal(r.status, "fail");

  r = await checkDkim(d, fakeDeps({ txt: { [`google._domainkey.${d}`]: [`v=DKIM1; t=y; k=rsa; p=${K2048}`] } }), google);
  assert.equal(r.status, "warn");

  r = await checkDkim(d, fakeDeps({ txt: { [`google._domainkey.${d}`]: ["v=DKIM1; p="] } }), google);
  assert.equal(r.status, "warn", "revoked key: no usable signing key");
  assert.equal(r.data.code, "missing");
});

test("a weak key becomes a rotation item that never overwrites the existing selector", async () => {
  const report = await runScan(d, fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ip4:74.125.0.0/16 ~all"], [`google._domainkey.${d}`]: [`v=DKIM1; k=rsa; p=${K1024}`] },
  }));
  const item = buildPlan(report).items.find((i) => i.id === "dkim");
  assert.match(item.title, /Strengthen/);
  assert.ok(item.records.every((r) => r.name !== "google._domainkey"));
  assert.match(item.found[0], /1024-bit RSA/);
});
