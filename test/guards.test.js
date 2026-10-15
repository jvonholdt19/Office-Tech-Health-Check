// Server-side change-set guards and the safe upload preview (no writes anywhere).
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import fs, { readFileSync } from "node:fs";
import net from "node:net";
import http from "node:http";
import tls from "node:tls";
import { syncBuiltinESMExports } from "node:module";
import { buildChangeSet, changeSetHash, recordsTouched } from "../lib/changeset.js";
import { checkChangeSet } from "../lib/guards.js";
import { parseZone } from "../lib/zone.js";
import { buildFullPlan } from "../api/plan.js";
import { confirmChangeSet } from "../api/plan-confirm.js";
import { fakeDeps, DKIM_RECORD } from "./fakes.js";

const d = "example.com";
const fixture = (f) => readFileSync(new URL(`./fixtures/${f}`, import.meta.url), "utf8");
const entry = (type, name, before, after, extra = {}) => ({ type, name, fqdn: name === "@" ? d : `${name}.${d}`, action: "replace", before, after, changes: [], blocked: false, ...extra });
const guard = (cs, opts = {}) => checkChangeSet(cs, { domain: d, ...opts });

test("deleting an MX, NS or A record is blocked", () => {
  for (const [type, value] of [["MX", "1 smtp.google.com"], ["NS", "ns1.example.net"], ["A", "192.0.2.1"], ["CNAME", "host.example.net"]]) {
    const cs = [entry(type, "@", [value], [], { action: "delete" })];
    const g = guard(cs);
    assert.equal(g.blocked, true, type);
    assert.equal(cs[0].blocked, true);
    assert.match(cs[0].blockedReason, new RegExp(`never removes ${type}`));
  }
});

test("removing a DKIM selector is blocked", () => {
  const g = guard([entry("TXT", "google._domainkey", [DKIM_RECORD], [], { action: "delete" })]);
  assert.equal(g.blocked, true);
  assert.equal(g.violations[0].code, "removes-dkim");
});

test("removing a non-SPF/DMARC TXT (e.g. site verification) is blocked; replacing SPF is not", () => {
  assert.equal(guard([entry("TXT", "@", ["google-site-verification=abc", "v=spf1 ~all"], ["v=spf1 include:_spf.google.com ~all"])]).blocked, true);
  assert.equal(guard([entry("TXT", "@", ["google-site-verification=abc", "v=spf1 include:a.example ~all"], ["google-site-verification=abc", "v=spf1 include:a.example include:_spf.google.com ~all"])]).blocked, false);
});

test("a second SPF or DMARC record is blocked", () => {
  assert.equal(guard([entry("TXT", "@", ["v=spf1 include:a.example ~all"], ["v=spf1 include:a.example ~all", "v=spf1 include:b.example ~all"], { action: "add" })]).violations[0].code, "multiple-spf");
  assert.equal(guard([entry("TXT", "_dmarc", ["v=DMARC1; p=none"], ["v=DMARC1; p=none", "v=DMARC1; p=reject"], { action: "add" })]).violations[0].code, "multiple-dmarc");
});

test("SPF may only lose a mechanism the plan lists with a reason", () => {
  const before = ["v=spf1 ptr include:a.example ~all"];
  const after = ["v=spf1 include:_spf.google.com ~all"];
  let g = guard([entry("TXT", "@", before, after)]);
  assert.equal(g.violations[0].code, "spf-drops-mechanism");
  assert.match(g.reasons[0], /include:a\.example/);
  g = guard([entry("TXT", "@", before, ["v=spf1 include:a.example include:_spf.google.com ~all"], { changes: [{ op: "remove", term: "ptr", reason: "RFC 7208 §5.5" }] })]);
  assert.equal(g.blocked, false);
});

test("a change set touching more than 5 records is too broad", () => {
  const cs = Array.from({ length: 6 }, (_, i) => entry("TXT", `_x${i}`, [], [`v=x${i}`], { action: "add" }));
  const g = guard(cs);
  assert.equal(recordsTouched(cs), 6);
  assert.equal(g.blocked, "too-broad");
  assert.equal(guard(cs.slice(0, 5)).blocked, false);
});

test("an upload that differs from live DNS is blocked until the export is confirmed", () => {
  const differences = [{ label: "SPF", match: false }];
  assert.equal(guard([], { differences }).blocked, "upload-mismatch");
  assert.equal(guard([], { differences, exportConfirmed: true }).blocked, false);
});

test("partial export warning", () => {
  const g = guard([], { partial: { uploadTypes: ["TXT"], liveTypes: ["A", "MX", "TXT", "NS", "SOA"] } });
  assert.equal(g.blocked, false);
  assert.match(g.warnings[0], /export looks partial \(no SOA or NS/);
  assert.deepEqual(guard([], { partial: { uploadTypes: ["A", "MX", "TXT", "NS", "SOA"], liveTypes: ["A", "MX", "TXT", "NS", "SOA"] } }).warnings, []);
});

test("the change set lists every existing record at each changed name, before and after", () => {
  const base = [
    { name: d, type: "TXT", value: "google-site-verification=abc" },
    { name: d, type: "TXT", value: "v=spf1 include:sendgrid.net ~all" },
    { name: d, type: "MX", priority: 1, value: "smtp.google.com" },
  ];
  const plan = { items: [{ title: "SPF", records: [{ type: "TXT", name: "@", action: "Replace", current: "v=spf1 include:sendgrid.net ~all", value: "v=spf1 include:sendgrid.net include:_spf.google.com ~all", changes: [] }] }] };
  const cs = buildChangeSet(base, plan, d);
  assert.deepEqual(cs.map((e) => [e.type, e.name, e.action]), [["TXT", "@", "replace"]]);
  assert.deepEqual(cs[0].before, ["google-site-verification=abc", "v=spf1 include:sendgrid.net ~all"]);
  assert.deepEqual(cs[0].after, ["google-site-verification=abc", "v=spf1 include:sendgrid.net include:_spf.google.com ~all"]);
  assert.equal(changeSetHash(cs), changeSetHash(buildChangeSet(base, plan, d)), "stable hash");
});

test("parseZone is pure: no file writes and no network", () => {
  const src = readFileSync(new URL("../lib/zone.js", import.meta.url), "utf8");
  const imports = [...src.matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]);
  assert.deepEqual(imports, ["./checks/email.js"], "zone.js imports nothing that can write or connect");

  const spies = [
    ...["writeFileSync", "writeFile", "appendFileSync", "appendFile", "createWriteStream", "mkdirSync", "openSync"].map((m) => mock.method(fs, m, () => assert.fail(`fs.${m} called`))),
    ...["writeFile", "appendFile", "mkdir", "open"].map((m) => mock.method(fs.promises, m, async () => assert.fail(`fs.promises.${m} called`))),
    mock.method(net, "connect", () => assert.fail("net.connect called")),
    mock.method(net, "createConnection", () => assert.fail("net.createConnection called")),
    mock.method(tls, "connect", () => assert.fail("tls.connect called")),
    mock.method(http, "request", () => assert.fail("http.request called")),
    mock.method(globalThis, "fetch", async () => assert.fail("fetch called")),
  ];
  syncBuiltinESMExports();
  try {
    for (const [f, dom] of [["godaddy.txt", "old.example.net"], ["cloudflare.txt", "example.com"], ["hosts.csv", "csv.example.com"], ["route53.json", "r53.example.com"]]) {
      const text = fixture(f);
      const z = parseZone(text, dom);
      assert.ok(z.records.length > 0);
    }
  } finally {
    for (const s of spies) s.mock.restore();
    syncBuiltinESMExports();
  }
});

test("building a plan from an upload never writes the upload anywhere", async () => {
  const spies = ["writeFileSync", "writeFile", "appendFileSync", "appendFile", "createWriteStream"].map((m) => mock.method(fs, m, () => assert.fail(`fs.${m} called`)));
  const pspies = ["writeFile", "appendFile"].map((m) => mock.method(fs.promises, m, async () => assert.fail(`fs.promises.${m} called`)));
  syncBuiltinESMExports();
  try {
    const r = await buildFullPlan("old.example.net", { text: fixture("godaddy.txt") }, fakeDeps({ txt: { "_spf.google.com": ["v=spf1 ~all"], "secureserver.net": ["v=spf1 ip4:68.178.213.0/24 ~all"], "servers.mcsv.net": ["v=spf1 ip4:205.201.128.0/20 ~all"] } }));
    assert.match(r.zone.sha256, /^[0-9a-f]{64}$/);
    assert.equal(r.zone.text, undefined, "the response doesn't echo the upload");
  } finally {
    for (const s of [...spies, ...pspies]) s.mock.restore();
    syncBuiltinESMExports();
  }
});

test("upload mismatch: blocked on the first request, unlocked by a confirmation that matches the upload", async () => {
  const INC = { "_spf.google.com": ["v=spf1 ~all"], "secureserver.net": ["v=spf1 ip4:68.178.213.0/24 ~all"], "servers.mcsv.net": ["v=spf1 ip4:205.201.128.0/20 ~all"] };
  const zone = { text: fixture("godaddy.txt") };
  const first = await buildFullPlan("old.example.net", zone, fakeDeps({ txt: INC }));
  assert.equal(first.guards.blocked, "upload-mismatch");
  const wrong = await buildFullPlan("old.example.net", zone, fakeDeps({ txt: INC }), { confirmExport: { sha256: "0".repeat(64) } });
  assert.equal(wrong.guards.blocked, "upload-mismatch", "a confirmation for a different file doesn't count");
  const second = await buildFullPlan("old.example.net", zone, fakeDeps({ txt: INC }), { confirmExport: { sha256: first.zone.sha256 } });
  assert.equal(second.guards.blocked, false);
});

test("confirm: the server recomputes the hash, requires the typed domain, and returns copy-ready values", async () => {
  const deps = fakeDeps({
    mx: { [d]: [{ exchange: "smtp.google.com", priority: 1 }] },
    txt: { [d]: ["v=spf1 include:sendgrid.net ~all"], "sendgrid.net": ["v=spf1 ip4:167.89.0.0/17 ~all"], "_spf.google.com": ["v=spf1 ip4:74.125.0.0/16 ~all"], [`google._domainkey.${d}`]: [DKIM_RECORD] },
  });
  const built = await buildFullPlan(d, null, deps);
  assert.equal(built.guards.blocked, false, built.guards.reasons.join(" "));
  assert.equal((await confirmChangeSet({ domain: d, typedDomain: "example.net", changeSetHash: built.changeSetHash }, deps)).status, 400);
  assert.equal((await confirmChangeSet({ domain: d, typedDomain: d, changeSetHash: "f".repeat(64) }, deps)).status, 409, "stale or forged hash");
  const ok = await confirmChangeSet({ domain: d, typedDomain: "EXAMPLE.com", changeSetHash: built.changeSetHash }, deps);
  assert.equal(ok.status, 200);
  assert.ok(ok.body.values.some((v) => v.value === "v=spf1 include:sendgrid.net include:_spf.google.com ~all"));
  assert.equal(ok.audit.changeSetHash, built.changeSetHash);
  assert.ok(ok.audit.recordsTouched >= 1);
});
