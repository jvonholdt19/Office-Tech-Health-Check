// SPF accuracy against RFC 7208: lookup counting (§4.6.4), void lookups, ptr (§5.5), syntax and merge-safe proposals.
import { test } from "node:test";
import assert from "node:assert/strict";
import { countSpfLookups, validateSpfSyntax, splitTxt } from "../lib/checks/spf.js";
import { checkSpf } from "../lib/checks/email.js";
import { recommendSpf, safetyCheckPlan } from "../lib/plan.js";
import { fakeDeps, fakeResolver } from "./fakes.js";

const other = { key: "other", name: "Other" };
const leaf = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`s${i}.example.net`, ["v=spf1 ip4:192.0.2.1 -all"]]));
const includes = (n) => Array.from({ length: n }, (_, i) => `include:s${i}.example.net`).join(" ");
// Makes "live DNS" look reachable for the safety check.
const GOOGLE = { "_spf.google.com": ["v=spf1 ip4:74.125.0.0/16 ~all"] };

test("a repeated include is counted every time it is evaluated", async () => {
  const resolver = fakeResolver({ txt: { "x.example": ["v=spf1 ip4:192.0.2.1 -all"] } });
  assert.equal((await countSpfLookups(resolver, "v=spf1 include:x.example include:x.example -all")).count, 2);
  const nested = fakeResolver({
    txt: { "a.example": ["v=spf1 include:c.example -all"], "b.example": ["v=spf1 include:c.example -all"], "c.example": ["v=spf1 a:host.c.example -all"] },
    a: { "host.c.example": ["192.0.2.9"] },
  });
  const r = await countSpfLookups(nested, "v=spf1 include:a.example include:b.example -all");
  assert.equal(r.count, 6, "a, b, c twice, a:host twice");
  assert.equal(r.complete, true);
  assert.equal(r.voids, 0);
});

test("redirect is ignored when the record has an all mechanism (§6.1), followed otherwise", async () => {
  const resolver = fakeResolver({ txt: { "r.example": ["v=spf1 include:x.example -all"], "x.example": ["v=spf1 ip4:192.0.2.1 -all"] } });
  const ignored = await countSpfLookups(resolver, "v=spf1 ip4:192.0.2.5 -all redirect=r.example");
  assert.equal(ignored.count, 0);
  assert.deepEqual(ignored.names, []);
  const followed = await countSpfLookups(resolver, "v=spf1 ip4:192.0.2.5 redirect=r.example");
  assert.equal(followed.count, 2);
});

test("exactly 10 lookups pass, 11 fail", async () => {
  const d = "acme.com";
  let r = await checkSpf(d, fakeDeps({ txt: { ...leaf(11), [d]: [`v=spf1 ${includes(10)} -all`] } }), other);
  assert.equal(r.status, "pass");
  assert.equal(r.data.lookups, 10);
  r = await checkSpf(d, fakeDeps({ txt: { ...leaf(11), [d]: [`v=spf1 ${includes(11)} -all`] } }), other);
  assert.equal(r.status, "fail");
  assert.ok(r.data.codes.includes("too-many-lookups"));
  assert.equal(r.data.lookups, null, "stopped counting, so not reported as exact");
  assert.match(r.summary, /more than 10/);
});

test("void lookups: 2 pass, 3 fail", async () => {
  const d = "acme.com";
  let r = await checkSpf(d, fakeDeps({ txt: { [d]: ["v=spf1 a:gone1.acme.com mx:gone2.acme.com ip4:192.0.2.1 -all"] } }), other);
  assert.equal(r.data.voids, 2);
  assert.equal(r.status, "pass");
  r = await checkSpf(d, fakeDeps({ txt: { [d]: ["v=spf1 a:gone1.acme.com mx:gone2.acme.com exists:gone3.acme.com -all"] } }), other);
  assert.equal(r.data.voids, 3);
  assert.equal(r.status, "fail");
  assert.ok(r.data.codes.includes("too-many-void-lookups"));
});

test("an include loop is a permanent error", async () => {
  const d = "acme.com";
  const txt = { [d]: ["v=spf1 include:x.example -all"], "x.example": ["v=spf1 include:y.example -all"], "y.example": ["v=spf1 include:x.example -all"] };
  const walk = await countSpfLookups(fakeResolver({ txt }), txt[d][0], { domain: d });
  assert.ok(walk.errors.some((e) => e.code === "loop" && e.severity === "permerror"));
  const r = await checkSpf(d, fakeDeps({ txt }), other);
  assert.equal(r.status, "fail");
  assert.ok(r.data.codes.includes("include-loop"));
});

test("an incomplete count is never reported as exact", async () => {
  const d = "acme.com";
  const deps = fakeDeps({ txt: { [d]: ["v=spf1 include:ok.example include:broken.example -all"], "ok.example": ["v=spf1 ip4:192.0.2.1 -all"] } });
  const realTxt = deps.resolver.resolveTxt;
  deps.resolver.resolveTxt = async (name) => {
    if (name === "broken.example") throw Object.assign(new Error("SERVFAIL"), { code: "ESERVFAIL" });
    return realTxt(name);
  };
  const walk = await countSpfLookups(deps.resolver, "v=spf1 include:ok.example include:broken.example -all");
  assert.equal(walk.complete, false);
  const r = await checkSpf(d, deps, other);
  assert.equal(r.data.lookups, null);
  assert.equal(r.data.lookupsAtLeast, 2);
  assert.match(r.detail, /at least 2 DNS lookups/);
});

test("an mx mechanism with more than 10 mail servers is a permanent error", async () => {
  const mx = Array.from({ length: 11 }, (_, i) => ({ exchange: `mx${i}.acme.com`, priority: i }));
  const walk = await countSpfLookups(fakeResolver({ mx: { "acme.com": mx } }), "v=spf1 mx -all", { domain: "acme.com" });
  assert.ok(walk.errors.some((e) => e.code === "mx-too-many"));
});

test("ptr is flagged and removed from the proposal with a reason", async () => {
  const d = "acme.com";
  const r = await checkSpf(d, fakeDeps({ txt: { [d]: ["v=spf1 ptr ip4:192.0.2.1 -all"] } }), other);
  assert.equal(r.status, "warn");
  assert.ok(r.data.codes.includes("ptr-deprecated"));
  assert.match(r.summary, /RFC 7208 §5\.5: ptr SHOULD NOT be used/);
  const rec = recommendSpf(["v=spf1 ptr ip4:192.0.2.1 -all"], "google");
  assert.equal(rec.value, "v=spf1 ip4:192.0.2.1 include:_spf.google.com -all");
  const removed = rec.changes.find((c) => c.op === "remove");
  assert.equal(removed.term, "ptr");
  assert.match(removed.reason, /RFC 7208 §5\.5/);
});

test("syntax: multiple all, terms after all, unknown mechanisms and repeated modifiers", () => {
  const codes = (r) => validateSpfSyntax(r).map((i) => i.code);
  assert.ok(codes("v=spf1 -all ~all").includes("multiple-all"));
  assert.ok(codes("v=spf1 -all include:x.example").includes("terms-after-all"));
  assert.ok(codes("v=spf1 inclde:x.example -all").includes("unknown-mechanism"));
  assert.ok(codes("v=spf1 redirect=a.example redirect=b.example").includes("duplicate-modifier"));
  assert.ok(codes("v=spf1 exp=a.example exp=b.example -all").includes("duplicate-modifier"));
  assert.deepEqual(codes("v=spf1 include:x.example ip4:192.0.2.0/24 a mx/24 -all exp=explain.example"), []);
});

test("merge keeps every term in order and puts the platform include before all", () => {
  const rec = recommendSpf(["v=spf1 include:a ip4:1.2.3.4 -all"], "google");
  assert.equal(rec.value, "v=spf1 include:a ip4:1.2.3.4 include:_spf.google.com -all");
  assert.deepEqual(rec.changes.filter((c) => c.op === "add").map((c) => c.term), ["include:_spf.google.com"]);
  assert.ok(rec.changes.filter((c) => c.op === "remove").length === 0, "nothing removed");
});

test("two records merge into exactly one, duplicates removed with a reason", () => {
  const rec = recommendSpf(["v=spf1 include:sendgrid.net ip4:1.2.3.4 -all", "v=spf1 include:sendgrid.net include:mailgun.org ~all"], "google");
  assert.equal(rec.value, "v=spf1 include:sendgrid.net ip4:1.2.3.4 include:mailgun.org include:_spf.google.com ~all");
  assert.equal(rec.value.match(/v=spf1/g).length, 1);
  const dup = rec.changes.find((c) => c.op === "remove");
  assert.equal(dup.term, "include:sendgrid.net");
  assert.match(dup.reason, /Duplicate/);
});

test("exp= is preserved and redirect is kept when it still works", () => {
  assert.equal(recommendSpf(["v=spf1 include:a.example -all exp=explain.acme.com"], "google").value, "v=spf1 include:a.example include:_spf.google.com -all exp=explain.acme.com");
  const r = recommendSpf(["v=spf1 redirect=_spf.acme.com"], "google");
  assert.equal(r.value, "v=spf1 include:_spf.google.com redirect=_spf.acme.com", "provider added in front of the redirect, no all");
  assert.equal(recommendSpf(["v=spf1 redirect=_spf.google.com"], "google").value, "v=spf1 redirect=_spf.google.com", "already covered");
  // Merged with a record that has "all": the redirect would be ignored, so it's converted, with a warning.
  const merged = recommendSpf(["v=spf1 redirect=_spf.acme.com", "v=spf1 include:x.example ~all"], "other");
  assert.equal(merged.value, "v=spf1 include:x.example include:_spf.acme.com ~all");
  assert.ok(merged.changes.some((c) => c.op === "convert" && /redirect=_spf\.acme\.com → include:_spf\.acme\.com/.test(c.term)));
  assert.ok(merged.warnings.length >= 1);
});

test("a long record is split into strings of at most 255 bytes", () => {
  const ips = Array.from({ length: 40 }, (_, i) => `ip4:198.51.100.${i}`).join(" ");
  const rec = recommendSpf([`v=spf1 ${ips} -all`], "google");
  assert.ok(rec.value.length > 450);
  assert.ok(rec.strings.length >= 3);
  for (const s of rec.strings) assert.ok(Buffer.byteLength(s) <= 255);
  assert.equal(rec.strings.join(""), rec.value);
  assert.ok(rec.warnings.some((w) => /450/.test(w)));
  assert.deepEqual(splitTxt("short"), ["short"]);
  assert.deepEqual(splitTxt("é".repeat(200)).map((s) => Buffer.byteLength(s)), [254, 146]);
});

test("no senders: still refuses to guess", () => {
  assert.equal(recommendSpf([], "other"), null);
});

test("safety check blocks over 10 lookups, over 2 voids, and marks an unverified count", async () => {
  const mk = (value) => ({ domain: "acme.com", items: [{ title: "SPF", steps: [], records: [{ type: "TXT", name: "@", action: "Replace", value }] }] });
  let p = await safetyCheckPlan(mk(`v=spf1 ${includes(11)} -all`), { resolver: fakeResolver({ txt: { ...GOOGLE, ...leaf(11) } }) });
  assert.equal(p.items[0].records[0].blocked, true);
  assert.match(p.items[0].records[0].note, /more than 10/);

  p = await safetyCheckPlan(mk("v=spf1 a:g1.acme.com a:g2.acme.com a:g3.acme.com -all"), { resolver: fakeResolver({ txt: GOOGLE }) });
  assert.equal(p.items[0].records[0].blocked, true);
  assert.equal(p.items[0].records[0].voids, 3);

  const flaky = fakeResolver({ txt: { ...GOOGLE } });
  flaky.resolve4 = async () => {
    throw Object.assign(new Error("timeout"), { code: "ETIMEOUT" });
  };
  p = await safetyCheckPlan(mk("v=spf1 a:host.acme.com -all"), { resolver: flaky });
  assert.equal(p.items[0].records[0].blocked, "unverified");
  assert.equal(p.items[0].records[0].lookups, null);
  assert.equal(p.items[0].records[0].lookupsAtLeast, 1);
});
