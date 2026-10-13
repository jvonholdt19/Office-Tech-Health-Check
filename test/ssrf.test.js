// SSRF hardening: website checks only ever connect to vetted public IPs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { inspectTls, probeHttp, isNonPublicAddress, resolvePublicAddress } from "../lib/net.js";
import { fakeResolver } from "./fakes.js";

const neverConnect = () => assert.fail("must not connect to a non-public address");

test("hosts that resolve to private, loopback or metadata addresses are refused before connecting", async () => {
  const cases = [
    { a: { "evil.example": ["127.0.0.1"] } },
    { a: { "evil.example": ["169.254.169.254"] } },
    { aaaa: { "evil.example": ["::ffff:10.0.0.1"] } },
    { aaaa: { "evil.example": ["::1"] } },
    { a: { "evil.example": ["93.184.216.34", "10.1.2.3"] } }, // one bad answer is enough
  ];
  for (const c of cases) {
    const resolver = fakeResolver(c);
    assert.deepEqual(await inspectTls("evil.example", { resolver, connect: neverConnect }), { ok: false, error: "non-public address" });
    assert.deepEqual(await probeHttp("evil.example", { resolver, request: neverConnect }), { ok: false, error: "non-public address" });
  }
});

test("every blocked range is recognised, public addresses are allowed", () => {
  for (const a of ["127.0.0.1", "10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "::", "fc00::1", "fd00::1", "fe80::1", "ff02::1", "::ffff:10.0.0.1", "::ffff:a00:1", "::ffff:127.0.0.1", "not-an-ip"]) {
    assert.equal(isNonPublicAddress(a), true, a);
  }
  for (const a of ["93.184.216.34", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111"]) assert.equal(isNonPublicAddress(a), false, a);
});

test("a vetted public IP is what gets connected to, with the host as SNI / Host header", async () => {
  const resolver = fakeResolver({ a: { "shop.example": ["93.184.216.34"] }, aaaa: { "shop.example": ["2606:2800:220:1::1"] } });
  assert.deepEqual(await resolvePublicAddress("shop.example", resolver), { ok: true, address: "93.184.216.34", family: 4 });

  let opts;
  const fakeReq = (o, cb) => {
    opts = o;
    const handlers = {};
    queueMicrotask(() => cb({ statusCode: 301, headers: { location: "https://shop.example/" }, resume() {} }));
    return { on: (e, f) => (handlers[e] = f), end() {}, destroy() {} };
  };
  const r = await probeHttp("shop.example", { resolver, request: fakeReq });
  assert.deepEqual(r, { ok: true, status: 301, location: "https://shop.example/" });
  assert.equal(opts.host, "93.184.216.34");
  assert.equal(opts.headers.Host, "shop.example");

  let tlsOpts;
  const fakeConnect = (o) => {
    tlsOpts = o;
    const handlers = {};
    return { on: (e, f) => ((handlers[e] = f), queueMicrotask(() => e === "error" && f(Object.assign(new Error("x"), { code: "ECONNREFUSED" })))), destroy() {} };
  };
  assert.deepEqual(await inspectTls("shop.example", { resolver, connect: fakeConnect }), { ok: false, error: "ECONNREFUSED" });
  assert.equal(tlsOpts.host, "93.184.216.34");
  assert.equal(tlsOpts.servername, "shop.example");
});

test("a host with no addresses isn't connected to", async () => {
  assert.deepEqual(await probeHttp("nothing.example", { resolver: fakeResolver(), request: neverConnect }), { ok: false, error: "ENOTFOUND" });
});
