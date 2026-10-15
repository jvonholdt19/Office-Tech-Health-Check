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

/* ------------------------------------------------------------------ */
/* Website Security Check: fetchPage / fetchChain redirect policy      */
/* ------------------------------------------------------------------ */

import { Readable } from "node:stream";
import { gzipSync } from "node:zlib";
import { fetchPage, fetchChain, urlRefusal } from "../lib/net.js";

/** Fake http(s).request: answers from `routes` keyed by "https://host/path", records every connection. */
function fakeSite(routes, log = []) {
  return (opts, cb) => {
    const key = `${opts.protocol}//${opts.headers.Host}${opts.path}`;
    log.push({ key, ip: opts.host, servername: opts.servername, headers: opts.headers });
    const route = routes[key] || { status: 404, headers: {}, body: "not found" };
    const handlers = {};
    queueMicrotask(() => {
      const res = Readable.from([Buffer.isBuffer(route.body) ? route.body : Buffer.from(route.body || "")]);
      Object.assign(res, { statusCode: route.status, headers: route.headers || {}, socket: { authorized: true } });
      cb(res);
    });
    return { on: (e, f) => (handlers[e] = f), end() {}, destroy() {} };
  };
}
const shopDns = { a: { "shop.example": ["93.184.216.34"], "www.shop.example": ["93.184.216.34"] } };

test("fetchPage connects to the vetted IP with SNI + Host, sends the UA, and caps the body", async () => {
  const log = [];
  const big = "x".repeat(5000);
  const request = fakeSite({ "https://shop.example/": { status: 200, headers: { "content-type": "text/html" }, body: big } }, log);
  const r = await fetchPage("https://shop.example/", { resolver: fakeResolver(shopDns), request, maxBytes: 1000 });
  assert.equal(r.ok, true);
  assert.equal(r.body.length, 1000);
  assert.equal(r.truncated, true);
  assert.equal(log[0].ip, "93.184.216.34");
  assert.equal(log[0].servername, "shop.example");
  assert.equal(log[0].headers.Host, "shop.example");
  assert.match(log[0].headers["User-Agent"], /^OfficeTechHealthCheck\/0\.3 \(\+https:\/\/officetech\.nwimpm\.com\)$/);
});

test("fetchPage decompresses gzip bodies", async () => {
  const request = fakeSite({ "https://shop.example/": { status: 200, headers: { "content-encoding": "gzip" }, body: gzipSync("<html>hello</html>") } });
  const r = await fetchPage("https://shop.example/", { resolver: fakeResolver(shopDns), request });
  assert.equal(r.body, "<html>hello</html>");
});

test("fetchPage refuses bad URLs before any DNS lookup or connection", async () => {
  const noDns = { resolve4: () => assert.fail("no DNS lookup"), resolve6: () => assert.fail("no DNS lookup") };
  for (const u of ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "file:///etc/passwd", "https://shop.example:8080/", "https://user:pw@shop.example/", "gopher://shop.example/"]) {
    const r = await fetchPage(u, { resolver: noDns, request: neverConnect });
    assert.equal(r.ok, false, u);
    assert.equal(r.refused, true, u);
  }
});

test("urlRefusal: scope is the exact host and its www. variant only", () => {
  assert.equal(urlRefusal("https://www.shop.example/a", "shop.example"), null);
  assert.equal(urlRefusal("https://shop.example/", "shop.example"), null);
  assert.equal(urlRefusal("https://shop.example/", "www.shop.example"), null, "www → bare is allowed too");
  assert.match(urlRefusal("https://blog.shop.example/", "shop.example"), /off-site redirect to blog\.shop\.example/);
  assert.match(urlRefusal("https://www.www.shop.example/", "shop.example"), /off-site/);
  assert.match(urlRefusal("https://evilshop.example/", "shop.example"), /off-site/);
  assert.match(urlRefusal("https://shop.example.evil.test/", "shop.example"), /off-site/);
  assert.equal(urlRefusal("http://shop.example:80/", "shop.example"), null); // URL drops a default port
  assert.match(urlRefusal("https://shop.example:80/", "shop.example"), /port 80/);
});

test("redirects to another subdomain or another site stop as an off-site redirect, without connecting", async () => {
  for (const location of ["https://blog.shop.example/", "https://shop.example.evil.test/", "https://other.example/landing"]) {
    const log = [];
    const dns = { a: { ...shopDns.a, "blog.shop.example": ["93.184.216.34"], "shop.example.evil.test": ["93.184.216.34"], "other.example": ["93.184.216.34"] } };
    const request = fakeSite({ "https://shop.example/": { status: 301, headers: { location } } }, log);
    const r = await fetchChain("https://shop.example/", { scope: "shop.example", resolver: fakeResolver(dns), request });
    assert.equal(log.length, 1, `${location} was not requested`);
    assert.equal(r.stopped.offsite, true, location);
    assert.equal(r.stopped.location, location);
    assert.match(r.stopped.reason, /off-site redirect .*not followed/);
  }
  // Private/metadata targets are refused for being unsafe, not labelled off-site.
  const r = await fetchChain("https://shop.example/", { scope: "shop.example", resolver: fakeResolver(shopDns), request: fakeSite({ "https://shop.example/": { status: 302, headers: { location: "http://169.254.169.254/" } } }) });
  assert.equal(r.stopped.offsite, undefined);
});

test("bare ↔ www redirects are followed, each hop re-vetted", async () => {
  const lookups = [];
  const base = fakeResolver(shopDns);
  const resolver = { resolve4: (n) => (lookups.push(n), base.resolve4(n)), resolve6: (n) => base.resolve6(n) };
  const request = fakeSite({
    "https://shop.example/": { status: 301, headers: { location: "https://www.shop.example/" } },
    "https://www.shop.example/": { status: 200, headers: {}, body: "ok" },
  });
  const r = await fetchChain("https://shop.example/", { scope: "shop.example", resolver, request });
  assert.equal(r.final.url, "https://www.shop.example/");
  assert.equal(r.stopped, null);
  assert.deepEqual(lookups, ["shop.example", "www.shop.example"]);
});

test("redirects to private addresses, file:, other ports or other domains are refused WITHOUT connecting", async () => {
  for (const location of ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "https://shop.example:8080/", "https://other.example/", "https://blog.shop.example/", "http://[::ffff:10.0.0.1]/"]) {
    const log = [];
    const request = fakeSite({ "https://shop.example/": { status: 302, headers: { location } } }, log);
    const r = await fetchChain("https://shop.example/", { scope: "shop.example", resolver: fakeResolver(shopDns), request });
    assert.equal(r.ok, true, location);
    assert.equal(log.length, 1, `only the first hop was requested for ${location}`);
    assert.ok(r.stopped && r.stopped.reason, location);
    assert.equal(r.final.status, 302);
  }
});

test("at most 5 redirects are followed", async () => {
  const routes = {};
  for (let i = 0; i < 10; i++) routes[`https://shop.example/${i}`] = { status: 301, headers: { location: `/${i + 1}` } };
  const log = [];
  const r = await fetchChain("https://shop.example/0", { scope: "shop.example", resolver: fakeResolver(shopDns), request: fakeSite(routes, log) });
  assert.equal(log.length, 6, "the start plus 5 redirects");
  assert.match(r.stopped.reason, /more than 5 redirects/);
});

test("an https → http downgrade is followed and flagged", async () => {
  const request = fakeSite({
    "https://shop.example/": { status: 301, headers: { location: "http://www.shop.example/" } },
    "http://www.shop.example/": { status: 200, headers: {}, body: "<html></html>" },
  });
  const r = await fetchChain("https://shop.example/", { scope: "shop.example", resolver: fakeResolver(shopDns), request });
  assert.equal(r.downgraded, true);
  assert.equal(r.final.url, "http://www.shop.example/");
});

test("DNS is re-vetted on every hop (rebinding to a private address mid-chain is refused)", async () => {
  let calls = 0;
  const resolver = {
    // First lookup answers a public IP, every later one a private IP.
    async resolve4() {
      calls++;
      return calls === 1 ? ["93.184.216.34"] : ["10.0.0.5"];
    },
    async resolve6() {
      throw Object.assign(new Error("none"), { code: "ENODATA" });
    },
  };
  const log = [];
  const request = fakeSite({ "https://shop.example/": { status: 301, headers: { location: "https://www.shop.example/" } } }, log);
  const r = await fetchChain("https://shop.example/", { scope: "shop.example", resolver, request });
  assert.equal(calls, 2, "the second hop was resolved again");
  assert.equal(log.length, 1, "the rebound hop was never connected to");
  assert.equal(r.stopped.reason, "non-public address");
});
