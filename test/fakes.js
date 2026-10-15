// Fake network layer so tests never touch real DNS or websites.
export function fakeResolver({ mx = {}, txt = {}, ns = {}, a = {}, aaaa = {}, soa = {}, caa = {}, cname = {} } = {}) {
  const notFound = () => Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  return {
    async resolveMx(name) {
      if (!(name in mx)) throw notFound();
      return mx[name];
    },
    async resolveNs(name) {
      if (!(name in ns)) throw notFound();
      return ns[name];
    },
    async resolve4(name) {
      if (!(name in a)) throw notFound();
      return a[name];
    },
    async resolve6(name) {
      if (!(name in aaaa)) throw notFound();
      return aaaa[name];
    },
    async resolveSoa(name) {
      if (!(name in soa)) throw Object.assign(new Error("no data"), { code: "ENODATA" });
      return soa[name];
    },
    async resolveCaa(name) {
      if (!(name in caa)) throw Object.assign(new Error("no data"), { code: "ENODATA" });
      return caa[name];
    },
    async resolveCname(name) {
      if (!(name in cname)) throw Object.assign(new Error("no data"), { code: "ENODATA" });
      return cname[name];
    },
    async resolveTxt(name) {
      if (!(name in txt)) throw notFound();
      return txt[name].map((r) => (Array.isArray(r) ? r : [r]));
    },
  };
}

// A real 2048-bit RSA public key (SubjectPublicKeyInfo, base64), so DKIM key-size checks see a valid key.
export const DKIM_2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr70UHT8KFBm54FnKShc+vvr7AK90xtOQUSfp8oFNC9leC70r6eMvxr0uvmXjlCg4z0WA07vtRW6ig6KvoIPRhEE+WbKkZutQzqMxtKYOvCtnV1WKeFthgKGVAw7o2/LcionXxWXLKfC5JqqM/ZeQ5RBlzDm3301F4GKBqg1QxUvj3oRYuGPxUvMq8oowuv/FzlGDhUcT6Tz43MLW5rZeyjuuLOhqIKV+ds4AqfF9ZsUCHSFZDeOgphtFxmVFlz74rYJbjQfARLuh8vC8vQHo87DTri5lzvB4AddGYUQIBC8X/qULELa57rRmoNCtWTOwUWQUALvT8ylGamFC5it8uwIDAQAB";
export const DKIM_RECORD = `v=DKIM1; k=rsa; p=${DKIM_2048}`;

export const NOW = new Date("2026-10-01T12:00:00Z");

export function fakeDeps({ mx, txt, ns, a, aaaa, tls, http, rdap } = {}) {
  return {
    resolver: fakeResolver({ mx, txt, ns, a, aaaa }),
    inspectTls: async (host) => (tls && tls[host]) || { ok: false, error: "ECONNREFUSED" },
    probeHttp: async () => http || { ok: false, error: "ECONNREFUSED" },
    fetchRdap: async () => rdap || { ok: false, error: "HTTP 404" },
    now: () => NOW,
  };
}

export const goodTls = { ok: true, authorized: true, validTo: "2027-01-01T00:00:00Z", issuer: "Let's Encrypt" };

export function rdapData({ expiry = "2028-05-01T00:00:00Z", locked = true, dnssec = false } = {}) {
  return {
    ok: true,
    data: {
      events: [
        { eventAction: "registration", eventDate: "2012-05-01T00:00:00Z" },
        { eventAction: "expiration", eventDate: expiry },
      ],
      status: locked ? ["client transfer prohibited"] : ["active"],
      secureDNS: { delegationSigned: dnssec },
      entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, LLC"]]] }],
    },
  };
}
