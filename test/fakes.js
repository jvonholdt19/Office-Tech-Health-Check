// Fake network layer so tests never touch real DNS or websites.
export function fakeResolver({ mx = {}, txt = {} } = {}) {
  const notFound = () => Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  return {
    async resolveMx(name) {
      if (!(name in mx)) throw notFound();
      return mx[name];
    },
    async resolveTxt(name) {
      if (!(name in txt)) throw notFound();
      return txt[name].map((r) => (Array.isArray(r) ? r : [r]));
    },
  };
}

export const NOW = new Date("2026-10-01T12:00:00Z");

export function fakeDeps({ mx, txt, tls, http, rdap } = {}) {
  return {
    resolver: fakeResolver({ mx, txt }),
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
