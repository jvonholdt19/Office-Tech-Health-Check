// Minimal DNS-over-UDP client (RFC 1035 message format, RFC 6891 EDNS0), used only by the Domain
// Health check to ask a domain's own nameservers about that domain: SOA (to spot lame delegation and
// compare serials) and DNSKEY (to spot broken DNSSEC). Node's resolver can't do this because it
// hides the AA (authoritative answer) flag. Zero dependencies.
//
// Safety: queries go only to UDP port 53 on an IP that passes isNonPublicAddress() === false, with
// recursion off, a 3 s timeout and a 4 KB response cap. Nothing else is ever sent.
import dgram from "node:dgram";
import net from "node:net";
import { randomInt } from "node:crypto";
import { isNonPublicAddress } from "./net.js";

export const TYPE = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, OPT: 41, DS: 43, DNSKEY: 48 };

/** Encode a query for `name`/`type` with recursion desired off and an EDNS0 OPT record (1232-byte payload). */
export function buildQuery(name, type, id = randomInt(0, 65536)) {
  const labels = String(name).replace(/\.$/, "").split(".").filter(Boolean);
  const qname = Buffer.concat([...labels.map((l) => Buffer.concat([Buffer.from([Buffer.byteLength(l)]), Buffer.from(l, "ascii")])), Buffer.from([0])]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0000, 2); // QR=0, opcode QUERY, RD=0: ask the server only about what it holds itself
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(1, 10); // ARCOUNT (OPT)
  const question = Buffer.alloc(4);
  question.writeUInt16BE(type, 0);
  question.writeUInt16BE(1, 2); // class IN
  const opt = Buffer.alloc(11);
  opt.writeUInt8(0, 0); // root name
  opt.writeUInt16BE(TYPE.OPT, 1);
  opt.writeUInt16BE(1232, 3); // UDP payload size
  // ttl (extended rcode, version, flags) = 0, rdlength = 0
  return { id, packet: Buffer.concat([header, qname, question, opt]) };
}

/** Read a (possibly compressed) domain name at `offset`. Returns { name, next }. */
function readName(buf, offset) {
  const labels = [];
  let pos = offset;
  let next = -1;
  for (let jumps = 0; jumps < 64; jumps++) {
    if (pos >= buf.length) throw new Error("truncated name");
    const len = buf[pos];
    if (len === 0) {
      if (next === -1) next = pos + 1;
      return { name: labels.join("."), next };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw new Error("truncated pointer");
      if (next === -1) next = pos + 2;
      pos = ((len & 0x3f) << 8) | buf[pos + 1];
      continue;
    }
    if (pos + 1 + len > buf.length) throw new Error("truncated label");
    labels.push(buf.toString("ascii", pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  throw new Error("name compression loop");
}

/** Decode a response: flags, rcode and the answer section (SOA rdata decoded; other types by length). */
export function parseResponse(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) throw new Error("short response");
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  let pos = 12;
  for (let i = 0; i < qd; i++) pos = readName(buf, pos).next + 4;
  const answers = [];
  for (let i = 0; i < an; i++) {
    const { name, next } = readName(buf, pos);
    pos = next;
    if (pos + 10 > buf.length) throw new Error("truncated record");
    const type = buf.readUInt16BE(pos);
    const ttl = buf.readUInt32BE(pos + 4);
    const rdlength = buf.readUInt16BE(pos + 8);
    const rdStart = pos + 10;
    if (rdStart + rdlength > buf.length) throw new Error("truncated rdata");
    let data = { length: rdlength };
    if (type === TYPE.SOA) {
      const mname = readName(buf, rdStart);
      const rname = readName(buf, mname.next);
      const n = rname.next;
      data = { mname: mname.name, rname: rname.name, serial: buf.readUInt32BE(n), refresh: buf.readUInt32BE(n + 4), retry: buf.readUInt32BE(n + 8), expire: buf.readUInt32BE(n + 12), minimum: buf.readUInt32BE(n + 16) };
    }
    answers.push({ name, type, ttl, data });
    pos = rdStart + rdlength;
  }
  return { id, qr: Boolean(flags & 0x8000), aa: Boolean(flags & 0x0400), tc: Boolean(flags & 0x0200), rcode: flags & 0x000f, answers };
}

/**
 * Ask the DNS server at `ip` (port 53, UDP) one question. Never throws.
 * Returns { ok: true, aa, tc, rcode, answers } or { ok: false, error, refused? }.
 */
export async function queryDns(ip, name, type, { timeoutMs = 3000, createSocket = dgram.createSocket } = {}) {
  if (isNonPublicAddress(ip)) return { ok: false, refused: true, error: "non-public address" };
  const { id, packet } = buildQuery(name, type);
  return new Promise((resolve) => {
    const socket = createSocket(net.isIP(ip) === 6 ? "udp6" : "udp4");
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.close();
      } catch {}
      resolve(value);
    };
    const timer = setTimeout(() => done({ ok: false, error: "timeout" }), timeoutMs);
    socket.on("error", (err) => done({ ok: false, error: err.code || err.message }));
    socket.on("message", (msg, rinfo) => {
      if (rinfo && rinfo.address !== ip && rinfo.address !== `::ffff:${ip}`) return; // ignore anyone else
      if (msg.length > 4096) return done({ ok: false, error: "response too large" });
      try {
        const r = parseResponse(msg);
        if (r.id !== id || !r.qr) return; // not our answer
        done({ ok: true, aa: r.aa, tc: r.tc, rcode: r.rcode, answers: r.answers });
      } catch (err) {
        done({ ok: false, error: err.message });
      }
    });
    socket.send(packet, 53, ip, (err) => err && done({ ok: false, error: err.code || err.message }));
  });
}
