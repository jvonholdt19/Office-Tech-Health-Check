// Step-by-step fix guide generation tests
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  detectDnsHostFromNS,
  detectEmailProvider,
  generateSpfSteps,
  generateDkimSteps,
  generateDmarcSteps,
  generateFixSteps,
} from "../lib/fix-guides-steps.js";

test("detectDnsHostFromNS identifies common hosts", () => {
  assert.deepStrictEqual(
    detectDnsHostFromNS(["alice.ns.cloudflare.com", "bob.ns.cloudflare.com"]),
    { key: "cloudflare", name: "Cloudflare" }
  );
  assert.deepStrictEqual(
    detectDnsHostFromNS(["ns1.domaincontrol.com"]),
    { key: "godaddy", name: "GoDaddy" }
  );
  assert.deepStrictEqual(
    detectDnsHostFromNS(["dns1.registrar-servers.com"]),
    { key: "namecheap", name: "Namecheap" }
  );
  assert.deepStrictEqual(
    detectDnsHostFromNS(["ns-123.awsdns-45.com"]),
    { key: "route53", name: "Amazon Route 53" }
  );
  assert.deepStrictEqual(
    detectDnsHostFromNS(["ns-cloud-e1.googledomains.com"]),
    { key: "google-domains", name: "Google Domains" }
  );
  assert.deepStrictEqual(
    detectDnsHostFromNS(["ns1-01.azure-dns.com"]),
    { key: "microsoft", name: "Microsoft DNS" }
  );
});

test("detectDnsHostFromNS returns other for unknown", () => {
  assert.deepStrictEqual(
    detectDnsHostFromNS(["ns1.example.com", "ns2.example.com"]),
    { key: "other", name: "Other DNS provider" }
  );
});

test("detectEmailProvider identifies providers", () => {
  assert.deepStrictEqual(
    detectEmailProvider([{ exchange: "smtp.google.com" }]),
    { key: "google", name: "Google Workspace" }
  );
  assert.deepStrictEqual(
    detectEmailProvider([{ exchange: "example.mail.protection.outlook.com" }]),
    { key: "microsoft", name: "Microsoft 365" }
  );
  assert.deepStrictEqual(
    detectEmailProvider([{ exchange: "mx.zoho.com" }]),
    { key: "zoho", name: "Zoho Mail" }
  );
  assert.deepStrictEqual(
    detectEmailProvider([{ exchange: "mailstore1.secureserver.net" }]),
    { key: "godaddy", name: "GoDaddy Email" }
  );
  assert.deepStrictEqual(
    detectEmailProvider([{ exchange: "mail.example.com" }]),
    { key: "other", name: "Other email provider" }
  );
});

test("generateSpfSteps produces numbered steps for new SPF", () => {
  const check = {
    id: "spf",
    status: "fail",
    data: { records: [] },
  };
  const scanData = {
    provider: { key: "google", name: "Google Workspace" },
    dnsHost: { key: "cloudflare", name: "Cloudflare" },
  };
  
  const result = generateSpfSteps(check, "example.com", scanData);
  
  assert.ok(result.summary);
  assert.ok(Array.isArray(result.steps));
  assert.ok(result.steps.length > 0);
  assert.ok(result.steps.every(s => typeof s.num === "number" && s.action));
  assert.ok(result.steps.some(s => s.recheck === true));
  assert.strictEqual(result.recordType, "TXT");
  assert.strictEqual(result.recordName, "example.com");
  assert.ok(result.recordValue);
  assert.ok(result.recordValue.includes("v=spf1"));
  assert.ok(result.recordValue.includes("include:_spf.google.com"));
});

test("generateSpfSteps handles existing SPF record", () => {
  const check = {
    id: "spf",
    status: "warn",
    data: { records: ["v=spf1 include:_spf.google.com -all"] },
  };
  const scanData = {
    provider: { key: "google", name: "Google Workspace" },
    dnsHost: { key: "godaddy", name: "GoDaddy" },
  };
  
  const result = generateSpfSteps(check, "example.com", scanData);
  
  assert.ok(result.summary.includes("Fix") || result.summary.includes("existing"));
  assert.ok(result.steps.length > 0);
  assert.ok(result.recordValue);
});

test("generateDkimSteps produces provider-specific steps", () => {
  const check = {
    id: "dkim",
    status: "fail",
    data: {},
  };
  const scanData = {
    provider: { key: "google", name: "Google Workspace" },
    dnsHost: { key: "cloudflare", name: "Cloudflare" },
  };
  
  const result = generateDkimSteps(check, "example.com", scanData);
  
  assert.ok(result.summary);
  assert.ok(result.summary.includes("Google Workspace"));
  assert.ok(Array.isArray(result.steps));
  assert.ok(result.steps.length >= 5);
  assert.ok(result.steps.some(s => s.recheck === true));
  assert.strictEqual(result.providerName, "Google Workspace");
});

test("generateDmarcSteps produces staged rollout steps", () => {
  const check = {
    id: "dmarc",
    status: "fail",
    data: { tags: null },
  };
  const scanData = {
    provider: { key: "google", name: "Google Workspace" },
    dnsHost: { key: "cloudflare", name: "Cloudflare" },
  };
  
  const result = generateDmarcSteps(check, "example.com", scanData, "dmarc@nwimpm.com");
  
  assert.ok(result.summary);
  assert.ok(Array.isArray(result.steps));
  assert.ok(result.steps.some(s => s.recheck === true));
  assert.strictEqual(result.recordType, "TXT");
  assert.strictEqual(result.recordName, "_dmarc.example.com");
  assert.ok(result.recordValue);
  assert.ok(result.recordValue.includes("v=DMARC1"));
  assert.ok(result.recordValue.includes("p=none"));
  assert.ok(result.recordValue.includes("rua=mailto:dmarc@nwimpm.com"));
  assert.strictEqual(result.staged, true);
  assert.ok(result.steps.some(s => s.note && s.note.includes("staged")));
});

test("generateFixSteps dispatches to correct generator", () => {
  const spfCheck = { id: "spf", status: "fail", data: { records: [] } };
  const scanData = {
    provider: { key: "google", name: "Google Workspace" },
    dnsHost: { key: "cloudflare", name: "Cloudflare" },
  };
  const config = { reportAddress: "dmarc@test.com" };
  
  const result = generateFixSteps(spfCheck, "example.com", scanData, config);
  assert.ok(result);
  assert.ok(result.steps);
  assert.ok(result.recordValue);
});

test("generateFixSteps returns null for unsupported check", () => {
  const check = { id: "unsupported-check", status: "fail", data: {} };
  const scanData = {};
  
  const result = generateFixSteps(check, "example.com", scanData);
  assert.strictEqual(result, null);
});

test("generateSslSteps produces certificate renewal steps", () => {
  const check = {
    id: "ssl",
    status: "fail",
    data: { code: "expired" },
  };
  const scanData = {};
  
  const result = generateFixSteps(check, "example.com", scanData);
  
  assert.ok(result);
  assert.ok(result.summary.includes("expired"));
  assert.ok(result.steps.length > 0);
  assert.ok(result.steps.some(s => s.action.includes("Renew")));
  assert.ok(result.steps.some(s => s.recheck === true));
});
