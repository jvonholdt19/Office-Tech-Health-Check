// Renders a real Website Security Check report with the page script (public/website.js) against a
// small fake DOM: the disclaimer shows next to the print header, and the "Platform for this client"
// choice is kept per domain (a new site starts with all platforms).
import { test } from "node:test";
import assert from "node:assert/strict";
import { runWebsiteScan } from "../lib/website-scan.js";
import { fakeResolver, NOW } from "./fakes.js";

class FakeNode {}
class FakeEl extends FakeNode {
  constructor(tag, id) {
    super();
    Object.assign(this, { tagName: String(tag).toUpperCase(), id: id || "", className: "", hidden: false, value: "", disabled: false, open: false, children: [], parent: null, attrs: {}, dataset: {}, listeners: {} });
  }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
    if (k === "id") this.id = String(v);
    if (k.startsWith("data-")) this.dataset[k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = String(v);
    if (k === "value") this.value = String(v);
  }
  getAttribute(k) {
    return this.attrs[k] ?? null;
  }
  addEventListener(type, fn) {
    this.listeners[type] = fn;
  }
  append(...nodes) {
    for (const n of nodes) {
      const node = typeof n === "string" ? new FakeText(n) : n;
      if (node.parent) node.parent.children = node.parent.children.filter((c) => c !== node);
      node.parent = this;
      this.children.push(node);
    }
  }
  prepend(node) {
    if (node.parent) node.parent.children = node.parent.children.filter((c) => c !== node);
    node.parent = this;
    this.children.unshift(node);
  }
  replaceChildren(...nodes) {
    this.children = [];
    this.append(...nodes);
  }
  get firstElementChild() {
    return this.children.find((c) => c instanceof FakeEl) || null;
  }
  get textContent() {
    return this.children.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    this.children = [new FakeText(String(v))];
  }
  *walk() {
    for (const c of this.children) {
      if (c instanceof FakeEl) {
        yield c;
        yield* c.walk();
      }
    }
  }
  matches(sel) {
    if (sel.startsWith("#")) return this.id === sel.slice(1);
    if (sel.startsWith(".")) return this.className.split(/\s+/).includes(sel.slice(1).split(/[:[]/)[0]);
    return this.tagName === sel.toUpperCase();
  }
  querySelectorAll(sel) {
    const last = sel.trim().split(/\s+/).pop();
    return [...this.walk()].filter((e) => e.matches(last));
  }
  focus() {}
}
class FakeText extends FakeNode {
  constructor(t) {
    super();
    this.text = t;
    this.parent = null;
  }
  get textContent() {
    return this.text;
  }
}

function setupDom() {
  const ids = ["gate", "gate-form", "access-code", "gate-error", "lock-btn", "tool", "website-form", "target", "website-btn", "website-error", "website-loading", "website-report"];
  const body = new FakeEl("body");
  for (const id of ids) body.append(new FakeEl("div", id));
  const store = new Map();
  Object.assign(globalThis, {
    Node: FakeNode,
    window: { addEventListener() {}, getSelection: () => ({ removeAllRanges() {}, addRange() {} }) },
    document: {
      createElement: (tag) => new FakeEl(tag),
      createTextNode: (t) => new FakeText(t),
      createRange: () => ({ selectNodeContents() {} }),
      getElementById: (id) => [...body.walk()].find((e) => e.id === id) || null,
      querySelectorAll: (sel) => body.querySelectorAll(sel),
    },
    location: { search: "" },
    history: { replaceState() {} },
    localStorage: { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) },
  });
  return { body, store, byId: (id) => globalThis.document.getElementById(id) };
}

async function reportFor(domain) {
  const page = (headers, url) => ({ ok: true, url, status: 200, headers, body: "", truncated: false });
  return runWebsiteScan(domain, {
    resolver: fakeResolver(),
    fetchPage: async (url) => (url.startsWith("https://") ? page({ "x-frame-options": "SAMEORIGIN" }, url) : page({}, url)),
    inspectTls: async () => ({ ok: true, authorized: true, validTo: new Date(NOW.getTime() + 90 * 864e5).toISOString(), protocol: "TLSv1.3" }),
    now: () => NOW,
  });
}
const tick = async () => {
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
};

test("the report shows the disclaimer right after the print header, and the platform choice is kept per domain", async () => {
  const { store, byId } = setupDom();
  const reports = { "example.com": await reportFor("example.com"), "example.net": await reportFor("example.net") };
  globalThis.fetch = async (path) => {
    if (path === "/api/session") return { status: 200, ok: true, json: async () => ({ authenticated: true }) };
    const target = new URL(path, "http://localhost").searchParams.get("target");
    return { status: 200, ok: true, json: async () => reports[target] };
  };
  const { DISCLAIMER } = await import(`../public/website.js?render=${Date.now()}`);
  await tick();
  assert.equal(DISCLAIMER, "Back up your site and test changes first. Your web host or developer should apply these changes.");

  // The technician picked WordPress for example.com on an earlier visit.
  store.set("ohc-fix-platform:example.com", "wordpress");
  const scan = async (domain) => {
    byId("target").value = domain;
    byId("website-form").listeners.submit({ preventDefault() {} });
    await tick();
  };

  await scan("example.com");
  const root = byId("website-report");
  const kids = root.children.filter((c) => c instanceof FakeEl);
  assert.equal(kids[0].className, "print-header");
  assert.equal(kids[1].className, "disclaimer", "the disclaimer comes straight after the print header");
  assert.equal(kids[1].textContent, DISCLAIMER);
  assert.ok(root.querySelectorAll(".fix-guide").length > 0, "guides rendered");
  assert.equal(byId("platform-select").value, "wordpress", "the saved choice for this domain is restored");
  const visible = root.querySelectorAll(".platform").filter((p) => !p.hidden).map((p) => p.dataset.platform);
  assert.ok(visible.length > 0 && visible.every((p) => p === "wordpress"));
  assert.match(byId("print-platform").textContent, /WordPress/);

  await scan("example.net");
  assert.equal(byId("platform-select").value, "", "a different site starts with all platforms");
  assert.ok(root.querySelectorAll(".platform").every((p) => !p.hidden));
  assert.equal(byId("print-platform").textContent, "");
  assert.equal(root.children.find((c) => c.className === "disclaimer").textContent, DISCLAIMER);

  // Changing the choice saves it for that domain only.
  const select = byId("platform-select");
  select.value = "nginx";
  select.listeners.change();
  assert.equal(store.get("ohc-fix-platform:example.net"), "nginx");
  assert.equal(store.get("ohc-fix-platform:example.com"), "wordpress");
});
