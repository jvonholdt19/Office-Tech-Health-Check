// The /tools/website page script, run against a minimal fake DOM: a ?t= link must only pre-fill the
// field. The scan starts only when the technician submits the form.
import { test } from "node:test";
import assert from "node:assert/strict";

function fakeDom() {
  const els = {};
  const el = (id) =>
    (els[id] ||= {
      id, hidden: false, value: "", textContent: "", disabled: false, listeners: {},
      addEventListener(type, fn) { this.listeners[type] = fn; },
      focus() {}, replaceChildren() {},
    });
  return { els, document: { getElementById: el, createElement: () => ({ append() {}, setAttribute() {}, addEventListener() {} }), createTextNode: (t) => t } };
}

test("/tools/website?t=… pre-fills the target but never scans until the form is submitted", async () => {
  const { els, document } = fakeDom();
  const calls = [];
  Object.assign(globalThis, {
    document,
    location: { search: "?t=example.com" },
    history: { replaceState() {} },
    fetch: async (path) => {
      calls.push(path);
      const body = path === "/api/session" ? { authenticated: true } : { error: "stop here" };
      return { status: path === "/api/session" ? 200 : 400, ok: path === "/api/session", json: async () => body };
    },
  });
  await import(`../public/website.js?t=${Date.now()}`);
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));

  assert.equal(els.tool.hidden, false, "signed in: the tool is shown");
  assert.equal(els.target.value, "example.com", "the field is pre-filled from ?t=");
  assert.deepEqual(calls, ["/api/session"], "no scan was requested on page load");

  els["website-form"].listeners.submit({ preventDefault() {} });
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
  assert.deepEqual(calls, ["/api/session", "/api/website?target=example.com"], "the scan runs after the technician presses the button");
});
