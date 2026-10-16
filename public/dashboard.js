// Technician tools dashboard (/tools): one card per tool in the registry (tools.js).
// Every tool lives under /tools behind the technician sign-in; the public lander is at /.
import { $, h, initGate, featureEnabled, isAdminSession } from "./tech-session.js";
import { TOOLS } from "./tools.js";

const SVG_NS = "http://www.w3.org/2000/svg";

/** <svg><use href="/assets/icons.svg#id"/></svg>, built in the SVG namespace (h() makes HTML elements). */
function icon(id) {
  const svg = document.createElementNS(SVG_NS, "svg");
  for (const [k, v] of Object.entries({ class: "tool-icon", width: "28", height: "28", "aria-hidden": "true", focusable: "false" })) svg.setAttribute(k, v);
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", `/assets/icons.svg#${id}`);
  svg.append(use);
  return svg;
}

function card(tool) {
  // A tool behind a feature switch (tools.js `feature`) is a "Coming soon" card until the switch is on.
  const live = tool.status === "live" && tool.href && (!tool.feature || featureEnabled(tool.feature));
  const body = [
    tool.icon ? icon(tool.icon) : null,
    h("div", { class: "tool-card-head" }, h("h2", {}, tool.name), live ? null : h("span", { class: "soon-tag" }, "Coming soon")),
    h("p", {}, tool.blurb),
  ];
  return live
    ? h("a", { class: "tool-card", href: tool.href, "data-tool": tool.id }, ...body)
    : h("div", { class: "tool-card disabled", "aria-disabled": "true", "data-tool": tool.id }, ...body);
}

function render() {
  // Admin-only tools (tools.js `admin`) are left off for non-admins.
  $("tool-grid").replaceChildren(...TOOLS.filter((t) => !t.admin || isAdminSession()).map(card));
}

initGate({ contentId: "dashboard", onSignedIn: render });
