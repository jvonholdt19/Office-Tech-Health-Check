// Email Security Check (/tools/email, technician only). The full email & domain scanner that used to
// live at /. It calls the private /api/scan with the technician session cookie; signed-out visitors
// see the access-code gate from tech-session.js.
import { $, api, initGate } from "./tech-session.js";
const els = {
  form: $("scan-form"),
  input: $("domain"),
  button: $("scan-btn"),
  error: $("form-error"),
  hero: $("hero"),
  loading: $("loading"),
  steps: $("loading-steps"),
  report: $("report"),
  grade: $("grade"),
  domain: $("summary-domain"),
  headline: $("summary-headline"),
  meta: $("summary-meta"),
  pills: $("summary-pills"),
  categories: $("categories"),
  fixCard: $("fix-card"),
  fixList: $("fix-list"),
  scannedAt: $("scanned-at"),
  template: $("check-template"),
};

const STATUS_LABEL = { pass: "Good", warn: "Needs attention", fail: "At risk", unknown: "Couldn't verify", info: "FYI" };
const CATEGORY_ORDER = ["Email platform", "Email security", "Domain", "Website"];
const CATEGORY_BLURB = {
  "Email platform": "Where your business email lives.",
  "Email security": "Whether scammers can send email that looks like it came from you, and whether your real email reaches the inbox.",
  Domain: "Your domain name is the foundation for your website and every email address.",
  Website: "What customers see when they visit your site.",
};

function headlineFor(report) {
  const { grade, counts } = report;
  const problems = (counts.fail || 0) + (counts.warn || 0);
  if (grade === null) return "Not enough could be checked to give a fair grade";
  if (grade === "A") return "Your office tech basics are in great shape";
  if (grade === "B") return `Solid, with ${problems} thing${problems === 1 ? "" : "s"} worth tightening up`;
  if (grade === "C") return `A few gaps put your business at risk`;
  return `Important gaps found: ${problems} item${problems === 1 ? "" : "s"} to fix`;
}

let stepTimer;
function showLoading(on) {
  els.loading.hidden = !on;
  els.button.disabled = on;
  els.button.textContent = on ? "Checking…" : "Run check";
  clearInterval(stepTimer);
  const items = [...els.steps.children];
  items.forEach((li) => li.classList.remove("active", "done"));
  if (on) {
    let i = 0;
    items[0].classList.add("active");
    stepTimer = setInterval(() => {
      if (i < items.length - 1) {
        items[i].classList.replace("active", "done");
        items[++i].classList.add("active");
      }
    }, 1400);
  }
}

function showError(msg) {
  els.error.textContent = msg;
  els.error.hidden = !msg;
}

function renderCheck(check) {
  const node = els.template.content.firstElementChild.cloneNode(true);
  node.dataset.status = check.status;
  const status = node.querySelector("[data-status]");
  status.textContent = STATUS_LABEL[check.status] || check.status;
  status.dataset.status = check.status;
  node.querySelector(".check-title").textContent = check.title;
  node.querySelector(".check-summary").textContent = check.summary;
  node.querySelector(".check-raw").textContent = check.detail || "n/a";
  return node;
}

function renderReport(report) {
  els.grade.textContent = report.grade ?? "?";
  els.grade.dataset.grade = report.grade ?? "none";
  els.domain.textContent = report.domain;
  els.headline.textContent = headlineFor(report);
  const coverageNote = report.coverage < 100 && report.unverified?.length
    ? ` · Based on ${report.coverage}% of checks (couldn't verify: ${report.unverified.map((u) => u.title.replace(/\s*\(.*\)$/, "")).join(", ")})`
    : "";
  els.meta.textContent = `Email platform: ${report.provider?.name ?? "Unknown"}${report.score !== null && report.grade ? ` · Score ${report.score}/100` : ""}${coverageNote}`;

  els.pills.replaceChildren(
    ...["fail", "warn", "unknown", "pass"]
      .filter((s) => report.counts[s])
      .map((s) => {
        const span = document.createElement("span");
        span.className = "pill";
        span.dataset.status = s;
        span.textContent = `${report.counts[s]} ${STATUS_LABEL[s].toLowerCase()}`;
        return span;
      }),
  );

  const groups = CATEGORY_ORDER.map((cat) => ({ cat, items: report.checks.filter((c) => c.category === cat) })).filter((g) => g.items.length);
  els.categories.replaceChildren(
    ...groups.map(({ cat, items }) => {
      const section = document.createElement("section");
      section.className = "category";
      const h = document.createElement("h3");
      h.textContent = cat;
      const p = document.createElement("p");
      p.className = "category-blurb";
      p.textContent = CATEGORY_BLURB[cat] || "";
      const grid = document.createElement("div");
      grid.className = "check-grid";
      grid.append(...items.map(renderCheck));
      section.append(h, p, grid);
      return section;
    }),
  );

  els.fixList.replaceChildren(
    ...report.fixes.map((f) => {
      const li = document.createElement("li");
      const strong = document.createElement("strong");
      strong.textContent = `${f.title}: `;
      li.append(strong, document.createTextNode(f.fix));
      return li;
    }),
  );
  els.fixCard.hidden = report.fixes.length === 0;
  els.scannedAt.textContent = new Date(report.scannedAt).toLocaleString();
  $("plan-link").href = `/plan?d=${encodeURIComponent(report.domain)}`;

  els.report.hidden = false;
  els.report.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function scan(rawDomain) {
  showError("");
  els.report.hidden = true;
  showLoading(true);
  try {
    const { res, body } = await api(`/api/scan?domain=${encodeURIComponent(rawDomain)}`);
    if (res.status === 401) return; // the gate is shown again by api()
    if (!res.ok) throw new Error(body.error || "Something went wrong. Please try again.");
    const url = new URL(location.href);
    url.searchParams.set("d", body.domain);
    history.replaceState(null, "", url);
    els.input.value = body.domain;
    renderReport(body);
  } catch (err) {
    showError(err.message || "Something went wrong. Please try again.");
  } finally {
    showLoading(false);
  }
}

els.form.addEventListener("submit", (e) => {
  e.preventDefault();
  const value = els.input.value.trim();
  if (!value) return showError("Enter your business domain, like example.com.");
  scan(value);
});

$("copy-link").addEventListener("click", async (e) => {
  try {
    await navigator.clipboard.writeText(location.href);
    e.target.textContent = "Copied!";
  } catch {
    e.target.textContent = "Copy failed";
  }
  setTimeout(() => (e.target.textContent = "Copy link"), 1800);
});
$("print-report").addEventListener("click", () => window.print());
$("scan-another").addEventListener("click", () => {
  els.report.hidden = true;
  els.input.value = "";
  history.replaceState(null, "", location.pathname);
  els.hero.scrollIntoView({ behavior: "smooth" });
  els.input.focus();
});

// Links like /tools/email?d=example.com (and old /?d= or /?domain= links, redirected here by vercel.json)
// pre-fill the domain once signed in. Like the Website Security Check, a link never starts a scan
// by itself: the technician presses "Run check".
initGate({
  contentId: "tool",
  onSignedIn: () => {
    const params = new URLSearchParams(location.search);
    const initial = params.get("d") || params.get("domain");
    if (initial && !els.input.value) els.input.value = initial.slice(0, 253);
    els.input.focus();
  },
  onSignedOut: () => (els.report.hidden = true),
});
