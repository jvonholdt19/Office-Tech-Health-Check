// Public lander (/): the "Quick email security check (preview)". Calls /api/preview (public, rate
// limited) and shows only the grade and a pass/warn/fail line per item. All text goes in through
// textContent; nothing from the response is parsed as HTML.
const $ = (id) => document.getElementById(id);
const STATUS_LABEL = { pass: "Good", warn: "Needs attention", fail: "At risk", unknown: "Couldn't verify", info: "Not applicable" };

function showError(msg) {
  $("preview-error").textContent = msg || "";
  $("preview-error").hidden = !msg;
}

function render(r) {
  $("preview-grade").textContent = r.grade || "–";
  $("preview-grade").dataset.grade = r.grade || "none";
  $("preview-for").textContent = r.domain;
  const list = $("preview-items");
  list.replaceChildren(
    ...r.items.map((item) => {
      const li = document.createElement("li");
      const status = document.createElement("span");
      status.className = "status";
      status.dataset.status = item.status;
      status.textContent = STATUS_LABEL[item.status] || item.status;
      const title = document.createElement("span");
      title.textContent = item.title;
      li.append(status, title);
      return li;
    }),
  );
  $("preview-result").hidden = false;
}

$("preview-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = $("preview-domain").value.trim();
  if (!domain) return showError("Enter your business domain, like yourbusiness.com.");
  showError("");
  $("preview-result").hidden = true;
  $("preview-loading").hidden = false;
  $("preview-btn").disabled = true;
  try {
    const res = await fetch(`/api/preview?domain=${encodeURIComponent(domain)}`, { credentials: "omit" });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) return showError(body.error || "Something went wrong. Please try again.");
    render(body);
  } catch {
    showError("Couldn't reach the server. Please try again.");
  } finally {
    $("preview-loading").hidden = true;
    $("preview-btn").disabled = false;
  }
});
