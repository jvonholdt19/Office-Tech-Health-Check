// DMARC Tracker Dashboard: manage staged DMARC rollout for client domains.
/* global fetch, alert, confirm */

let trackedDomains = [];
let stages = {};

async function loadDomains() {
  try {
    const res = await fetch("/api/dmarc-tracker");
    if (!res.ok) {
      if (res.status === 401) {
        window.location.href = "/tools";
        return;
      }
      throw new Error(`HTTP ${res.status}`);
    }
    const data = await res.json();
    trackedDomains = data.domains || [];
    stages = data.stages || {};
    renderDomains();
  } catch (err) {
    console.error("Failed to load domains:", err);
    document.getElementById("loading").innerHTML =
      '<p style="color: var(--fail);">Failed to load tracked domains. Please refresh the page.</p>';
  }
}

function renderDomains() {
  document.getElementById("loading").classList.add("content-hidden");
  document.getElementById("content").classList.remove("content-hidden");

  const readyCount = trackedDomains.filter((d) => d.can_advance).length;
  const summaryEl = document.getElementById("summary");
  if (readyCount > 0) {
    document.getElementById("ready-count").textContent = readyCount;
    summaryEl.classList.remove("summary-hidden");
  } else {
    summaryEl.classList.add("summary-hidden");
  }

  const listEl = document.getElementById("domains-list");
  if (trackedDomains.length === 0) {
    listEl.innerHTML =
      '<div class="empty-state"><p>No domains tracked yet. Add one above to get started.</p></div>';
    return;
  }

  listEl.innerHTML =
    '<div class="tracker-grid">' +
    trackedDomains.map(renderDomain).join("") +
    "</div>";
}

function renderDomain(d) {
  const stage = stages[d.stage] || {};
  const canAdvance = d.can_advance;
  const nextStage = stages[d.stage + 1];

  return `
    <div class="tracker-card ${canAdvance ? "ready" : ""}" data-id="${d.id}">
      <div class="tracker-header">
        <h3 class="tracker-domain">${escapeHtml(d.domain)}</h3>
        <span class="tracker-stage stage-${d.stage}">Stage ${d.stage}: ${escapeHtml(stage.name || "")}</span>
      </div>
      
      ${canAdvance ? `<div class="ready-notice"><strong>✓ Ready to advance to ${escapeHtml(nextStage?.name || "")}</strong></div>` : ""}
      
      <div class="tracker-meta">
        <div><strong>Days in stage:</strong> ${d.daysInStage}</div>
        ${stage.minWaitDays ? `<div><strong>Minimum wait:</strong> ${stage.minWaitDays} days</div>` : ""}
        <div><strong>Last check:</strong> ${d.last_check_at ? new Date(d.last_check_at).toLocaleString() : "Never"}</div>
        ${d.advance_note ? `<div><strong>Status:</strong> ${escapeHtml(d.advance_note)}</div>` : ""}
        ${d.notes ? `<div><strong>Notes:</strong> ${escapeHtml(d.notes)}</div>` : ""}
      </div>
      
      ${renderStageExplanation(d.stage)}
      
      <div class="tracker-actions">
        <button onclick="checkDomain(${d.id})" class="secondary">Recheck Now</button>
        ${canAdvance ? `<button onclick="advanceDomain(${d.id})" class="primary">Advance to ${escapeHtml(nextStage?.name || "")}</button>` : ""}
        ${d.stage === 1 && !canAdvance ? `<button onclick="skipToQuarantine(${d.id})" class="secondary">Skip to Quarantine</button>` : ""}
        <button onclick="removeDomain(${d.id}, '${escapeHtml(d.domain)}')" class="secondary">Remove</button>
      </div>
    </div>
  `;
}

function renderStageExplanation(stage) {
  const explanations = {
    1: "Monitor mode (p=none): collects DMARC reports to identify all legitimate senders. No email is blocked.",
    2: "Quarantine mode (p=quarantine): unauthenticated mail goes to spam. Monitor reports to ensure no legitimate mail is affected.",
    3: "Reject mode (p=reject): unauthenticated mail is rejected outright. Full protection against email spoofing.",
  };

  return `<div class="stage-explanation">${explanations[stage] || ""}</div>`;
}

async function checkDomain(id) {
  if (
    !confirm(
      "Recheck this domain now? This will verify the current DNS records and update advancement eligibility."
    )
  )
    return;

  try {
    const res = await fetch("/api/dmarc-tracker", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "check", id }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    alert(`Check complete:\n\n${data.check.reason}`);
    await loadDomains();
  } catch (err) {
    console.error("Check failed:", err);
    alert("Check failed: " + err.message);
  }
}

async function advanceDomain(id) {
  const domain = trackedDomains.find((d) => d.id === id);
  if (!domain) return;

  const nextStage = stages[domain.stage + 1];
  if (
    !confirm(
      `Advance ${domain.domain} to ${nextStage.name}?\n\nMake sure you've reviewed DMARC reports and confirmed all legitimate senders are authenticated.`
    )
  )
    return;

  try {
    const res = await fetch("/api/dmarc-tracker", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "advance", id }),
    });

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || `HTTP ${res.status}`);
    }

    alert(`${domain.domain} advanced to ${nextStage.name}!`);
    await loadDomains();
  } catch (err) {
    console.error("Advance failed:", err);
    alert("Advance failed: " + err.message);
  }
}

async function skipToQuarantine(id) {
  const domain = trackedDomains.find((d) => d.id === id);
  if (!domain) return;

  if (
    !confirm(
      `Skip ${domain.domain} directly to Quarantine?\n\nOnly do this if:\n1. You've confirmed ALL services that send email (billing, CRM, newsletters, etc.) are properly set up\n2. You understand the risk that legitimate mail could be marked as spam\n\nAre you sure?`
    )
  )
    return;

  try {
    const res = await fetch("/api/dmarc-tracker", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "advance",
        id,
        skipToStage: 2,
        note: "Skipped directly to quarantine after confirmation",
      }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    alert(`${domain.domain} moved to Quarantine mode.`);
    await loadDomains();
  } catch (err) {
    console.error("Skip failed:", err);
    alert("Skip failed: " + err.message);
  }
}

async function removeDomain(id, domain) {
  if (
    !confirm(
      `Remove ${domain} from tracking?\n\nThis will not change the domain's DMARC record - only stop tracking it in this tool.`
    )
  )
    return;

  try {
    const res = await fetch("/api/dmarc-tracker", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "remove", id }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    alert(`${domain} removed from tracking.`);
    await loadDomains();
  } catch (err) {
    console.error("Remove failed:", err);
    alert("Remove failed: " + err.message);
  }
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Wire up the add form
function initAddForm() {
  document
    .getElementById("add-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const domain = document.getElementById("domain").value.trim();
      const notes = document.getElementById("notes").value.trim();

      if (!domain) return;

      try {
        const res = await fetch("/api/dmarc-tracker", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "add", domain, note: notes || null }),
        });

        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || `HTTP ${res.status}`);
        }

        document.getElementById("domain").value = "";
        document.getElementById("notes").value = "";
        alert(`${domain} added to tracker!`);
        await loadDomains();
      } catch (err) {
        console.error("Add failed:", err);
        alert("Failed to add domain: " + err.message);
      }
    });
}

// Load on page load
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    initAddForm();
    loadDomains();
  });
} else {
  initAddForm();
  loadDomains();
}
