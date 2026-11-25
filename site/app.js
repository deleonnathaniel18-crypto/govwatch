const STATUS_META = {
  online: { label: "Online", cls: "chip-online" },
  experiencing_issues: { label: "Issues", cls: "chip-issues" },
  unavailable: { label: "Unavailable", cls: "chip-unavailable" },
  monitoring_restricted: { label: "WAF Restricted", cls: "chip-restricted" },
  not_yet_checked: { label: "Not Checked", cls: "chip-neutral" },
  monitoring_suspended: { label: "Suspended", cls: "chip-neutral" },
};

const CATEGORY_LABELS = {
  agency_portal: "Agency Portal",
  open_data_portal: "Open Data Portal",
  open_data_api: "Open Data API",
  statistical_api: "Statistical API",
  document_repository: "Document Repo",
  public_service_portal: "Service Portal",
};

const VIEW_PATHS = {
  overview: "/overview",
  directory: "/sources",
  history: "/history",
  incidents: "/incidents",
  methodology: "/methodology",
  about: "/about",
};

const PATH_VIEWS = {
  "/": "overview",
  "/overview": "overview",
  "/sources": "directory",
  "/directory": "directory",
  "/history": "history",
  "/incidents": "incidents",
  "/methodology": "methodology",
  "/about": "about",
};

const state = {
  sources: [],
  status: null,
  incidents: [],
  datasets: [],
  history: null,
  activeView: "overview",
};

function chipHtml(statusKey) {
  const info = STATUS_META[statusKey] || STATUS_META.not_yet_checked;
  return `<span class="status-chip ${info.cls}"><span class="dot"></span>${info.label}</span>`;
}

function formatTime(iso) {
  if (!iso) return "STANDBY";
  return new Date(iso).toLocaleString("en-PH", { dateStyle: "medium", timeStyle: "short" });
}

function updateClock() {
  const now = new Date();
  const hh = String(now.getUTCHours()).padStart(2, "0");
  const mm = String(now.getUTCMinutes()).padStart(2, "0");
  const ss = String(now.getUTCSeconds()).padStart(2, "0");
  document.getElementById("clockBadge").textContent = `UTC // ${hh}:${mm}:${ss}`;
}

function switchView(viewName, push = true) {
  state.activeView = viewName;
  document.querySelectorAll(".view").forEach((el) => el.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === viewName);
  });
  const target = document.getElementById(`view-${viewName}`);
  if (target) target.classList.add("active");
  document.getElementById("topbarRight").classList.remove("open");

  if (push) {
    const nextPath = VIEW_PATHS[viewName] || "/overview";
    if (window.location.pathname !== nextPath) {
      window.history.pushState({ view: viewName }, "", nextPath);
    }
  }
}

function renderKpis() {
  const s = {
    total_monitored: state.sources.length,
    online: 0,
    experiencing_issues: 0,
    unavailable: 0,
    monitoring_restricted: 0,
    not_yet_checked: 0,
  };
  state.sources.forEach((src) => {
    const st = state.status.sources[src.id]?.status || "not_yet_checked";
    if (st in s) s[st] += 1;
    else s.not_yet_checked += 1;
  });
  const kpis = [
    {
      label: "MONITORED ENDPOINTS",
      value: s.total_monitored,
      sub: `${s.not_yet_checked} awaiting probe`,
      color: "var(--accent-cyan)",
      icon: `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/></svg>`,
    },
    {
      label: "NOMINAL / ONLINE",
      value: s.online,
      sub: "HTTP 200 verified",
      color: "var(--accent-mint)",
      icon: `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`,
    },
    {
      label: "DEGRADED / ISSUES",
      value: s.experiencing_issues,
      sub: "Awaiting confirmation",
      color: "var(--accent-amber)",
      icon: `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 8v4l2.5 2.5"/></svg>`,
    },
    {
      label: "CONFIRMED OFFLINE",
      value: s.unavailable,
      sub: "2+ consecutive failures",
      color: "var(--accent-red)",
      icon: `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    },
    {
      label: "WAF RESTRICTED",
      value: s.monitoring_restricted,
      sub: "Cloud-IP bot challenge",
      color: "var(--accent-violet)",
      icon: `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    },
  ];

  document.getElementById("kpiGrid").innerHTML = kpis
    .map(
      (k) => `
      <div class="kpi-card">
        <div>
          <div class="kpi-label">${k.label}</div>
          <div class="kpi-value" style="color:${k.color}">${k.value}</div>
          <div class="kpi-sub">${k.sub}</div>
        </div>
        <div class="kpi-icon" style="color:${k.color}">${k.icon}</div>
      </div>`
    )
    .join("");
}

function renderOverviewMatrix() {
  const tbody = document.getElementById("overviewMatrixBody");
  const mobileAcc = document.getElementById("overviewMobileAccordion");

  tbody.innerHTML = state.sources
    .map((src) => {
      const st = state.status.sources[src.id] || {};
      const httpCode = st.http_status ?? "—";
      const latency = st.response_time_ms !== null && st.response_time_ms !== undefined ? `${st.response_time_ms} ms` : "—";
      const uptime = st.uptime_30d_pct !== null && st.uptime_30d_pct !== undefined ? `${st.uptime_30d_pct}%` : "PENDING";
      return `
        <tr class="matrix-row" data-source-id="${src.id}">
          <td>
            <div class="src-name">${src.name}</div>
            <div class="src-agency">${src.agency_abbr}</div>
          </td>
          <td>${chipHtml(st.status)}</td>
          <td class="mono-cell">${CATEGORY_LABELS[src.category] || src.category}</td>
          <td class="mono-cell">${src.check_method}</td>
          <td class="mono-cell">${httpCode}</td>
          <td class="mono-cell">${latency}</td>
          <td class="mono-cell">${uptime}</td>
          <td class="mono-cell">&rsaquo;</td>
        </tr>`;
    })
    .join("");

  if (mobileAcc) {
    mobileAcc.innerHTML = state.sources
      .map((src) => {
        const st = state.status.sources[src.id] || {};
        const httpCode = st.http_status ?? "—";
        const latency = st.response_time_ms !== null && st.response_time_ms !== undefined ? `${st.response_time_ms} ms` : "—";
        const uptime = st.uptime_30d_pct !== null && st.uptime_30d_pct !== undefined ? `${st.uptime_30d_pct}% (${st.uptime_30d_sample_count ?? 0})` : "Pending";
        return `
          <details class="acc-item">
            <summary class="acc-summary">
              <div class="acc-title-wrap">
                <div class="acc-title">${src.name}</div>
                <div class="acc-sub">${src.agency_abbr} &middot; ${CATEGORY_LABELS[src.category] || src.category}</div>
              </div>
              <div class="acc-right">
                ${chipHtml(st.status)}
                <span class="acc-chevron" aria-hidden="true">▾</span>
              </div>
            </summary>
            <div class="acc-body">
              <div class="acc-kv"><span>Method</span><code>${src.check_method}</code></div>
              <div class="acc-kv"><span>HTTP / Evidence</span><code>${httpCode}${st.last_error ? ` (${st.last_error})` : ""}</code></div>
              <div class="acc-kv"><span>Latency</span><span>${latency}</span></div>
              <div class="acc-kv"><span>30d Uptime</span><span>${uptime}</span></div>
              <button class="btn-ghost acc-detail-btn" data-source-id="${src.id}">View Full Details &rarr;</button>
            </div>
          </details>`;
      })
      .join("");
  }
}

function renderOverviewTelemetry() {
  const box = document.getElementById("overviewTelemetryChart");
  const slots = new Array(30).fill(null);

  if (state.history && state.history.sources) {
    document.getElementById("historyMonthLabel").textContent = `MONTH // ${state.history.month}`;
    const dayMap = {};
    Object.values(state.history.sources).forEach((days) => {
      Object.entries(days).forEach(([day, rec]) => {
        if (!dayMap[day]) dayMap[day] = { ok: 0, issues: 0, down: 0, restricted: 0 };
        dayMap[day].ok += rec.success;
        dayMap[day].issues += rec.issues;
        dayMap[day].down += rec.unavailable;
        dayMap[day].restricted += rec.restricted;
      });
    });
    const sortedDays = Object.entries(dayMap).sort(([a], [b]) => a.localeCompare(b)).slice(-30);
    sortedDays.forEach(([day, agg], i) => {
      let cls = "online";
      if (agg.down > 0) cls = "unavailable";
      else if (agg.issues > 0) cls = "issues";
      else if (agg.restricted > 0 && agg.ok === 0) cls = "restricted";
      slots[30 - sortedDays.length + i] = { day, cls };
    });
  }

  const barsHtml = slots
    .map((slot) =>
      slot
        ? `<div class="t-bar ${slot.cls}" title="${slot.day}: ${slot.cls.toUpperCase()}"></div>`
        : `<div class="t-bar" title="No observation recorded"></div>`
    )
    .join("");

  box.innerHTML = `
    <div class="bar-strip">${barsHtml}</div>
    <div class="bar-caption">
      <span>T-30 DAYS</span>
      <span>${state.history ? "LIVE ROLLUP DATA" : "HOLLOW SLOTS = NO DATA COLLECTED YET"}</span>
      <span>TODAY</span>
    </div>`;
}

function renderWatchDeskAndArrays() {
  const openCount = state.incidents.filter((i) => i.status === "open").length;
  document.getElementById("openIncidentsBadge").textContent = `${String(openCount).padStart(2, "0")} OPEN`;

  const watchEl = document.getElementById("watchDeskList");
  if (!state.incidents.length) {
    watchEl.innerHTML = `
      <div class="watch-item">
        <div>
          <div class="watch-item-title">ALL CLEAR // STANDBY</div>
          <div class="watch-item-sub">No multi-check incidents recorded</div>
        </div>
        <span class="status-chip chip-neutral">00</span>
      </div>`;
  } else {
    watchEl.innerHTML = state.incidents.slice(0, 3).map((inc) => `
      <div class="watch-item">
        <div>
          <div class="watch-item-title">${inc.source_id}</div>
          <div class="watch-item-sub">Detected ${formatTime(inc.first_detected_at)}</div>
        </div>
        <span class="status-chip ${inc.status === "open" ? "chip-unavailable" : "chip-online"}">${inc.status.toUpperCase()}</span>
      </div>`).join("");
  }

  const counts = {};
  state.sources.forEach((s) => {
    counts[s.agency_abbr] = (counts[s.agency_abbr] || 0) + 1;
  });
  const total = state.sources.length || 1;
  document.getElementById("agencyArray").innerHTML = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([abbr, count]) => {
      const pct = Math.round((count / total) * 100);
      return `
        <div>
          <div class="array-row-head"><span>${abbr}</span><span>${count} ENDPOINTS (${pct}%)</span></div>
          <div class="array-track"><div class="array-fill" style="width:${pct}%"></div></div>
        </div>`;
    })
    .join("");

  document.getElementById("statSourcesCount").textContent = state.sources.length;
  const viewAllBtn = document.getElementById("viewAllSourcesBtn");
  if (viewAllBtn) viewAllBtn.textContent = `View all (${state.sources.length})`;
  document.getElementById("statDatasetsCount").textContent = state.datasets.length;

  document.getElementById("overviewDatasetList").innerHTML = state.datasets
    .map(
      (ds) => `
      <div class="watch-item">
        <div>
          <div class="watch-item-title">${ds.title}</div>
          <div class="watch-item-sub">${ds.agency_abbr} // CADENCE: ${ds.expected_frequency.toUpperCase()}</div>
        </div>
        ${chipHtml(ds.freshness_status)}
      </div>`
    )
    .join("");
}

function populateFilters() {
  const agencies = [...new Set(state.sources.map((s) => s.agency_abbr))].sort();
  const categories = [...new Set(state.sources.map((s) => s.category))].sort();

  const agencySel = document.getElementById("agencyFilter");
  agencies.forEach((a) => agencySel.insertAdjacentHTML("beforeend", `<option value="${a}">AGENCY: ${a}</option>`));

  const catSel = document.getElementById("categoryFilter");
  categories.forEach((c) =>
    catSel.insertAdjacentHTML("beforeend", `<option value="${c}">TYPE: ${CATEGORY_LABELS[c] || c}</option>`)
  );

  const statusSel = document.getElementById("statusFilter");
  Object.entries(STATUS_META).forEach(([k, v]) =>
    statusSel.insertAdjacentHTML("beforeend", `<option value="${k}">STATUS: ${v.label}</option>`)
  );
}

function renderDirectory() {
  const q = document.getElementById("searchInput").value.trim().toLowerCase();
  const agency = document.getElementById("agencyFilter").value;
  const category = document.getElementById("categoryFilter").value;
  const statusFilter = document.getElementById("statusFilter").value;

  const filtered = state.sources.filter((src) => {
    const st = state.status.sources[src.id]?.status || "not_yet_checked";
    const matchQ =
      !q ||
      src.name.toLowerCase().includes(q) ||
      src.agency.toLowerCase().includes(q) ||
      src.url.toLowerCase().includes(q);
    return (
      matchQ &&
      (agency === "all" || src.agency_abbr === agency) &&
      (category === "all" || src.category === category) &&
      (statusFilter === "all" || st === statusFilter)
    );
  });

  const grid = document.getElementById("directoryGrid");
  if (!filtered.length) {
    grid.innerHTML = `<div class="empty-state"><h3>NO MATCHING ENDPOINTS</h3><p>Adjust search or filter parameters.</p></div>`;
    return;
  }

  grid.innerHTML = filtered
    .map((src) => {
      const st = state.status.sources[src.id] || { status: "not_yet_checked", last_checked_at: null };
      return `
        <article class="source-card" data-source-id="${src.id}">
          <div class="source-card-top">
            <span class="eyebrow">${src.agency_abbr} // ${CATEGORY_LABELS[src.category] || src.category}</span>
            ${chipHtml(st.status)}
          </div>
          <strong>${src.name}</strong>
          <div class="source-url">${src.url}</div>
          <div class="source-meta">
            <span>METHOD: ${src.check_method}</span>
            <span>CHECK: ${formatTime(st.last_checked_at)}</span>
          </div>
        </article>`;
    })
    .join("");
}

function renderHistory() {
  const container = document.getElementById("historyContainer");
  if (!state.history || !Object.keys(state.history.sources || {}).length) return;

  const rows = state.sources
    .map((src) => {
      const days = state.history.sources[src.id] || {};
      const entries = Object.entries(days).sort(([a], [b]) => a.localeCompare(b));
      if (!entries.length) return "";
      const bars = entries
        .map(([day, rec]) => {
          let cls = "day-online";
          if (rec.unavailable > 0) cls = "day-unavailable";
          else if (rec.issues > 0) cls = "day-issues";
          else if (rec.restricted > 0 && rec.success === 0) cls = "day-restricted";
          const title = `${day}: ${rec.success}/${rec.checks} ok` + (rec.avg_latency_ms ? ` (${rec.avg_latency_ms}ms avg)` : "");
          return `<span class="history-bar ${cls}" title="${title}"></span>`;
        })
        .join("");
      const st = state.status.sources[src.id] || {};
      const uptime = st.uptime_30d_pct !== null && st.uptime_30d_pct !== undefined ? `${st.uptime_30d_pct}%` : "N/A";
      return `
        <div class="history-row">
          <div class="history-row-head">
            <div>
              <strong>${src.name}</strong>
              <div class="eyebrow">${src.agency_abbr} // MONTH ${state.history.month}</div>
            </div>
            <span class="eyebrow" style="color:var(--accent-mint)">30D UPTIME: ${uptime}</span>
          </div>
          <div class="history-bars">${bars}</div>
        </div>`;
    })
    .filter(Boolean)
    .join("");

  if (rows) container.innerHTML = `<div class="history-list">${rows}</div>`;
}

function renderIncidents() {
  const el = document.getElementById("incidentsContainer");
  if (!state.incidents.length) {
    el.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">✓</div>
        <h3>NO VERIFIED INCIDENTS RECORDED</h3>
        <p>Incidents are logged only after 2+ consecutive failed checks confirm an availability disruption.</p>
      </div>`;
    return;
  }

  el.innerHTML = state.incidents
    .map((inc) => {
      const src = state.sources.find((s) => s.id === inc.source_id);
      const name = src ? src.name : inc.source_id;
      const isResolved = inc.status === "resolved";
      const codes = (inc.evidence?.observed_http_statuses || []).join(", ") || "TIMEOUT / NETWORK";
      return `
        <article class="incident-card ${isResolved ? "resolved" : ""}">
          <div class="source-card-top">
            <strong>${name}</strong>
            ${chipHtml(isResolved ? "online" : "unavailable")}
          </div>
          <div class="watch-item-sub" style="margin-top:0.4rem;">
            FIRST DETECTED: ${formatTime(inc.first_detected_at)} // LAST OBSERVED: ${formatTime(inc.last_observed_at)}
            ${inc.resolved_at ? ` // RESOLVED: ${formatTime(inc.resolved_at)}` : ""}
          </div>
          <div class="watch-item-sub" style="margin-top:0.25rem;">
            PEAK FAILURES: ${inc.consecutive_failures_peak} // HTTP CODES: <code>${codes}</code>
          </div>
        </article>`;
    })
    .join("");
}

function openSourceDetail(sourceId, push = true) {
  const src = state.sources.find((s) => s.id === sourceId);
  if (!src) return;
  const st = state.status.sources[src.id] || {};

  document.getElementById("modalAgency").textContent = `${src.agency} (${src.agency_abbr})`;
  document.getElementById("modalTitle").textContent = src.name;
  document.getElementById("modalBody").innerHTML = `
    <div class="detail-row"><span>Status</span><span>${chipHtml(st.status)}</span></div>
    <div class="detail-row"><span>Official URL</span><a href="${src.url}" target="_blank" rel="noopener noreferrer">${src.url}</a></div>
    <div class="detail-row"><span>Category</span><span>${CATEGORY_LABELS[src.category] || src.category}</span></div>
    <div class="detail-row"><span>Check Method</span><code>${src.check_method}</code></div>
    <div class="detail-row"><span>HTTP / Evidence</span><code>${st.http_status ?? "—"}${st.last_error ? ` (${st.last_error})` : ""}</code></div>
    <div class="detail-row"><span>Last Checked</span><span>${formatTime(st.last_checked_at)}</span></div>
    <div class="detail-row"><span>Last Successful</span><span>${formatTime(st.last_successful_at)}</span></div>
    <div class="detail-row"><span>30D Availability</span><span>${st.uptime_30d_pct !== null && st.uptime_30d_pct !== undefined ? `${st.uptime_30d_pct}% (${st.uptime_30d_sample_count ?? 0} valid checks)` : "Pending observations"}</span></div>
    <div class="detail-row"><span>Runner Scope</span><span>Checked from GitHub Actions (cloud IP). Geo-blocks or WAFs may differ from PH browsers.</span></div>
    <div class="detail-row"><span>Notes</span><span>${src.notes}</span></div>
  `;
  document.getElementById("detailModal").hidden = false;

  if (push) {
    const detailPath = `/source/${sourceId}`;
    if (window.location.pathname !== detailPath) {
      window.history.pushState({ view: state.activeView, sourceId }, "", detailPath);
    }
  }
}

function closeSourceDetail(push = true) {
  document.getElementById("detailModal").hidden = true;
  if (push && window.location.pathname.startsWith("/source/")) {
    window.history.pushState({ view: state.activeView }, "", VIEW_PATHS[state.activeView] || "/overview");
  }
}

function applyRouteFromUrl() {
  const path = window.location.pathname.replace(/\/+$/, "") || "/";
  if (path.startsWith("/source/")) {
    const sourceId = path.slice("/source/".length);
    switchView(state.activeView || "directory", false);
    openSourceDetail(sourceId, false);
    return;
  }
  closeSourceDetail(false);
  const viewName = PATH_VIEWS[path] || "overview";
  switchView(viewName, false);
}

async function init() {
  updateClock();
  setInterval(updateClock, 1000);

  const [sourcesRes, statusRes, incidentsRes, datasetsRes, historyIndexRes] = await Promise.all([
    fetch("/data/sources.json").then((r) => r.json()),
    fetch("/data/status.json").then((r) => r.json()),
    fetch("/data/incidents.json").then((r) => r.json()),
    fetch("/data/datasets.json").then((r) => r.json()),
    fetch("/data/history/index.json").then((r) => r.json()).catch(() => ({ months: [] })),
  ]);

  state.sources = sourcesRes.sources;
  state.status = statusRes;
  state.incidents = incidentsRes.incidents;
  state.datasets = datasetsRes.datasets;

  if (historyIndexRes.months && historyIndexRes.months.length > 0) {
    state.history = await fetch(`/data/history/daily-${historyIndexRes.months[0]}.json`)
      .then((r) => r.json())
      .catch(() => null);
  }

  if (state.status.monitoring_active && state.status.generated_at) {
    document.getElementById("sysPill").classList.add("live");
    document.getElementById("sysPillText").textContent = "Monitoring Active";
    document.getElementById("lastSyncTag").textContent = `Last run: ${formatTime(state.status.generated_at)}`;
    const strip = document.getElementById("alertStrip");
    strip.classList.remove("standby");
    strip.classList.add("active");
    document.getElementById("alertTitle").textContent = "Monitoring Active";
    document.getElementById("lastUpdatedText").textContent = `Last completed check: ${formatTime(state.status.generated_at)}`;
  }

  populateFilters();
  renderKpis();
  renderOverviewMatrix();
  renderOverviewTelemetry();
  renderWatchDeskAndArrays();
  renderDirectory();
  renderHistory();
  renderIncidents();
  applyRouteFromUrl();

  window.addEventListener("popstate", applyRouteFromUrl);

  document.querySelectorAll(".nav-btn").forEach((btn) =>
    btn.addEventListener("click", () => switchView(btn.dataset.view))
  );
  document.querySelectorAll("[data-jump]").forEach((btn) =>
    btn.addEventListener("click", () => switchView(btn.dataset.jump))
  );
  document.getElementById("navToggle").addEventListener("click", () => {
    document.getElementById("topbarRight").classList.toggle("open");
  });

  ["searchInput", "agencyFilter", "categoryFilter", "statusFilter"].forEach((id) => {
    document.getElementById(id).addEventListener("input", renderDirectory);
    document.getElementById(id).addEventListener("change", renderDirectory);
  });

  document.body.addEventListener("click", (e) => {
    const target = e.target.closest("[data-source-id]");
    if (target) openSourceDetail(target.dataset.sourceId);
  });

  document.getElementById("closeModal").addEventListener("click", () => closeSourceDetail(true));
  document.getElementById("detailModal").addEventListener("click", (e) => {
    if (e.target.id === "detailModal") closeSourceDetail(true);
  });
}

init();
