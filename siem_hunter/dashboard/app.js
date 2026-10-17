/* SIEM Hunter dashboard. Log data is attacker-controlled, so every dynamic value goes through esc(). */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } },
  };
  const fmtTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "-");
  const fmtHM = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const sevOrder = ["critical", "high", "medium", "low", "info"];
  const sevChip = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
  const riskBar = (n) => {
    const c = n >= 80 ? "c" : n >= 60 ? "h" : n >= 40 ? "m" : "";
    return `<div class="risk"><span>${esc(n)}</span><div class="bar"><i class="${c}" style="width:${Math.max(0, Math.min(100, +n || 0))}%"></i></div></div>`;
  };
  const label = (s) => String(s || "").replace(/_/g, " ");

  let tab = "overview";
  let alerts = [];
  let openId = null;
  let busy = false;

  // ---------------------------------------------------------------- api
  async function api(path, opts = {}) {
    const headers = { "Content-Type": "application/json" };
    const key = store.get("siem_key");
    if (key) headers["X-API-Key"] = key;
    const res = await fetch(path, { ...opts, headers });
    if (res.status === 401) { const e = new Error("API key required - click Key to set it"); e.auth = true; throw e; }
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch (e) { /* ignore */ }
      throw new Error(detail);
    }
    return res.json();
  }
  function toast(msg, err = false) {
    const t = $("#toast");
    t.textContent = msg; t.className = "toast" + (err ? " err" : ""); t.hidden = false;
    clearTimeout(toast.h); toast.h = setTimeout(() => (t.hidden = true), 4200);
  }
  const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };

  // ---------------------------------------------------------------- overview
  function renderVolume(series) {
    if (!series.length) return '<div class="empty">No events yet. Load the demo or POST logs to /api/ingest.</div>';
    const W = 640, H = 170, pl = 34, pb = 20, pt = 6;
    const max = Math.max(...series.map((s) => s.count), 1);
    const bw = (W - pl) / series.length;
    let g = "";
    [0, 0.5, 1].forEach((f) => {
      const y = pt + (H - pb - pt) * (1 - f);
      g += `<line x1="${pl}" x2="${W}" y1="${y}" y2="${y}" stroke="currentColor" opacity=".12"/><text x="${pl - 5}" y="${y + 3}" text-anchor="end">${Math.round(max * f)}</text>`;
    });
    series.forEach((s, i) => {
      const x = pl + i * bw, h = (H - pb - pt) * (s.count / max), hf = (H - pb - pt) * (s.failures / max);
      g += `<rect x="${x + 1}" y="${H - pb - h}" width="${Math.max(bw - 2, 1)}" height="${h}" rx="2" fill="var(--accent)" opacity=".75"><title>${esc(fmtHM(s.ts))}: ${s.count} events, ${s.failures} failed logins</title></rect>`;
      if (s.failures) g += `<rect x="${x + 1}" y="${H - pb - hf}" width="${Math.max(bw - 2, 1)}" height="${hf}" rx="2" fill="var(--crit)"/>`;
      if (i % Math.ceil(series.length / 8) === 0) g += `<text x="${x}" y="${H - 5}">${esc(fmtHM(s.ts))}</text>`;
    });
    return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Event volume over time">${g}</svg>
      <div class="legend"><span><i style="background:var(--accent)"></i>All events</span><span><i style="background:var(--crit)"></i>Failed logins</span></div>`;
  }
  function renderBars(items, labelKey, valueKey, fmtLabel = (x) => x) {
    if (!items.length) return '<div class="empty">Nothing to show</div>';
    const max = Math.max(...items.map((i) => i[valueKey]), 1);
    return `<div class="bars">${items.map((i) => `<div class="row"><span class="mono" title="${esc(i[labelKey])}">${esc(fmtLabel(i[labelKey]))}</span><div class="track"><i style="width:${(i[valueKey] / max) * 100}%"></i></div><span>${esc(i[valueKey])}</span></div>`).join("")}</div>`;
  }
  const TECH_NAMES = {};
  async function loadOverview() {
    const s = await api("/api/stats");
    const sev = s.alerts_by_severity || {};
    const open = Object.entries(s.alerts_by_status || {}).filter(([k]) => !["resolved", "false_positive"].includes(k)).reduce((a, [, v]) => a + v, 0);
    $("#kpis").innerHTML = [
      ["Events ingested", s.total_events.toLocaleString(), ""],
      ["Open alerts", open, ""],
      ["Critical", sev.critical || 0, "crit"],
      ["High", sev.high || 0, "high"],
      ["Awaiting approval", s.pending_actions, s.pending_actions ? "high" : ""],
      ["Latest event", s.latest_event_ts ? fmtTime(s.latest_event_ts) : "-", ""],
    ].map(([l, v, c]) => `<div class="kpi ${c}"><div class="v" style="${l === "Latest event" ? "font-size:17px;padding:7px 0" : ""}">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");
    $("#chartVolume").innerHTML = renderVolume(s.series);
    $("#chartSev").innerHTML = renderBars(sevOrder.filter((k) => sev[k]).map((k) => ({ k, c: sev[k] })), "k", "c");
    $("#topIps").innerHTML = renderBars(s.top_ips, "ip", "count");
    const techs = Object.entries(s.techniques).sort((a, b) => b[1] - a[1]);
    $("#techs").innerHTML = techs.length ? techs.map(([t, n]) => `<span class="tech mono">${esc(t)} <small>x${esc(n)}</small></span>`).join("") : '<div class="empty">No techniques observed</div>';
    const top = await api("/api/alerts?limit=6");
    $("#topAlerts").innerHTML = top.length ? top.map((a) => `<div class="list-item click" data-open="${esc(a.id)}"><span>${sevChip(a.severity)} ${esc(a.title)}</span><span class="muted">${esc(a.risk_score)}</span></div>`).join("") : '<div class="empty">No alerts</div>';
    $("#pendingBadge").hidden = !s.pending_actions;
    $("#pendingBadge").textContent = s.pending_actions;
    $("#banner").hidden = s.total_events > 0;
    if (!s.total_events) $("#banner").innerHTML = "<strong>No data yet.</strong> Click <em>Load demo attack</em> to generate a day of normal traffic plus a multi-stage intrusion (SSH brute force &rarr; account takeover &rarr; persistence &rarr; lateral movement, port scan, web attack, password spray, ransomware prep and C2 beaconing) and watch the platform detect, investigate and recommend responses.";
  }

  // ---------------------------------------------------------------- alerts
  function renderAlertTable() {
    const text = $("#fText").value.trim().toLowerCase();
    const rows = alerts.filter((a) => !text || [a.title, a.src_ip, a.user, a.host, a.rule_id, a.description].join(" ").toLowerCase().includes(text));
    $("#alertCount").textContent = `${rows.length} alert${rows.length === 1 ? "" : "s"}`;
    $("#alertTable").innerHTML = rows.length
      ? `<thead><tr><th>Severity</th><th>Risk</th><th>Alert</th><th>Source / entity</th><th>Verdict</th><th>Status</th><th>Last seen</th><th>Events</th></tr></thead><tbody>${rows.map((a) => `
        <tr data-id="${esc(a.id)}" tabindex="0"><td>${sevChip(a.severity)}</td><td>${riskBar(a.risk_score)}</td>
        <td class="wrap"><strong>${esc(a.title)}</strong><br><small>${esc((a.techniques || []).join(", "))}</small></td>
        <td class="mono">${esc(a.src_ip || a.user || a.host || "-")}</td>
        <td><span class="chip verdict-${esc(a.verdict)}">${esc(label(a.verdict) || "-")}</span></td>
        <td><span class="chip st-${esc(a.status)}">${esc(label(a.status))}</span></td>
        <td>${esc(fmtTime(a.last_seen))}</td><td>${esc(a.event_count)}</td></tr>`).join("")}</tbody>`
      : '<tbody><tr><td class="empty">No alerts match.</td></tr></tbody>';
  }
  async function loadAlerts() {
    const q = new URLSearchParams({ limit: "500" });
    if ($("#fSev").value) q.set("severity", $("#fSev").value);
    if ($("#fStatus").value) q.set("status", $("#fStatus").value);
    alerts = await api("/api/alerts?" + q);
    renderAlertTable();
  }

  // ---------------------------------------------------------------- alert drawer
  function actionCard(a) {
    const btns = a.status === "pending"
      ? `<button class="btn small good" data-act="approve" data-aid="${esc(a.id)}">Approve &amp; execute</button><button class="btn small danger" data-act="reject" data-aid="${esc(a.id)}">Reject</button>`
      : a.status === "executed" ? `<button class="btn small" data-act="revert" data-aid="${esc(a.id)}">Revert</button>` : "";
    return `<div class="act"><div class="row"><span><strong>${esc(label(a.type))}</strong> <span class="mono">${esc(a.target)}</span> ${sevChip(a.priority === "high" ? "high" : a.priority === "medium" ? "medium" : "low")}</span>
      <span><span class="chip st-${esc(a.status)}">${esc(label(a.status))}</span> ${btns}</span></div>
      <div class="muted">${esc(a.reason)}</div>${a.result ? `<div class="mono muted">${esc(a.result)}</div>` : ""}</div>`;
  }
  async function openAlert(id, keepScroll = false) {
    openId = id;
    const d = await api("/api/alerts/" + id);
    const a = d.alert, inv = d.investigation;
    const scroll = $("#drawer").scrollTop;
    let html = `<h1>${esc(a.title)}</h1><div class="meta">${sevChip(a.severity)}<span class="chip verdict-${esc(a.verdict)}">${esc(label(a.verdict) || "not investigated")}</span><span class="chip st-${esc(a.status)}">${esc(label(a.status))}</span>
      <span class="muted">Risk</span>${riskBar(a.risk_score)}<span class="muted">#${esc(a.id)} &middot; ${esc(a.rule_id)} &middot; ${esc(fmtTime(a.first_seen))} &rarr; ${esc(fmtTime(a.last_seen))}</span></div>`;
    if (inv) {
      html += `<h3>Investigation summary</h3><div class="narr">${esc(inv.explanation ? inv.explanation.narrative : inv.summary)}<small>${inv.explanation && inv.explanation.source === "llm" ? "Written by an LLM from structured findings" : "Generated from structured findings"} &middot; actions below come from deterministic rules only</small></div>`;
      html += `<h3>Findings</h3>${inv.findings.map((f) => `<div class="finding">${sevChip(f.level)}<span>${esc(f.text)}</span></div>`).join("") || '<div class="muted">None</div>'}`;
      if (inv.kill_chain.length) html += `<h3>ATT&amp;CK kill chain</h3><div class="chain">${inv.kill_chain.map((c) => `<div class="stage"><b>${esc(c.tactic)}</b>${c.techniques.map((t) => `<div><span class="mono">${esc(t.id)}</span> ${esc(t.name)}</div>`).join("")}</div>`).join("")}</div>`;
      if (inv.timeline.length) html += `<h3>Timeline</h3><div class="timeline">${inv.timeline.map((t) => `<div class="t ${esc(t.kind)}"><span class="mono muted">${esc(fmtTime(t.ts))}</span> <span class="chip">${esc(t.host)}</span><br>${esc(t.text)}</div>`).join("")}</div>`;
      if (inv.related_alerts.length) html += `<h3>Correlated alerts</h3>${inv.related_alerts.map((r) => `<div class="list-item click" data-open="${esc(r.id)}"><span>${sevChip(r.severity)} ${esc(r.title)}</span><span class="muted">#${esc(r.id)}</span></div>`).join("")}`;
    }
    html += `<h3>Response</h3>${d.actions.length ? d.actions.map(actionCard).join("") : '<div class="muted">No actions recommended.</div>'}`;
    html += `<h3>Analyst</h3><div class="meta"><button class="btn small" data-reinv="${esc(a.id)}">Re-run investigation</button>
      ${["resolved", "false_positive"].map((s) => `<button class="btn small" data-status="${s}" data-aid="${esc(a.id)}">Mark ${esc(label(s))}</button>`).join("")}</div>`;
    html += `<h3>Evidence (${esc(a.event_count)} events${d.events.length < a.event_count ? ", first " + d.events.length : ""})</h3><div class="tablewrap"><table><thead><tr><th>Time</th><th>Host</th><th>Detail</th><th>IP</th><th>User</th></tr></thead><tbody>${d.events.slice(0, 80).map((e) => `<tr><td>${esc(fmtTime(e.ts))}</td><td>${esc(e.host)}</td><td class="wrap mono">${esc((e.command_line || e.message || e.raw).slice(0, 200))}</td><td class="mono">${esc(e.src_ip || "")}</td><td>${esc(e.user || "")}</td></tr>`).join("")}</tbody></table></div>`;
    $("#drawerBody").innerHTML = html;
    $("#drawer").hidden = false; $("#scrim").hidden = false;
    if (keepScroll) $("#drawer").scrollTop = scroll;
  }
  function closeDrawer() { openId = null; $("#drawer").hidden = true; $("#scrim").hidden = true; }

  // ---------------------------------------------------------------- search / response / audit
  async function runSearch() {
    const rows = await api("/api/events/search?limit=300&q=" + encodeURIComponent($("#q").value));
    $("#searchTable").innerHTML = rows.length
      ? `<thead><tr><th>Time</th><th>Host</th><th>Category</th><th>User</th><th>Source IP</th><th>Detail</th></tr></thead><tbody>${rows.map((e) => `<tr><td>${esc(fmtTime(e.ts))}</td><td>${esc(e.host)}</td><td><span class="chip">${esc(label(e.category))}</span></td><td>${esc(e.user || "")}</td><td class="mono">${esc(e.src_ip || "")}</td><td class="wrap mono">${esc((e.command_line || e.message || e.raw).slice(0, 220))}</td></tr>`).join("")}</tbody>`
      : '<tbody><tr><td class="empty">No matching events.</td></tr></tbody>';
  }
  async function loadResponse() {
    const [acts, enf] = await Promise.all([api("/api/actions?limit=300"), api("/api/enforcement")]);
    const pend = acts.filter((a) => a.status === "pending");
    $("#pendingList").innerHTML = pend.length ? pend.map(actionCard).join("") : '<div class="empty">Nothing waiting for approval.</div>';
    $("#enforceList").innerHTML = enf.length ? enf.map((e) => `<div class="list-item"><span><strong>${esc(label(e.kind))}</strong> <span class="mono">${esc(e.target)}</span></span><span class="muted">${esc(fmtTime(e.created_at))}</span></div>`).join("") : '<div class="empty">No active enforcement.</div>';
    $("#actionTable").innerHTML = acts.length ? `<thead><tr><th>#</th><th>Alert</th><th>Action</th><th>Target</th><th>Status</th><th>Result / reason</th></tr></thead><tbody>${acts.map((a) => `<tr data-id="${esc(a.alert_id)}"><td>${esc(a.id)}</td><td>#${esc(a.alert_id)}</td><td>${esc(label(a.type))}</td><td class="mono">${esc(a.target)}</td><td><span class="chip st-${esc(a.status)}">${esc(label(a.status))}</span></td><td class="wrap">${esc(a.result || a.reason)}</td></tr>`).join("")}</tbody>` : '<tbody><tr><td class="empty">No actions yet.</td></tr></tbody>';
  }
  async function loadAudit() {
    const rows = await api("/api/audit?limit=300");
    $("#auditTable").innerHTML = rows.length ? `<thead><tr><th>Time</th><th>Actor</th><th>Event</th><th>Detail</th></tr></thead><tbody>${rows.map((r) => `<tr><td>${esc(fmtTime(r.ts))}</td><td>${esc(r.actor)}</td><td>${esc(label(r.event))}</td><td class="mono wrap">${esc(r.detail)}</td></tr>`).join("")}</tbody>` : '<tbody><tr><td class="empty">Audit log is empty.</td></tr></tbody>';
  }

  // ---------------------------------------------------------------- wiring
  async function refresh() {
    if (busy) return;
    busy = true;
    try {
      if (tab === "overview") await loadOverview();
      else if (tab === "alerts") await loadAlerts();
      else if (tab === "response") await loadResponse();
      else if (tab === "audit") await loadAudit();
      if (openId !== null && !$("#drawer").hidden) await openAlert(openId, true);
      const s = await api("/api/stats");
      $("#pendingBadge").hidden = !s.pending_actions; $("#pendingBadge").textContent = s.pending_actions;
    } catch (e) {
      if (e.auth) { $("#banner").hidden = false; $("#banner").textContent = e.message; } else toast(e.message, true);
    } finally { busy = false; }
  }
  function showTab(name) {
    tab = name;
    $$("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    $$(".tab").forEach((t) => (t.hidden = t.id !== "tab-" + name));
    refresh();
  }

  document.addEventListener("click", guard(async (ev) => {
    const t = ev.target.closest("button, [data-open], tr[data-id]");
    if (!t) return;
    if (t.dataset.tab) return showTab(t.dataset.tab);
    if (t.dataset.open) return openAlert(+t.dataset.open);
    if (t.matches("tr[data-id]")) return openAlert(+t.dataset.id);
    if (t.dataset.act) {
      t.disabled = true;
      await api(`/api/actions/${t.dataset.aid}/${t.dataset.act}`, { method: "POST" });
      toast("Action " + t.dataset.act + "d");
      return refresh();
    }
    if (t.dataset.status) { await api(`/api/alerts/${t.dataset.aid}/status`, { method: "POST", body: JSON.stringify({ status: t.dataset.status }) }); toast("Alert updated"); return refresh(); }
    if (t.dataset.reinv) { await api(`/api/alerts/${t.dataset.reinv}/investigate`, { method: "POST" }); toast("Investigation re-run"); return refresh(); }
    if (t.id === "drawerClose") return closeDrawer();
    if (t.id === "btnDemo") {
      t.disabled = true; t.textContent = "Generating...";
      try {
        const r = await api("/api/demo/load", { method: "POST", body: JSON.stringify({ reset: true }) });
        toast(`Loaded ${r.stored.toLocaleString()} events, ${r.alerts_created} alerts raised`);
        showTab("overview");
      } finally { t.disabled = false; t.textContent = "Load demo attack"; }
      return;
    }
    if (t.id === "btnKey") { const k = prompt("API key (leave empty to clear):", store.get("siem_key") || ""); if (k !== null) { store.set("siem_key", k.trim()); refresh(); } }
  }));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
    if ((e.key === "Enter" || e.key === " ") && e.target.matches("tr[data-id]")) { e.preventDefault(); guard(openAlert)(+e.target.dataset.id); }
  });
  $("#scrim").addEventListener("click", closeDrawer);
  $("#fSev").addEventListener("change", guard(loadAlerts));
  $("#fStatus").addEventListener("change", guard(loadAlerts));
  $("#fText").addEventListener("input", renderAlertTable);
  $("#searchForm").addEventListener("submit", guard(async (e) => { e.preventDefault(); await runSearch(); }));
  setInterval(() => { if ($("#autoRefresh").checked && tab !== "search") refresh(); }, 5000);
  refresh();
})();
