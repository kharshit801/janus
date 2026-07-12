// ============================================================
// Janus — Fusion Risk Console (client)
// ============================================================
const $ = (s) => document.querySelector(s);
const API_KEY = "demo-key-finspark-2026";
const api = (p, o = {}) => {
  o.headers = { ...o.headers, "X-API-Key": API_KEY };
  return fetch(p, o).then((r) => r.json());
};

const C = {
  cyber: "#2fb6cf", txn: "#e0973a", fused: "#6f7bff", quantum: "#a374ff",
  crit: "#ff5470", high: "#ff9f45", med: "#f2c744", low: "#35d09a",
  muted: "#8792a6", grid: "rgba(255,255,255,0.06)",
};
const bandColor = (b) => ({ CRITICAL: C.crit, HIGH: C.high, MEDIUM: C.med, LOW: C.low }[b] || C.muted);

let ALERTS = [];        // full alert set
let charts = {};
let filterBand = "";
let selectedIndex = -1; // keyboard-selected triage row

// ---------------- boot ----------------
(async function init() {
  const [summary, metrics, alertsResp, quantum] = await Promise.all([
    api("/api/summary"), api("/api/metrics"),
    api("/api/alerts?min_score=0&limit=800"), api("/api/quantum"),
  ]);
  ALERTS = alertsResp.alerts;

  renderStats(summary);
  renderPipeline(metrics, quantum);
  renderQueue();
  renderMetricsChart(metrics);
  renderThreatChart();
  renderQuantum(quantum);
  wireUI();
  // data is in — drop the skeleton class to reveal real content
  document.body.classList.remove("loading");
  const openId = new URLSearchParams(location.search).get("open");
  if (openId) openCase(openId);
})();

// ---------------- command-bar stats ----------------
function renderStats(s) {
  const chips = [
    { v: s.total_sessions, l: "Sessions" },
    { v: s.true_threats, l: "Threats" },
    { v: (s.precision * 100).toFixed(0) + "%", l: "Precision", cls: "good" },
    { v: s.false_positives, l: "False pos", cls: s.false_positives === 0 ? "good" : "" },
    { v: s.pqc_readiness_pct + "%", l: "PQC ready", cls: s.pqc_readiness_pct < 50 ? "warn" : "" },
  ];
  $("#cbStats").innerHTML = chips
    .map((c) => `<div class="stat ${c.cls || ""}"><b>${c.v}</b><span>${c.l}</span></div>`)
    .join("");
}

// ---------------- fusion pipeline (the product, made visible) ----------------
function renderPipeline(m, q) {
  const cyberFlagged = m.cyber_only.true_positives + m.cyber_only.false_positives;
  const txnFlagged = m.fraud_only.true_positives + m.fraud_only.false_positives;
  const critical = ALERTS.filter((a) => a.risk_band === "CRITICAL").length;
  const vuln = q.summary.quantum_vulnerable_sessions;

  const source = (x, y, accent, title, sub, big) => `
    <rect x="${x}" y="${y}" width="196" height="66" rx="9" fill="var(--ink-750)" stroke="${accent}" stroke-opacity="0.55"/>
    <rect x="${x}" y="${y}" width="3.5" height="66" rx="2" fill="${accent}"/>
    <text class="node-label" x="${x + 16}" y="${y + 25}">${title}</text>
    <text class="node-sub" x="${x + 16}" y="${y + 44}">${sub}</text>
    <text class="node-big" x="${x + 180}" y="${y + 42}" text-anchor="end" fill="${accent}">${big}</text>`;

  const flow = (d, color) => `
    <path d="${d}" fill="none" stroke="${color}" stroke-opacity="0.16" stroke-width="6"/>
    <path class="flow" d="${d}" fill="none" stroke="${color}" stroke-width="2.2" stroke-opacity="0.95"/>`;

  const hex = "516,108 568,108 596,150 568,192 516,192 488,150";

  $("#pipe").innerHTML = `
    ${source(34, 52, C.cyber, "CYBER TELEMETRY", "auth · device · geo", cyberFlagged)}
    ${source(34, 182, C.txn, "TRANSACTIONS", "amount · payee", txnFlagged)}

    ${flow("M230,85 C330,85 380,120 486,138", C.cyber)}
    ${flow("M230,215 C330,215 380,180 486,162", C.txn)}
    ${flow("M596,150 C688,150 726,92 812,90", C.fused)}
    ${flow("M596,150 C688,150 726,210 812,214", C.quantum)}

    <polygon points="${hex}" fill="var(--ink-750)" stroke="var(--fused)" stroke-opacity="0.7"/>
    <polygon points="${hex}" fill="none" stroke="var(--fused)" stroke-opacity="0.18" stroke-width="6"/>
    <text class="node-label" x="542" y="146" text-anchor="middle" fill="var(--fused)">FUSION</text>
    <text class="node-sub" x="542" y="163" text-anchor="middle">correlate</text>

    <rect x="812" y="57" width="196" height="66" rx="9" fill="var(--ink-750)" stroke="${bandColor("CRITICAL")}" stroke-opacity="0.5"/>
    <text class="node-label" x="828" y="82">FUSED VERDICT</text>
    <text class="node-sub" x="828" y="101">critical caseload</text>
    <text class="node-big" x="992" y="99" text-anchor="end" fill="${C.crit}">${critical}</text>

    <rect x="812" y="181" width="196" height="66" rx="9" fill="var(--ink-750)" stroke="${C.quantum}" stroke-opacity="0.5"/>
    <text class="node-label" x="828" y="206">QUANTUM HORIZON</text>
    <text class="node-sub" x="828" y="225">HNDL exposed</text>
    <text class="node-big" x="992" y="223" text-anchor="end" fill="${C.quantum}">${vuln}</text>`;
}

// ---------------- triage queue ----------------
function renderQueue() {
  const min = +$("#minScore").value;
  const rows = ALERTS
    .filter((a) => a.fused_score >= min && (!filterBand || a.risk_band === filterBand))
    .map((a) => {
      const w = Math.round(a.fused_score);
      return `<tr data-id="${a.session_id}">
        <td class="case">${a.session_id}</td>
        <td>${a.user_id}</td>
        <td>${a.threat_type}</td>
        <td class="n c">${a.cyber_score}</td>
        <td class="n f">${a.fraud_score}</td>
        <td class="n q">${a.quantum_score}</td>
        <td class="n fused"><span class="fusedcell">${a.fused_score}
          <span class="fusedbar"><i style="width:${w}%;background:${bandColor(a.risk_band)}"></i></span></span></td>
        <td><span class="band ${a.risk_band}">${a.risk_band}</span></td>
        <td class="c">${a.cross_domain_correlated ? '<span class="corr-y">⋈</span>' : ""}</td>
      </tr>`;
    }).join("");
  const tb = $("#queue tbody");
  selectedIndex = -1; // filters changed — reset keyboard selection

  if (rows) {
    tb.innerHTML = rows;
    tb.querySelectorAll("tr[data-id]").forEach((tr, i) =>
      tr.addEventListener("click", () => { selectedIndex = i; openCase(tr.dataset.id, tr); }));
  } else {
    tb.innerHTML = `<tr class="empty-row"><td colspan="9">
      <div class="empty-state">
        <div class="es-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor"
               stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="7"></circle>
            <line x1="16.5" y1="16.5" x2="21" y2="21"></line>
            <line x1="8" y1="11" x2="14" y2="11"></line>
          </svg>
        </div>
        <div class="es-title">No cases match your filters</div>
        <div class="es-sub">Nothing in the triage queue meets the current band and score threshold. Try widening your criteria.</div>
        <button class="es-reset" id="queueReset" type="button">Reset filters</button>
      </div></td></tr>`;
    $("#queueReset").addEventListener("click", resetFilters);
  }
}

// reset triage filters to defaults (min_score 0, band all)
function resetFilters() {
  filterBand = "";
  $("#minScore").value = 0;
  $("#minScoreVal").textContent = "0";
  $("#bandSeg .active")?.classList.remove("active");
  $('#bandSeg button[data-band=""]')?.classList.add("active");
  renderQueue();
}

// ---------------- keyboard navigation over the queue ----------------
function queueRows() { return [...$("#queue tbody").querySelectorAll("tr[data-id]")]; }

function highlightSelected() {
  const rows = queueRows();
  rows.forEach((r, i) => r.classList.toggle("sel", i === selectedIndex));
  if (selectedIndex >= 0 && rows[selectedIndex])
    rows[selectedIndex].scrollIntoView({ block: "nearest" });
}

function moveSelection(delta) {
  const rows = queueRows();
  if (!rows.length) return;
  selectedIndex = selectedIndex < 0
    ? (delta > 0 ? 0 : rows.length - 1)
    : Math.min(rows.length - 1, Math.max(0, selectedIndex + delta));
  highlightSelected();
}

// ---------------- charts ----------------
function baseOpts(max) {
  return {
    responsive: true, maintainAspectRatio: false,
    scales: {
      y: { beginAtZero: true, max, ticks: { color: C.muted, font: { family: "IBM Plex Mono" } }, grid: { color: C.grid } },
      x: { ticks: { color: C.muted }, grid: { display: false } },
    },
    plugins: { legend: { labels: { color: C.muted, boxWidth: 10, font: { size: 11 } } } },
  };
}
function renderMetricsChart(m) {
  const mk = (o) => [o.precision, o.recall, o.f1];
  charts.metrics?.destroy();
  charts.metrics = new Chart($("#metricsChart"), {
    type: "bar",
    data: { labels: ["Precision", "Recall", "F1"], datasets: [
      { label: "Cyber", data: mk(m.cyber_only), backgroundColor: C.cyber },
      { label: "Transaction", data: mk(m.fraud_only), backgroundColor: C.txn },
      { label: "Fused", data: mk(m.fused), backgroundColor: C.fused },
    ] },
    options: baseOpts(1),
  });
  $("#fpNote").innerHTML =
    `False positives — cyber <b style="color:${C.cyber}">${m.cyber_only.false_positives}</b>, ` +
    `transaction <b style="color:${C.txn}">${m.fraud_only.false_positives}</b>, ` +
    `fused <b style="color:${C.low}">${m.fused.false_positives}</b>. ` +
    `Correlation removes ${m.false_positive_reduction_pct_vs_best_single_signal}% of single-signal noise.`;
}
async function renderThreatChart() {
  const t = await api("/api/threat-breakdown");
  charts.threat?.destroy();
  charts.threat = new Chart($("#threatChart"), {
    type: "doughnut",
    data: { labels: Object.keys(t), datasets: [{ data: Object.values(t),
      backgroundColor: [C.crit, C.txn, C.quantum, C.cyber, C.low], borderColor: "#121722", borderWidth: 2 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: "62%",
      plugins: { legend: { position: "bottom", labels: { color: C.muted, boxWidth: 10, font: { size: 10.5 } } } } },
  });
}
function renderQuantum(q) {
  const s = q.summary;
  charts.quantum?.destroy();
  charts.quantum = new Chart($("#quantumChart"), {
    type: "doughnut",
    data: { labels: ["Quantum-vulnerable", "Quantum-safe"],
      datasets: [{ data: [s.quantum_vulnerable_sessions, s.quantum_safe_sessions],
        backgroundColor: [C.crit, C.low], borderColor: "#121722", borderWidth: 2 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: "68%",
      plugins: { legend: { position: "bottom", labels: { color: C.muted, boxWidth: 10, font: { size: 10.5 } } } } },
  });
  $("#quantumNote").innerHTML =
    `Avg exposure <b>${s.avg_quantum_risk_score}</b> · <b style="color:${C.quantum}">${s.high_hndl_exposure_sessions}</b> high-risk sessions · ` +
    `artefacts sealed with <b>${q.pqc_module.aead || "AES-256-GCM"}</b>.`;

  $("#exposedList").innerHTML = (q.top_exposed_sessions || []).slice(0, 8).map((e) =>
    `<div class="exp-row" data-id="${e.session_id}">
      <span class="exp-id">${e.session_id}</span>
      <span class="exp-meter"><i style="width:${e.quantum_score}%"></i></span>
      <span class="exp-val">${e.quantum_score}</span>
    </div>`).join("");
  $("#exposedList").querySelectorAll(".exp-row").forEach((r) =>
    r.addEventListener("click", () => openCase(r.dataset.id)));
}

// ---------------- investigation slide-over ----------------
function ring(score, color) {
  const r = 26, c = 2 * Math.PI * r, off = c * (1 - score / 100);
  return `<svg class="ring" viewBox="0 0 62 62">
    <circle cx="31" cy="31" r="${r}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="6"/>
    <circle cx="31" cy="31" r="${r}" fill="none" stroke="${color}" stroke-width="6" stroke-linecap="round"
      stroke-dasharray="${c}" stroke-dashoffset="${off}" transform="rotate(-90 31 31)"/>
  </svg>`;
}
const money = (n) => "₹" + Number(n).toLocaleString("en-IN", { maximumFractionDigits: 0 });

// Plain-language findings synthesised from the correlated evidence (no z-scores)
function deriveFindings(a, t, txns) {
  const f = [];
  if (t.impossible_travel) f.push(["c", "CYBER", `Impossible travel · login from ${t.geo_country}`]);
  else if (t.device_known === false || t.device_risk >= 0.6) f.push(["c", "CYBER", "Unrecognised high-risk device"]);
  if (t.mfa_used === false && a.cyber_score >= 55) f.push(["c", "CYBER", "MFA not completed"]);
  if (t.privilege_escalation) f.push(["c", "CYBER", "Privilege escalation in session"]);

  if (txns && txns.length) {
    const mx = txns.reduce((p, c) => (c.amount > p.amount ? c : p), txns[0]);
    if (mx.amount >= 50000 || mx.beneficiary_new)
      f.push(["f", "TXN", `${money(mx.amount)} to ${mx.beneficiary_new ? "new " : ""}payee · ${mx.beneficiary_country}`]);
    else if (txns.length >= 4) f.push(["f", "TXN", `${txns.length} rapid transfers in session`]);
  }

  if (a.quantum_posture === "QUANTUM_VULNERABLE" && a.quantum_score >= 55)
    f.push(["q", "QUANTUM", `Quantum-vulnerable ${t.tls_key_exchange} on ${t.data_sensitivity} data`]);
  else if (a.quantum_score >= 70)
    f.push(["q", "QUANTUM", `High harvest-now-decrypt-later exposure`]);
  return f.slice(0, 4);
}

function deriveWhy(a) {
  if (a.cross_domain_correlated)
    return `Two independent signals — <b>cyber</b> and <b>transaction</b> — fired in the same session. That correlation is why confidence is high.`;
  const tt = a.threat_type;
  if (tt.startsWith("Transaction")) return `Transaction behaviour deviates sharply from this customer's baseline.`;
  if (tt.startsWith("Insider")) return `A privileged account is behaving outside its normal pattern.`;
  if (tt.startsWith("Quantum")) return `Sensitive data moved over <b>quantum-vulnerable</b> cryptography.`;
  if (tt.startsWith("Cyber")) return `Access pattern is anomalous for this user.`;
  return `Elevated risk detected on this session.`;
}

function deriveAction(a) {
  const tt = a.threat_type;
  if (tt.startsWith("Account Takeover")) return "Block session · force re-authentication · freeze beneficiary";
  if (tt.startsWith("Insider")) return "Suspend elevated access · open investigation";
  if (tt.startsWith("Transaction")) return "Hold pending transactions · verify with customer";
  if (tt.startsWith("Quantum")) return "Rotate to PQC · restrict bulk egress · flag for crypto migration";
  if (tt.startsWith("Cyber")) return "Step-up authentication · monitor session";
  return "Review case";
}

async function openCase(id, tr) {
  document.querySelectorAll("#queue tr.sel").forEach((r) => r.classList.remove("sel"));
  tr?.classList.add("sel");
  const d = await api(`/api/alerts/${id}`);
  const a = d.alert, t = d.telemetry;

  const findings = deriveFindings(a, t, d.transactions)
    .map(([c, tag, text]) => `<div class="finding"><span class="tag ${c}">${tag}</span><span>${text}</span></div>`)
    .join("");
  const txns = (d.transactions || []).slice(0, 4).map((x) =>
    `<div class="t"><span>${x.txn_type} · ${money(x.amount)}</span>
     <span class="dest">→ ${x.beneficiary_country}${x.beneficiary_new ? " · new" : ""}</span></div>`).join("") ||
    `<div class="t"><span class="dest">no transactions in session</span></div>`;

  $("#inspId").textContent = a.session_id;
  $("#inspClass").textContent = `${a.threat_type} · ${a.user_id}`;
  $("#inspBody").innerHTML = `
    <div class="verdict">
      ${ring(a.fused_score, bandColor(a.risk_band))}
      <div class="vmeta"><div class="vscore" style="color:${bandColor(a.risk_band)}">${a.fused_score}</div>
        <div class="vlbl">fused risk · <span class="band ${a.risk_band}">${a.risk_band}</span>
        ${a.cross_domain_correlated ? ' · <span class="corr-y">⋈ correlated</span>' : ""}</div></div>
    </div>
    <div class="splits">
      <div class="split c"><div class="sv">${a.cyber_score}</div><div class="sl">Cyber</div></div>
      <div class="split f"><div class="sv">${a.fraud_score}</div><div class="sl">Transaction</div></div>
      <div class="split q"><div class="sv">${a.quantum_score}</div><div class="sl">Quantum</div></div>
    </div>
    <div class="why">${deriveWhy(a)}</div>
    <div class="sect">Key findings</div>
    <div class="findings">${findings || '<div class="finding"><span>No individual signal above threshold.</span></div>'}</div>
    <div class="action"><div class="al">Recommended action</div><div class="at">${deriveAction(a)}</div></div>
    <div class="sect">Evidence</div>
    <div class="kv">
      <div>Origin <b>${t.geo_country} · ${t.geo_distance_km}km</b></div>
      <div>Device risk <b>${t.device_risk}</b></div>
      <div>Crypto <b>${t.tls_key_exchange}</b></div>
      <div>MFA <b>${t.mfa_used ? "yes" : "no"}</b></div>
    </div>
    <div class="txns">${txns}</div>`;
  $("#scrim").classList.add("on");
  $("#inspector").classList.add("on");
}
function closeCase() {
  $("#scrim").classList.remove("on");
  $("#inspector").classList.remove("on");
  document.querySelectorAll("#queue tr.sel").forEach((r) => r.classList.remove("sel"));
}

// ---------------- UI wiring ----------------
function wireUI() {
  $("#minScore").addEventListener("input", (e) => { $("#minScoreVal").textContent = e.target.value; renderQueue(); });
  $("#bandSeg").querySelectorAll("button").forEach((b) =>
    b.addEventListener("click", () => {
      $("#bandSeg .active")?.classList.remove("active");
      b.classList.add("active"); filterBand = b.dataset.band; renderQueue();
    }));
  $("#inspClose").addEventListener("click", closeCase);
  $("#scrim").addEventListener("click", closeCase);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeCase(); return; }
    // don't hijack typing in form controls (e.g. the score slider)
    if (e.target.matches("input, textarea, select")) return;
    const rows = queueRows();
    if (e.key === "ArrowDown") { e.preventDefault(); moveSelection(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); moveSelection(-1); }
    else if (e.key === "Enter" && selectedIndex >= 0 && rows[selectedIndex]) {
      e.preventDefault();
      openCase(rows[selectedIndex].dataset.id, rows[selectedIndex]);
    }
  });

  $("#protectBtn").addEventListener("click", async () => {
    const r = await api("/api/protect-top-case", { method: "POST" });
    $("#protectBtn").textContent = r.pqc_status ? "Sealed · " + r.pqc_status.mode : "Sealed";
  });

  // nav scroll-spy
  const sections = [...document.querySelectorAll(".block")];
  document.querySelectorAll(".nav-item").forEach((n) =>
    n.addEventListener("click", () => document.getElementById(n.dataset.target)
      .scrollIntoView({ behavior: "smooth", block: "start" })));
  const view = $(".view");
  let ticking = false;
  view.addEventListener("scroll", () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const y = view.scrollTop + 90;
      let cur = sections[0].id;
      for (const s of sections) if (s.offsetTop <= y) cur = s.id;
      document.querySelectorAll(".nav-item").forEach((n) =>
        n.classList.toggle("active", n.dataset.target === cur));
      ticking = false;
    });
  }, { passive: true });
}
