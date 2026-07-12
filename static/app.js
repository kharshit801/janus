// Janus dashboard logic
const $ = (s) => document.querySelector(s);
const api = (p, opts) => fetch(p, opts).then((r) => r.json());

let charts = {};

async function loadSummary() {
  const s = await api("/api/summary");
  const kpis = [
    { val: s.total_sessions, lbl: "Sessions analysed", cls: "" },
    { val: s.true_threats, lbl: "True threats present", cls: "" },
    { val: (s.precision * 100).toFixed(0) + "%", lbl: "Fused precision", cls: "good" },
    { val: (s.recall * 100).toFixed(0) + "%", lbl: "Fused recall", cls: "accent" },
    { val: "-" + s.false_positive_reduction_pct + "%", lbl: "False positives vs single-signal", cls: "good" },
    { val: s.pqc_readiness_pct + "%", lbl: "PQC readiness", cls: "quantum" },
  ];
  $("#kpis").innerHTML = kpis
    .map((k) => `<div class="kpi"><div class="val ${k.cls}">${k.val}</div><div class="lbl">${k.lbl}</div></div>`)
    .join("");
}

async function loadMetrics() {
  const m = await api("/api/metrics");
  const mk = (o) => [o.precision, o.recall, o.f1];
  charts.metrics && charts.metrics.destroy();
  charts.metrics = new Chart($("#metricsChart"), {
    type: "bar",
    data: {
      labels: ["Precision", "Recall", "F1"],
      datasets: [
        { label: "Cyber only", data: mk(m.cyber_only), backgroundColor: "#5b7fa6" },
        { label: "Fraud only", data: mk(m.fraud_only), backgroundColor: "#a85a00" },
        { label: "Fused", data: mk(m.fused), backgroundColor: "#1f4e79" },
      ],
    },
    options: chartOpts({ max: 1 }),
  });
  $("#fpNote").innerHTML =
    `False positives — cyber: <b>${m.cyber_only.false_positives}</b>, ` +
    `fraud: <b>${m.fraud_only.false_positives}</b>, ` +
    `<span style="color:#2ecc71">fused: <b>${m.fused.false_positives}</b></span>. ` +
    `Correlation cut FP by ${m.false_positive_reduction_pct_vs_best_single_signal}% vs the best single signal.`;
}

async function loadThreats() {
  const t = await api("/api/threat-breakdown");
  charts.threat && charts.threat.destroy();
  charts.threat = new Chart($("#threatChart"), {
    type: "doughnut",
    data: {
      labels: Object.keys(t),
      datasets: [{
        data: Object.values(t),
        backgroundColor: ["#b3261e", "#a85a00", "#12395d", "#5b7fa6", "#1e6b33"],
      }],
    },
    options: { plugins: { legend: { labels: { color: "#5b6b7b", boxWidth: 12, font: { size: 11 } } } } },
  });
}

async function loadQuantum() {
  const q = await api("/api/quantum");
  const s = q.summary;
  charts.quantum && charts.quantum.destroy();
  charts.quantum = new Chart($("#quantumChart"), {
    type: "polarArea",
    data: {
      labels: ["Vulnerable", "Safe", "High HNDL exposure"],
      datasets: [{
        data: [s.quantum_vulnerable_sessions, s.quantum_safe_sessions, s.high_hndl_exposure_sessions],
        backgroundColor: ["rgba(179,38,30,0.55)", "rgba(30,107,51,0.55)", "rgba(18,57,93,0.55)"],
        borderColor: ["#b3261e", "#1e6b33", "#12395d"],
        borderWidth: 1,
      }],
    },
    options: { plugins: { legend: { labels: { color: "#5b6b7b", boxWidth: 12, font: { size: 11 } } } },
      scales: { r: { ticks: { color: "#5b6b7b", backdropColor: "transparent" }, grid: { color: "#d3dae1" } } } },
  });
  $("#quantumNote").innerHTML =
    `Avg quantum-risk score <b>${s.avg_quantum_risk_score}</b> · ` +
    `<b>${s.quantum_vulnerable_sessions}</b> sessions use quantum-vulnerable crypto · ` +
    `vault: <b>${q.pqc_module.aead || q.pqc_module.confidentiality}</b>.`;
}

async function loadAlerts() {
  const min = $("#minScore").value;
  const band = $("#bandFilter").value;
  const q = `/api/alerts?limit=100&min_score=${min}${band ? "&band=" + band : ""}`;
  const data = await api(q);
  const tb = $("#alertsTable tbody");
  tb.innerHTML = data.alerts
    .map((a) => `
      <tr data-id="${a.session_id}">
        <td>${a.session_id}</td>
        <td>${a.user_id}</td>
        <td>${a.threat_type}</td>
        <td class="score">${a.cyber_score}</td>
        <td class="score">${a.fraud_score}</td>
        <td class="score">${a.quantum_score}</td>
        <td class="score">${a.fused_score}</td>
        <td><span class="band ${a.risk_band}">${a.risk_band}</span></td>
        <td class="corr">${a.cross_domain_correlated ? "✔" : ""}</td>
      </tr>`)
    .join("");
  tb.querySelectorAll("tr").forEach((tr) =>
    tr.addEventListener("click", () => loadCase(tr.dataset.id)));
}

async function loadCase(id, scroll = true) {
  const d = await api(`/api/alerts/${id}`);
  const a = d.alert;
  const list = (arr) => arr && arr.length
    ? `<ul>${arr.map((r) => `<li>${r}</li>`).join("")}</ul>`
    : `<span style="color:#8a97ad">none</span>`;
  const txnRows = (d.transactions || [])
    .map((t) => `${t.txn_type} ₹${Number(t.amount).toLocaleString()} → ${t.beneficiary_country}${t.beneficiary_new ? " (new)" : ""}`)
    .join("<br>") || "none";
  $("#caseDetail").innerHTML = `
    <div class="case">
      <h4>${a.session_id} · ${a.threat_type} · <span class="band ${a.risk_band}">${a.risk_band}</span></h4>
      <div class="narrative">${a.narrative}</div>
      <div class="reasons">
        <div class="col cyber"><h5>Cyber (${a.cyber_score})</h5>${list(a.cyber_reasons)}</div>
        <div class="col fraud"><h5>Fraud (${a.fraud_score})</h5>${list(a.fraud_reasons)}</div>
        <div class="col quantum"><h5>Quantum (${a.quantum_score})</h5>${list(a.quantum_reasons)}</div>
      </div>
      <div class="evidence">
        <span><b>User:</b> ${a.user_id}</span>
        <span><b>Device risk:</b> ${d.telemetry.device_risk}</span>
        <span><b>Geo:</b> ${d.telemetry.geo_country} (${d.telemetry.geo_distance_km} km)</span>
        <span><b>Crypto:</b> ${d.telemetry.tls_key_exchange}/${d.telemetry.tls_cipher}</span>
        <span><b>Egress:</b> ${(d.telemetry.bytes_out / 1e6).toFixed(0)} MB</span>
        <span><b>Ground truth:</b> ${a.ground_truth}</span>
      </div>
      <div class="evidence"><span><b>Transactions:</b><br>${txnRows}</span></div>
    </div>`;
  if (scroll) $("#caseCard").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function chartOpts({ max }) {
  return {
    scales: {
      y: { beginAtZero: true, max, ticks: { color: "#5b6b7b" }, grid: { color: "#e2e7ec" } },
      x: { ticks: { color: "#5b6b7b" }, grid: { color: "transparent" } },
    },
    plugins: { legend: { labels: { color: "#5b6b7b", boxWidth: 12, font: { size: 11 } } } },
  };
}

$("#minScore").addEventListener("input", (e) => {
  $("#minScoreVal").textContent = e.target.value;
  loadAlerts();
});
$("#bandFilter").addEventListener("change", loadAlerts);
$("#protectBtn").addEventListener("click", async () => {
  const r = await api("/api/protect-top-case", { method: "POST" });
  $("#pqcStatus").textContent = r.pqc_status
    ? `Sealed — ${r.pqc_status.mode}` : "Sealed";
});

(async function init() {
  await loadSummary();
  await Promise.all([loadMetrics(), loadThreats(), loadQuantum(), loadAlerts()]);
  const params = new URLSearchParams(location.search);
  const caseId = params.get("case");
  if (caseId) loadCase(caseId, false);
})();
