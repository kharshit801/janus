# Janus — Presentation Content (maps to the 16 Finspark template slides)

Copy each block into the matching slide of `Finspark_Hackathon_Template.pptx`.
Keep bullets tight; speak to the detail.

---

## Slide 1 — Title
- **Project:** Janus — Cyber & Transaction Risk Fusion (Quantum-Aware)
- **Team members:** Abhishek Rastogi, Shubit Yadav
- **Team bio:** _<one line per member — e.g. areas each of you led>_
- **Date:** July 2026
- Tagline: *"One risk verdict from two silos — watching today's threats and tomorrow's quantum risk."*

---

## Slide 2 — Problem Statement
- **Chosen: Problem Statement 2** — AI-Driven Correlation of Cybersecurity Telemetry & Transactional Behaviour.
- **Why we chose it:** Banks hold vast cyber + transaction data but run them in **separate silos**, so early warning signals slip through. It is also far less saturated than insider-threat/UEBA (which has dozens of ready-made tools and datasets), giving us room for genuine novelty.
- **The gap we attack:** no intelligent correlation for contextual threat awareness, high false-positive fatigue, and a *blind spot* to rising quantum risks like **harvest-now, decrypt-later (HNDL)**.

---

## Slide 3 — Pre-Requisite
- **Assumptions:** the bank can stream (a) cyber telemetry — auth logs, device/geo risk, TLS crypto metadata, data-egress volume; and (b) transaction events keyed to a session/user.
- **Prototype data:** synthetic, deterministic generator (`seed=42`, 800 sessions, 1,190 transactions) with four labelled behaviours (benign, account takeover, insider fraud, HNDL/quantum).
- **Required to run:** Python 3.11+, `pip install -r requirements.txt`. No GPU, no cloud, no paid API.
- **Prod inputs:** connectors to SIEM/XDR + core-banking transaction bus; KMS/HSM for keys.

---

## Slide 4 — Tools / Resources
- **Language/runtime:** Python 3.13.
- **ML:** scikit-learn (Isolation Forest), NumPy, pandas.
- **API:** FastAPI + Uvicorn.
- **Crypto:** `cryptography` (AES-256-GCM, HKDF-SHA3-256, SHA3-384); optional `liboqs`/ML-KEM.
- **UI:** HTML + vanilla JS + Chart.js (no build step).
- **Testing:** pytest (12 tests).
- **References:** NIST PQC (ML-KEM/FIPS 203, ML-DSA/FIPS 204), NSA HNDL advisory, cyber-fraud "fusion" industry trend (Mastercard, Cleafy FxDR).

---

## Slide 5 — Supporting Functional Documents
- `README.md` — overview, quick start, results table.
- `docs/ARCHITECTURE.md` — architecture diagram, pillars, data flow, prod hardening.
- Logic flow: **generate → feature-engineer → dual Isolation Forests + quantum monitor → fuse (with correlation boost) → explainable alert + case narrative → PQC vault**.
- Reason-code + case-narrative logic makes every score auditable (explainable AI).

---

## Slide 6 — Key Differentiators & Adoption Plan
**Differentiators**
1. **Cross-domain fusion**, not another siloed model — one verdict from cyber × transactions.
2. **Correlation boost** → **100% false-positive reduction** vs. best single signal (0 FP, precision 1.0) in our eval.
3. **Quantum/HNDL monitoring** — a blind spot in mainstream tools; we score cryptographic exposure per session.
4. **Explainable by construction** — reason codes + plain-English case narrative for analysts.
5. **PQC artifact vault** — sensitive outputs sealed with quantum-safe crypto.

**Adoption plan**
- Phase 1: deploy read-only alongside existing SIEM + fraud engine (shadow mode).
- Phase 2: feed fused alerts into the SOC/fraud case queue; tune weights per bank.
- Phase 3: enable risk-based actions (step-up auth, hold transaction) + PQC migration reporting.

---

## Slide 7 — GitHub Repository Link & Supporting Diagrams
- **GitHub:** _<paste repo URL after pushing>_
- Include the architecture diagram (from `docs/ARCHITECTURE.md`) and dashboard screenshot (`docs/screenshots/dashboard.png`).

---

## Slide 8 — Business Potential and Relevance
- **Direct relevance to Bank of Maharashtra:** unifies SOC + fraud operations, cutting analyst fatigue and missed cross-domain attacks (account takeover, mule transfers).
- **ROI:** fewer false positives = lower investigation cost; correlated detection = fewer fraud losses; quantum readiness = regulatory + reputational protection.
- **Expansion:** UPI/IMPS/NEFT fraud, card-not-present, corporate banking, and a bank-wide **PQC migration dashboard** as India/RBI moves toward quantum-safe mandates.
- **Long-term:** the fusion layer is a platform — new telemetry or transaction sources plug in without re-architecting.

---

## Slide 9 — Uniqueness of Approach and Solution
- Most solutions are **single-domain** (UEBA *or* fraud). Janus is a **fusion engine**.
- The **correlation-boost** mechanism is a simple, explainable way to raise true-positive confidence *and* suppress single-signal noise — proven with a measurable FP reduction.
- **HNDL detection is near-whitespace**: 2026 research explicitly notes current IDS/telemetry tools lack indicators for quantum-enabled attacks. We turn HNDL into an actionable per-session score.
- Combines detection **and** protection (PQC vault) in one prototype.

---

## Slide 10 — User Experience
- Single **dark ops dashboard**: KPI hero row, sortable fused-alert table, one-click **case narrative** with colour-coded cyber/fraud/quantum reason codes and the raw correlated evidence.
- Analysts read *why* in plain English, not raw scores — reduces triage time.
- Shareable deep-links (`/?case=S100136`), live risk-threshold slider, one-click "Seal case (PQC)".
- Screenshots: `docs/screenshots/dashboard.png`, `case_narrative.png`.

---

## Slide 11 — Scalability
- **Stateless scoring** → horizontally scalable API workers behind a load balancer.
- Feature pipeline moves from in-process pandas to **Spark/Flink**; models served from a registry with scheduled retraining.
- Isolation Forest scores in O(sessions) — millions of sessions/day feasible.
- Multi-tenant by branch/region; fusion weights configurable per environment.
- Streaming-ready: designed around session events that map cleanly to Kafka topics.

---

## Slide 12 — Ease of Deployment and Maintenance
- **One command to run** (`uvicorn janus.api:app`); pure-Python, no GPU, no external services.
- Pinned dependencies in `requirements.txt`; modular package (swap the data source without touching ML/fusion).
- **12 automated tests** guard the pipeline, quantum monitor, PQC round-trip and API.
- Deterministic seed → reproducible demos and CI.
- Containerises trivially (single Python image).

---

## Slide 13 — Security Considerations
- **Data protection:** synthetic data only in the prototype; no real PII. Artefacts sealed with **AES-256-GCM + SHA3-384** (quantum-resistant), keys via KMS/HSM in prod.
- **Quantum-safe:** HNDL monitoring + PQC vault directly address quantum risk; optional ML-KEM key encapsulation.
- **Access control (prod):** OIDC/mTLS auth, RBAC per analyst, least privilege — the demo API is intentionally unauthenticated and this is called out honestly.
- **Integrity & audit:** SHA3-384 integrity digests; production adds immutable audit logging of every decision and access.
- **Compliance-aligned:** explainable decisions support RBI/audit requirements; no black-box actions.

---

## Slide 14 — Architecture Diagram & Images
- Use the diagram in `docs/ARCHITECTURE.md` (Section 1).
- Flow: **Data sources → feature engineering → 3 pillars (cyber, fraud, quantum) → fusion engine → API + PQC vault → analyst dashboard**.

---

## Slide 15 — Solution Screenshots & Video & GitHub Link
- **Screenshots:** `docs/screenshots/dashboard.png` (KPIs + fused alerts + detection-quality chart + threat donut), `docs/screenshots/case_narrative.png` (quantum radar + case narrative).
- **Demo flow to record (60–90s):** open dashboard → point out precision 1.0 / FP reduction → click a CRITICAL account-takeover case → read the narrative + reason codes → show quantum posture → click "Seal Top Case (PQC)".
- **GitHub:** _<repo URL>_

---

## Slide 16 — Thank You
- **Team members:**
  - Abhishek Rastogi — _<role, e.g. presentation & solution design>_ · _<email/phone>_
  - Shubit Yadav — _<role, e.g. engineering & analytics>_ · _<email/phone>_
- Closing line: *"Janus — one verdict from two silos, ready for the quantum era."*

---

### Headline numbers to memorise for Q&A
- Fused detector: **precision 1.00, recall 0.70, F1 0.83, 0 false positives**.
- **100% false-positive reduction** vs. the best single signal (fraud-only had 33 FPs, cyber-only 7).
- **33.5% PQC readiness**, **198** high-HNDL-exposure sessions, **532** sessions on quantum-vulnerable crypto out of 800.
