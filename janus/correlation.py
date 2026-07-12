"""Correlation / fusion engine for Janus.

This is the core differentiator. Banks run cyber telemetry and transaction
monitoring in separate silos, so each side sees only half the picture. Janus
fuses three signals per session into one risk verdict:

    fused = w_cyber*cyber + w_fraud*fraud + w_quantum*quantum   (+ correlation boost)

The **correlation boost** is the key idea: when cyber *and* fraud signals are
both elevated in the *same* session they reinforce each other (e.g. an
anomalous login immediately followed by a high-value transfer = account
takeover). Correlated multi-domain evidence is far more reliable than either
signal alone, which is precisely how Janus raises confidence on real threats
while suppressing single-signal false positives.
"""

from __future__ import annotations

from typing import Dict, List

import pandas as pd

from . import config
from .ml_engine import AnomalyEngine
from . import quantum_risk

CORRELATION_TRIGGER = 55.0   # each component must exceed this to correlate
CORRELATION_BOOST = 15.0     # added when cyber & fraud co-fire in one session


def fuse_scores(cyber: float, fraud: float, quantum: float) -> Dict[str, float]:
    """Blend the three pillars into a single 0-100 fused risk score."""
    w = config.FUSION_WEIGHTS
    base = w["cyber"] * cyber + w["fraud"] * fraud + w["quantum"] * quantum

    boost = 0.0
    correlated = cyber >= CORRELATION_TRIGGER and fraud >= CORRELATION_TRIGGER
    if correlated:
        boost = CORRELATION_BOOST

    fused = min(100.0, base + boost)
    return {"fused_score": round(fused, 1), "correlation_boost": boost,
            "cross_domain_correlated": correlated}


def _classify_threat(cyber: float, fraud: float, quantum: float,
                     correlated: bool, is_privileged: bool) -> str:
    if quantum >= 60 and quantum >= max(cyber, fraud):
        return "Quantum / HNDL Exposure"
    if correlated:
        return "Account Takeover (cyber+fraud correlated)"
    if fraud >= 60 and is_privileged:
        return "Insider / Privilege Abuse"
    if fraud >= 60:
        return "Transaction Fraud"
    if cyber >= 60:
        return "Cyber Anomaly"
    if quantum >= 60:
        return "Quantum / HNDL Exposure"
    return "Normal"


def build_alerts(features: pd.DataFrame, scores: pd.DataFrame,
                 engine: AnomalyEngine) -> pd.DataFrame:
    """Produce a fully-fused, explainable alert per session."""
    merged = features.merge(scores, on="session_id")
    records: List[Dict] = []

    for _, row in merged.iterrows():
        cyber = float(row["cyber_score"])
        fraud = float(row["fraud_score"])

        q = quantum_risk.hndl_exposure(row.to_dict())
        quantum = float(q["quantum_risk_score"])

        fusion = fuse_scores(cyber, fraud, quantum)
        threat = _classify_threat(cyber, fraud, quantum,
                                  fusion["cross_domain_correlated"],
                                  bool(row["is_privileged"]))

        cyber_reasons = engine.reason_codes(row, "cyber") if cyber >= 45 else []
        fraud_reasons = engine.reason_codes(row, "fraud") if fraud >= 45 else []
        quantum_reasons = q["reasons"] if quantum >= 45 else []

        narrative = _narrative(row, threat, cyber, fraud, quantum,
                               fusion, cyber_reasons, fraud_reasons, quantum_reasons)

        records.append({
            "session_id": row["session_id"],
            "user_id": row["user_id"],
            "timestamp": row["timestamp"],
            "cyber_score": round(cyber, 1),
            "fraud_score": round(fraud, 1),
            "quantum_score": round(quantum, 1),
            "fused_score": fusion["fused_score"],
            "risk_band": config.risk_band(fusion["fused_score"]),
            "cross_domain_correlated": fusion["cross_domain_correlated"],
            "correlation_boost": fusion["correlation_boost"],
            "threat_type": threat,
            "quantum_posture": q["posture"],
            "cyber_reasons": cyber_reasons,
            "fraud_reasons": fraud_reasons,
            "quantum_reasons": quantum_reasons,
            "narrative": narrative,
            "ground_truth": row.get("label", "UNKNOWN"),
        })

    alerts = pd.DataFrame(records)
    return alerts.sort_values("fused_score", ascending=False).reset_index(drop=True)


def _narrative(row, threat, cyber, fraud, quantum, fusion,
               cyber_reasons, fraud_reasons, quantum_reasons) -> str:
    """Human-readable case narrative for the SOC / fraud analyst."""
    band = config.risk_band(fusion["fused_score"])
    parts = [
        f"[{band}] {threat} on session {row['session_id']} for user {row['user_id']}.",
        f"Fused risk {fusion['fused_score']}/100 "
        f"(cyber {cyber:.0f}, fraud {fraud:.0f}, quantum {quantum:.0f}).",
    ]
    if fusion["cross_domain_correlated"]:
        parts.append(
            "Cyber and transaction anomalies co-occurred in this session — "
            "correlated evidence raised confidence."
        )
    if cyber_reasons:
        parts.append("Cyber signals: " + "; ".join(cyber_reasons) + ".")
    if fraud_reasons:
        parts.append("Fraud signals: " + "; ".join(fraud_reasons) + ".")
    if quantum_reasons:
        parts.append("Quantum exposure: " + "; ".join(quantum_reasons))
    return " ".join(parts)
