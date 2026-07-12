"""End-to-end pipeline orchestration for Janus.

Wires the stages together: generate -> engineer features -> fit models ->
score -> fuse -> alerts -> metrics -> quantum posture. Holds the fitted state
in memory so the API can serve results quickly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Optional

import pandas as pd

from . import config, data_generator, quantum_risk, pqc
from .correlation import build_alerts
from .ml_engine import AnomalyEngine, build_features

HIGH_RISK_THRESHOLD = 60.0  # fused >= 60 -> actioned alert (HIGH/CRITICAL)


@dataclass
class PipelineState:
    sessions: pd.DataFrame
    transactions: pd.DataFrame
    features: pd.DataFrame
    scores: pd.DataFrame
    alerts: pd.DataFrame
    engine: AnomalyEngine
    metrics: Dict
    quantum_summary: Dict


_STATE: Optional[PipelineState] = None


def run(seed: int = config.DEFAULT_SEED) -> PipelineState:
    """Run the full pipeline and cache the state."""
    global _STATE
    data = data_generator.generate(seed=seed)
    features = build_features(data.sessions, data.transactions)

    engine = AnomalyEngine(random_state=seed).fit(features)
    scores = engine.score(features)
    alerts = build_alerts(features, scores, engine)

    metrics = _evaluate(alerts)
    q_summary = quantum_risk.portfolio_summary(data.sessions)

    _STATE = PipelineState(
        sessions=data.sessions,
        transactions=data.transactions,
        features=features,
        scores=scores,
        alerts=alerts,
        engine=engine,
        metrics=metrics,
        quantum_summary=q_summary,
    )
    return _STATE


def get_state() -> PipelineState:
    """Return cached state, running the pipeline on first access."""
    if _STATE is None:
        return run()
    return _STATE


def _evaluate(alerts: pd.DataFrame) -> Dict:
    """Compute detection quality and quantify false-positive reduction.

    A session is a *true threat* if its ground-truth label is not BENIGN.
    We compare single-signal detection (cyber-only, fraud-only) with the fused
    verdict to show that correlation reduces false positives.
    """
    df = alerts.copy()
    df["is_threat"] = df["ground_truth"] != "BENIGN"

    def prf(flag: pd.Series):
        tp = int((flag & df["is_threat"]).sum())
        fp = int((flag & ~df["is_threat"]).sum())
        fn = int((~flag & df["is_threat"]).sum())
        tn = int((~flag & ~df["is_threat"]).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        benign = int((~df["is_threat"]).sum())
        fp_rate = fp / benign if benign else 0.0
        return {
            "true_positives": tp, "false_positives": fp,
            "false_negatives": fn, "true_negatives": tn,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3), "false_positive_rate": round(fp_rate, 3),
        }

    cyber_only = prf(df["cyber_score"] >= HIGH_RISK_THRESHOLD)
    fraud_only = prf(df["fraud_score"] >= HIGH_RISK_THRESHOLD)
    fused = prf(df["fused_score"] >= HIGH_RISK_THRESHOLD)

    # False-positive reduction of the fused verdict vs the better single signal.
    best_single_fp = min(cyber_only["false_positives"], fraud_only["false_positives"])
    if best_single_fp > 0:
        fp_reduction = round(100.0 * (best_single_fp - fused["false_positives"]) / best_single_fp, 1)
    else:
        fp_reduction = 0.0

    return {
        "total_sessions": int(len(df)),
        "true_threats": int(df["is_threat"].sum()),
        "threats_by_type": df[df["is_threat"]]["ground_truth"].value_counts().to_dict(),
        "cyber_only": cyber_only,
        "fraud_only": fraud_only,
        "fused": fused,
        "false_positive_reduction_pct_vs_best_single_signal": fp_reduction,
    }


def demo_protect_top_case() -> Dict:
    """Protect the highest-risk case file with the PQC artifact vault (demo)."""
    state = get_state()
    if len(state.alerts) == 0:
        return {"status": "no alerts"}
    top = state.alerts.iloc[0].to_dict()
    payload = json.dumps(top, default=str).encode()
    out = pqc.protect_to_vault(payload, artifact_name=f"case_{top['session_id']}")
    return {"protected_artifact": str(out), "pqc_status": pqc.status()}


if __name__ == "__main__":
    st = run()
    print("== Detection metrics ==")
    print(json.dumps(st.metrics, indent=2, default=str))
    print("\n== Quantum posture ==")
    print(json.dumps(st.quantum_summary, indent=2))
    print("\n== Top 3 alerts ==")
    for _, a in st.alerts.head(3).iterrows():
        print(f"- {a['narrative']}")
