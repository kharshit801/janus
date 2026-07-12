"""ML anomaly-detection engine for Janus.

Two unsupervised Isolation Forests run in parallel over engineered features:

* a **cyber** model over telemetry (device, geo, auth, privilege) features, and
* a **fraud** model over aggregated transactional features.

Isolation Forest is chosen because labelled fraud/insider data is scarce in the
real world; unsupervised detection generalises to novel attack patterns. Scores
are normalised to 0-100. Because Isolation Forest is not natively explainable,
Janus attaches deterministic, human-readable *reason codes* derived from feature
deviations, which is what actually drives false-positive reduction and analyst
trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

HIGH_RISK_COUNTRIES = {"RU", "NG", "CN"}

CYBER_FEATURES = [
    "device_risk", "geo_distance_log", "impossible_travel_i", "ip_reputation",
    "failed_logins", "no_mfa", "privilege_escalation_i", "hour_deviation",
    "is_privileged_i",
]
FRAUD_FEATURES = [
    "txn_count", "txn_total_amount_log", "txn_max_amount_log",
    "new_beneficiary_ratio", "high_risk_country_ratio", "transfer_ratio",
]


def _hour_deviation(hour: int, typical: int) -> int:
    d = abs(int(hour) - int(typical))
    return min(d, 24 - d)


def build_features(sessions: pd.DataFrame, transactions: pd.DataFrame) -> pd.DataFrame:
    """Engineer per-session cyber + fraud feature vectors."""
    df = sessions.copy()

    # ---- cyber features ----
    df["geo_distance_log"] = np.log1p(df["geo_distance_km"].astype(float))
    df["impossible_travel_i"] = df["impossible_travel"].astype(int)
    df["no_mfa"] = (~df["mfa_used"].astype(bool)).astype(int)
    df["privilege_escalation_i"] = df["privilege_escalation"].astype(int)
    df["is_privileged_i"] = df["is_privileged"].astype(int)
    df["hour_deviation"] = [
        _hour_deviation(h, t) for h, t in zip(df["login_hour"], df["typical_hour"])
    ]

    # ---- fraud features (aggregate transactions per session) ----
    if len(transactions) > 0:
        tx = transactions.copy()
        tx["is_new_ben"] = tx["beneficiary_new"].astype(int)
        tx["is_high_risk"] = tx["beneficiary_country"].isin(HIGH_RISK_COUNTRIES).astype(int)
        tx["is_transfer"] = (tx["txn_type"] == "transfer").astype(int)
        agg = tx.groupby("session_id").agg(
            txn_count=("amount", "size"),
            txn_total_amount=("amount", "sum"),
            txn_max_amount=("amount", "max"),
            new_beneficiary_ratio=("is_new_ben", "mean"),
            high_risk_country_ratio=("is_high_risk", "mean"),
            transfer_ratio=("is_transfer", "mean"),
        )
    else:
        agg = pd.DataFrame()

    df = df.merge(agg, how="left", left_on="session_id", right_index=True)
    for col in ["txn_count", "txn_total_amount", "txn_max_amount",
                "new_beneficiary_ratio", "high_risk_country_ratio", "transfer_ratio"]:
        if col not in df:
            df[col] = 0.0
    df[["txn_count", "txn_total_amount", "txn_max_amount",
        "new_beneficiary_ratio", "high_risk_country_ratio",
        "transfer_ratio"]] = df[[
        "txn_count", "txn_total_amount", "txn_max_amount",
        "new_beneficiary_ratio", "high_risk_country_ratio", "transfer_ratio"]].fillna(0.0)

    df["txn_total_amount_log"] = np.log1p(df["txn_total_amount"].astype(float))
    df["txn_max_amount_log"] = np.log1p(df["txn_max_amount"].astype(float))
    return df


@dataclass
class AnomalyEngine:
    """Hybrid cyber + fraud anomaly detector."""

    random_state: int = 42
    _cyber_model: IsolationForest = field(default=None, init=False)
    _fraud_model: IsolationForest = field(default=None, init=False)
    _cyber_scaler: StandardScaler = field(default=None, init=False)
    _fraud_scaler: StandardScaler = field(default=None, init=False)
    _cyber_stats: Dict[str, Tuple[float, float]] = field(default_factory=dict, init=False)
    _fraud_stats: Dict[str, Tuple[float, float]] = field(default_factory=dict, init=False)
    _cyber_bounds: Tuple[float, float] = field(default=(0.0, 1.0), init=False)
    _fraud_bounds: Tuple[float, float] = field(default=(0.0, 1.0), init=False)
    fitted: bool = field(default=False, init=False)

    def fit(self, features: pd.DataFrame) -> "AnomalyEngine":
        self._cyber_scaler = StandardScaler().fit(features[CYBER_FEATURES])
        self._fraud_scaler = StandardScaler().fit(features[FRAUD_FEATURES])

        xc = self._cyber_scaler.transform(features[CYBER_FEATURES])
        xf = self._fraud_scaler.transform(features[FRAUD_FEATURES])

        self._cyber_model = IsolationForest(
            n_estimators=200, contamination=0.12, random_state=self.random_state
        ).fit(xc)
        self._fraud_model = IsolationForest(
            n_estimators=200, contamination=0.12, random_state=self.random_state
        ).fit(xf)

        # Raw anomaly signal: higher = more anomalous.
        raw_c = -self._cyber_model.score_samples(xc)
        raw_f = -self._fraud_model.score_samples(xf)
        self._cyber_bounds = (float(raw_c.min()), float(raw_c.max()))
        self._fraud_bounds = (float(raw_f.min()), float(raw_f.max()))

        # Per-feature mean/std for reason-code generation.
        for col in CYBER_FEATURES:
            self._cyber_stats[col] = (float(features[col].mean()), float(features[col].std() or 1.0))
        for col in FRAUD_FEATURES:
            self._fraud_stats[col] = (float(features[col].mean()), float(features[col].std() or 1.0))

        self.fitted = True
        return self

    @staticmethod
    def _normalize(raw: np.ndarray, bounds: Tuple[float, float]) -> np.ndarray:
        lo, hi = bounds
        if hi - lo < 1e-9:
            return np.zeros_like(raw)
        return np.clip((raw - lo) / (hi - lo), 0, 1) * 100.0

    def score(self, features: pd.DataFrame) -> pd.DataFrame:
        """Return per-session cyber_score and fraud_score (0-100)."""
        if not self.fitted:
            raise RuntimeError("AnomalyEngine must be fitted before scoring")
        xc = self._cyber_scaler.transform(features[CYBER_FEATURES])
        xf = self._fraud_scaler.transform(features[FRAUD_FEATURES])
        raw_c = -self._cyber_model.score_samples(xc)
        raw_f = -self._fraud_model.score_samples(xf)

        out = pd.DataFrame({
            "session_id": features["session_id"].values,
            "cyber_score": self._normalize(raw_c, self._cyber_bounds),
            "fraud_score": self._normalize(raw_f, self._fraud_bounds),
        })
        return out

    def reason_codes(self, feature_row: pd.Series, kind: str, top_n: int = 3) -> List[str]:
        """Explain a score via the top deviating features (z-score based)."""
        stats = self._cyber_stats if kind == "cyber" else self._fraud_stats
        cols = CYBER_FEATURES if kind == "cyber" else FRAUD_FEATURES
        deviations = []
        for col in cols:
            mean, std = stats.get(col, (0.0, 1.0))
            z = (float(feature_row[col]) - mean) / (std or 1.0)
            deviations.append((col, z, float(feature_row[col])))
        deviations.sort(key=lambda x: abs(x[1]), reverse=True)

        reasons = []
        for col, z, val in deviations[:top_n]:
            if abs(z) < 1.0:  # not meaningfully deviant
                continue
            reasons.append(_explain_feature(col, val, z))
        return reasons


_FEATURE_LABELS = {
    "device_risk": "device risk",
    "geo_distance_log": "geo distance from usual location",
    "impossible_travel_i": "impossible-travel flag",
    "ip_reputation": "source IP reputation risk",
    "failed_logins": "failed login attempts",
    "no_mfa": "MFA not used",
    "privilege_escalation_i": "privilege escalation",
    "is_privileged_i": "privileged account",
    "hour_deviation": "off-hours login",
    "txn_count": "transaction count",
    "txn_total_amount_log": "total transacted amount",
    "txn_max_amount_log": "largest single transaction",
    "new_beneficiary_ratio": "new-beneficiary ratio",
    "high_risk_country_ratio": "high-risk destination ratio",
    "transfer_ratio": "transfer ratio",
}


def _explain_feature(col: str, val: float, z: float) -> str:
    label = _FEATURE_LABELS.get(col, col)
    direction = "elevated" if z > 0 else "unusually low"
    return f"{label} is {direction} (z={z:+.1f})"
