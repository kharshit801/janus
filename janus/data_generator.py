"""Synthetic data generator for Janus.

Produces two correlated streams that a bank would normally keep in separate
silos:

1. Cybersecurity telemetry  -> one row per authenticated *session*
   (auth logs, device risk, geo, TLS crypto posture, data egress).
2. Transactional behaviour   -> zero or more banking transactions per session.

Ground-truth ``label`` is embedded so we can evaluate detection quality. The
generator injects four behaviours:

* ``BENIGN``        - normal customer / staff activity
* ``ATO_FRAUD``     - account takeover: anomalous login then high-value transfer
* ``INSIDER_FRAUD`` - legitimate login, abusive transaction pattern
* ``HNDL_QUANTUM``  - harvest-now-decrypt-later: bulk sensitive data over
                      quantum-vulnerable crypto
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from . import config

SCENARIOS = ["BENIGN", "ATO_FRAUD", "INSIDER_FRAUD", "HNDL_QUANTUM"]
# Mixture of scenarios in the generated population.
SCENARIO_MIX = [0.80, 0.08, 0.06, 0.06]

COUNTRIES = ["IN", "US", "GB", "SG", "AE", "DE", "RU", "NG", "CN"]
HIGH_RISK_COUNTRIES = {"RU", "NG", "CN"}
TXN_TYPES = ["transfer", "payment", "withdrawal", "bill_pay"]
CHANNELS = ["mobile", "web", "branch", "api"]
SENSITIVITIES = ["PII", "CREDENTIALS", "FINANCIAL", "PUBLIC"]


@dataclass
class GeneratedData:
    sessions: pd.DataFrame
    transactions: pd.DataFrame


def _choose(rng: np.random.Generator, items, p=None):
    return items[rng.choice(len(items), p=p)]


def generate(
    num_users: int = config.DEFAULT_NUM_USERS,
    num_sessions: int = config.DEFAULT_NUM_SESSIONS,
    seed: int = config.DEFAULT_SEED,
) -> GeneratedData:
    """Generate correlated telemetry + transaction data. Deterministic per seed."""
    rng = np.random.default_rng(seed)

    users = [f"U{1000 + i}" for i in range(num_users)]
    # Each user has a "home" country and typical login hour to define normalcy.
    home_country = {u: _choose(rng, COUNTRIES[:6]) for u in users}
    typical_hour = {u: int(rng.integers(8, 20)) for u in users}
    is_privileged = {u: bool(rng.random() < 0.15) for u in users}  # admins/vendors

    start = datetime(2026, 7, 1, 0, 0, 0)
    session_rows = []
    txn_rows = []

    labels = rng.choice(SCENARIOS, size=num_sessions, p=SCENARIO_MIX)

    for i, label in enumerate(labels):
        user = _choose(rng, users)
        sid = f"S{100000 + i}"
        ts = start + timedelta(minutes=int(rng.integers(0, 60 * 24 * 11)))

        row, txns = _build_session(rng, sid, user, ts, label, home_country,
                                   typical_hour, is_privileged)
        session_rows.append(row)
        txn_rows.extend(txns)

    sessions = pd.DataFrame(session_rows)
    transactions = pd.DataFrame(txn_rows) if txn_rows else pd.DataFrame(
        columns=["txn_id", "session_id", "user_id", "timestamp", "amount",
                 "txn_type", "channel", "beneficiary_new", "beneficiary_country"]
    )
    return GeneratedData(sessions=sessions, transactions=transactions)


def _build_session(rng, sid, user, ts, label, home_country, typical_hour, is_privileged):
    """Build one session row + its transactions according to the scenario."""
    home = home_country[user]
    hour = ts.hour
    priv = is_privileged[user]

    # ---- baseline (BENIGN) telemetry ----
    device_known = True
    device_risk = float(np.clip(rng.normal(0.15, 0.08), 0, 1))
    geo_country = home
    geo_distance_km = float(abs(rng.normal(20, 40)))
    impossible_travel = False
    ip_reputation = float(np.clip(rng.normal(0.1, 0.08), 0, 1))
    failed_logins = int(rng.poisson(0.2))
    mfa_used = bool(rng.random() < 0.9)
    privilege_escalation = False
    key_exchange = _choose(rng, ["ML-KEM-768", "ECDHE-P256", "ECDHE-P384"],
                           p=[0.35, 0.45, 0.20])
    cipher = _choose(rng, ["AES-256", "CHACHA20", "AES-128"], p=[0.6, 0.3, 0.1])
    bytes_out = float(abs(rng.normal(2_000_000, 1_500_000)))  # ~2 MB
    data_sensitivity = _choose(rng, SENSITIVITIES, p=[0.2, 0.1, 0.3, 0.4])
    duration = float(abs(rng.normal(12, 8)) + 1)
    n_txn = int(rng.poisson(1.2))

    # ---- scenario overrides ----
    if label == "ATO_FRAUD":
        device_known = False
        device_risk = float(np.clip(rng.normal(0.85, 0.08), 0, 1))
        geo_country = _choose(rng, list(HIGH_RISK_COUNTRIES))
        geo_distance_km = float(abs(rng.normal(6000, 1500)))
        impossible_travel = True
        ip_reputation = float(np.clip(rng.normal(0.8, 0.1), 0, 1))
        failed_logins = int(rng.integers(3, 12))
        mfa_used = bool(rng.random() < 0.2)
        hour = int(rng.choice([1, 2, 3, 4]))  # odd hours
        n_txn = int(rng.integers(1, 4))

    elif label == "INSIDER_FRAUD":
        # Login looks normal; abuse shows up in transactions / privilege use.
        priv = True
        privilege_escalation = bool(rng.random() < 0.7)
        device_risk = float(np.clip(rng.normal(0.35, 0.1), 0, 1))
        hour = int(rng.choice([21, 22, 23, 0, hour]))
        n_txn = int(rng.integers(3, 9))

    elif label == "HNDL_QUANTUM":
        # Large egress of long-lived sensitive data over quantum-vulnerable crypto.
        key_exchange = _choose(rng, ["RSA-2048", "ECDHE-P256", "DH-2048"],
                               p=[0.5, 0.3, 0.2])
        cipher = _choose(rng, ["AES-128", "3DES"], p=[0.7, 0.3])
        data_sensitivity = _choose(rng, ["PII", "CREDENTIALS", "FINANCIAL"],
                                   p=[0.5, 0.3, 0.2])
        bytes_out = float(abs(rng.normal(650_000_000, 150_000_000)))  # ~650 MB bulk
        duration = float(abs(rng.normal(90, 30)) + 10)
        device_risk = float(np.clip(rng.normal(0.4, 0.15), 0, 1))
        n_txn = int(rng.poisson(0.5))

    session = {
        "session_id": sid,
        "user_id": user,
        "timestamp": ts.isoformat(),
        "login_hour": hour,
        "is_privileged": priv,
        "device_known": device_known,
        "device_risk": round(device_risk, 4),
        "geo_country": geo_country,
        "geo_distance_km": round(geo_distance_km, 1),
        "impossible_travel": impossible_travel,
        "ip_reputation": round(ip_reputation, 4),
        "failed_logins": failed_logins,
        "mfa_used": mfa_used,
        "privilege_escalation": privilege_escalation,
        "tls_key_exchange": key_exchange,
        "tls_cipher": cipher,
        "bytes_out": round(bytes_out, 0),
        "data_sensitivity": data_sensitivity,
        "session_duration_min": round(duration, 1),
        "typical_hour": typical_hour[user],
        "label": label,
    }

    txns = _build_transactions(rng, sid, user, ts, label, n_txn)
    return session, txns


def _build_transactions(rng, sid, user, ts, label, n_txn):
    rows = []
    for j in range(n_txn):
        t_ts = ts + timedelta(minutes=int(rng.integers(0, 60)))
        beneficiary_new = bool(rng.random() < 0.2)
        beneficiary_country = _choose(rng, COUNTRIES[:6])
        txn_type = _choose(rng, TXN_TYPES)
        channel = _choose(rng, CHANNELS)
        amount = float(abs(rng.normal(4_000, 3_000)) + 100)

        if label == "ATO_FRAUD":
            amount = float(abs(rng.normal(180_000, 60_000)) + 20_000)
            beneficiary_new = True
            beneficiary_country = _choose(rng, list(HIGH_RISK_COUNTRIES))
            txn_type = "transfer"
        elif label == "INSIDER_FRAUD":
            # many mid-value transfers to a handful of new beneficiaries
            amount = float(abs(rng.normal(45_000, 15_000)) + 5_000)
            beneficiary_new = bool(rng.random() < 0.6)
            txn_type = _choose(rng, ["transfer", "payment"])

        rows.append({
            "txn_id": f"{sid}-T{j}",
            "session_id": sid,
            "user_id": user,
            "timestamp": t_ts.isoformat(),
            "amount": round(amount, 2),
            "txn_type": txn_type,
            "channel": channel,
            "beneficiary_new": beneficiary_new,
            "beneficiary_country": beneficiary_country,
        })
    return rows


def generate_and_save(seed: int = config.DEFAULT_SEED) -> GeneratedData:
    """Generate data and persist to the data directory as CSV."""
    data = generate(seed=seed)
    data.sessions.to_csv(config.DATA_DIR / "sessions.csv", index=False)
    data.transactions.to_csv(config.DATA_DIR / "transactions.csv", index=False)
    return data


if __name__ == "__main__":
    d = generate_and_save()
    print(f"Generated {len(d.sessions)} sessions and {len(d.transactions)} transactions")
    print(d.sessions["label"].value_counts())
