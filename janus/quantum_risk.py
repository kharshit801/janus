"""Quantum-risk monitor for Janus.

Implements two capabilities that are largely absent from mainstream security
tooling today:

1. **Cryptographic-posture scoring** - classifies each session's key exchange
   and cipher as quantum-vulnerable (broken by Shor's algorithm) or quantum-safe.

2. **Harvest-Now-Decrypt-Later (HNDL) exposure scoring** - the real danger is
   not a weak cipher alone, but *long-lived sensitive data* moved in *bulk*
   over quantum-vulnerable crypto. Such traffic, if captured today, can be
   decrypted years later once a cryptographically relevant quantum computer
   (CRQC) exists. This module turns that into an actionable 0-100 exposure
   score with human-readable reasons.
"""

from __future__ import annotations

from typing import Dict, List

from . import config

# A "large" egress that materially increases harvesting value (~100 MB).
BULK_EGRESS_BYTES = 100_000_000


def classify_crypto(key_exchange: str, cipher: str) -> Dict[str, object]:
    """Classify a session's crypto posture as quantum vulnerable or safe."""
    kx_vuln = key_exchange in config.QUANTUM_VULNERABLE_ALGOS
    cipher_vuln = cipher in config.QUANTUM_VULNERABLE_ALGOS
    kx_safe = key_exchange in config.QUANTUM_SAFE_ALGOS

    # Key exchange dominates HNDL risk: a broken KEX exposes the whole session
    # key regardless of the symmetric cipher.
    if kx_vuln:
        posture = "QUANTUM_VULNERABLE"
    elif kx_safe:
        posture = "QUANTUM_SAFE"
    else:
        posture = "UNKNOWN"

    return {
        "posture": posture,
        "key_exchange_vulnerable": kx_vuln,
        "cipher_vulnerable": cipher_vuln,
    }


def hndl_exposure(session: dict) -> Dict[str, object]:
    """Compute an HNDL exposure score (0-100) and reasons for one session.

    ``session`` is a dict-like row from the sessions table.
    """
    kx = session.get("tls_key_exchange", "UNKNOWN")
    cipher = session.get("tls_cipher", "UNKNOWN")
    bytes_out = float(session.get("bytes_out", 0) or 0)
    sensitivity = session.get("data_sensitivity", "PUBLIC")

    crypto = classify_crypto(kx, cipher)
    longevity = config.SENSITIVITY_LONGEVITY_YEARS.get(sensitivity, 0)

    score = 0.0
    reasons: List[str] = []

    # 1) Quantum-vulnerable key exchange is the precondition for HNDL.
    if crypto["key_exchange_vulnerable"]:
        score += 45
        reasons.append(
            f"Key exchange '{kx}' is broken by Shor's algorithm (quantum-vulnerable)."
        )
    elif crypto["posture"] == "QUANTUM_SAFE":
        reasons.append(f"Key exchange '{kx}' is post-quantum safe.")
    else:
        score += 10
        reasons.append(f"Key exchange '{kx}' has unknown quantum posture.")

    # 2) Data longevity: only data that stays sensitive for years is worth
    #    harvesting.
    if longevity >= 15:
        score += 25
        reasons.append(
            f"Data class '{sensitivity}' stays sensitive ~{longevity}y — attractive to harvest."
        )
    elif longevity >= 5:
        score += 12
        reasons.append(f"Data class '{sensitivity}' has medium longevity (~{longevity}y).")

    # 3) Bulk egress amplifies harvesting value.
    if bytes_out >= BULK_EGRESS_BYTES:
        score += 25
        reasons.append(
            f"Bulk egress of {bytes_out/1e6:.0f} MB over the session (harvestable volume)."
        )
    elif bytes_out >= BULK_EGRESS_BYTES / 5:
        score += 8
        reasons.append(f"Elevated egress of {bytes_out/1e6:.0f} MB.")

    # 4) Weak symmetric cipher adds marginal risk.
    if crypto["cipher_vulnerable"]:
        score += 5
        reasons.append(f"Symmetric cipher '{cipher}' is weak against quantum attacks.")

    score = float(min(100.0, score))
    return {
        "quantum_risk_score": round(score, 1),
        "posture": crypto["posture"],
        "data_longevity_years": longevity,
        "reasons": reasons,
    }


def portfolio_summary(sessions) -> Dict[str, object]:
    """Aggregate quantum posture across all sessions for the dashboard radar."""
    total = len(sessions)
    if total == 0:
        return {"total_sessions": 0}

    vulnerable = 0
    safe = 0
    unknown = 0
    high_exposure = 0
    scores = []

    for _, s in sessions.iterrows():
        res = hndl_exposure(s.to_dict())
        scores.append(res["quantum_risk_score"])
        if res["posture"] == "QUANTUM_VULNERABLE":
            vulnerable += 1
        elif res["posture"] == "QUANTUM_SAFE":
            safe += 1
        else:
            unknown += 1
        if res["quantum_risk_score"] >= 60:
            high_exposure += 1

    pqc_readiness = round(100.0 * safe / total, 1)
    return {
        "total_sessions": total,
        "quantum_vulnerable_sessions": vulnerable,
        "quantum_safe_sessions": safe,
        "unknown_posture_sessions": unknown,
        "high_hndl_exposure_sessions": high_exposure,
        "avg_quantum_risk_score": round(float(sum(scores) / total), 1),
        "pqc_readiness_pct": pqc_readiness,
    }
