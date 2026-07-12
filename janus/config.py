"""Central configuration and shared constants for Janus."""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
VAULT_DIR = BASE_DIR / "vault"

DATA_DIR.mkdir(exist_ok=True)
VAULT_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Data generation defaults
# ---------------------------------------------------------------------------
DEFAULT_SEED = int(os.getenv("JANUS_SEED", "42"))
DEFAULT_NUM_USERS = int(os.getenv("JANUS_USERS", "60"))
DEFAULT_NUM_SESSIONS = int(os.getenv("JANUS_SESSIONS", "800"))

# ---------------------------------------------------------------------------
# Risk scoring weights (fusion engine)
# ---------------------------------------------------------------------------
# The fused risk score is a weighted blend of the three analytic pillars.
FUSION_WEIGHTS = {
    "cyber": 0.40,      # cyber-telemetry anomaly component
    "fraud": 0.40,      # transactional-fraud anomaly component
    "quantum": 0.20,    # quantum / HNDL exposure component
}

# Risk band thresholds on a 0-100 scale.
RISK_BANDS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (35, "MEDIUM"),
    (0, "LOW"),
]

# ---------------------------------------------------------------------------
# Cryptography posture reference data (used by the quantum-risk monitor)
# ---------------------------------------------------------------------------
# Classifies observed cipher/key-exchange strings as quantum-vulnerable or safe.
# Symmetric AES-256 and SHA-3/384+ are considered quantum-resistant (Grover only
# halves effective strength); RSA / classic ECDH / ECDSA are broken by Shor.
QUANTUM_VULNERABLE_ALGOS = {
    "RSA-1024", "RSA-2048", "RSA-4096",
    "ECDHE-P256", "ECDHE-P384", "ECDSA-P256",
    "DH-2048", "3DES", "AES-128",
}
QUANTUM_SAFE_ALGOS = {
    "ML-KEM-768", "ML-KEM-1024", "KYBER-768", "KYBER-1024",
    "ML-DSA-65", "DILITHIUM-3", "AES-256", "CHACHA20", "SHA3-384",
}

# Data-sensitivity longevity (years the data stays sensitive). Long-lived
# sensitive data over quantum-vulnerable crypto is the core HNDL exposure.
SENSITIVITY_LONGEVITY_YEARS = {
    "PII": 25,
    "CREDENTIALS": 15,
    "FINANCIAL": 10,
    "PUBLIC": 0,
}


def risk_band(score: float) -> str:
    """Map a 0-100 risk score to a categorical band."""
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "LOW"
