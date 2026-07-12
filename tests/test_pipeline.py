"""Automated tests for the Janus pipeline, quantum monitor, PQC vault and API."""

import os

import pytest
from fastapi.testclient import TestClient

from janus import data_generator, quantum_risk, pqc, pipeline
from janus.ml_engine import AnomalyEngine, build_features
from janus.correlation import fuse_scores
from janus.api import app


# ---------------------------------------------------------------------------
# Data generation
# ---------------------------------------------------------------------------
def test_generation_is_deterministic():
    a = data_generator.generate(seed=42)
    b = data_generator.generate(seed=42)
    assert a.sessions.equals(b.sessions)
    assert len(a.sessions) == 800
    assert set(a.sessions["label"].unique()) <= set(data_generator.SCENARIOS)


# ---------------------------------------------------------------------------
# Quantum-risk monitor
# ---------------------------------------------------------------------------
def test_hndl_high_for_vulnerable_bulk_pii():
    session = {
        "tls_key_exchange": "RSA-2048", "tls_cipher": "3DES",
        "bytes_out": 600_000_000, "data_sensitivity": "PII",
    }
    res = quantum_risk.hndl_exposure(session)
    assert res["posture"] == "QUANTUM_VULNERABLE"
    assert res["quantum_risk_score"] >= 80
    assert any("Shor" in r for r in res["reasons"])


def test_hndl_low_for_safe_crypto():
    session = {
        "tls_key_exchange": "ML-KEM-768", "tls_cipher": "AES-256",
        "bytes_out": 1_000_000, "data_sensitivity": "PUBLIC",
    }
    res = quantum_risk.hndl_exposure(session)
    assert res["posture"] == "QUANTUM_SAFE"
    assert res["quantum_risk_score"] < 20


# ---------------------------------------------------------------------------
# PQC artifact vault
# ---------------------------------------------------------------------------
def test_pqc_roundtrip():
    secret = b"unit-test-master-secret"
    payload = b"top-secret harvested-credential watchlist"
    manifest = pqc.protect_artifact(payload, secret, "case_test")
    assert manifest["aead"] == "AES-256-GCM"
    assert manifest["quantum_safe"] is True
    recovered = pqc.recover_artifact(manifest, secret)
    assert recovered == payload


def test_pqc_tamper_detection():
    secret = b"unit-test-master-secret"
    manifest = pqc.protect_artifact(b"data", secret, "case_test")
    manifest["ciphertext"] = manifest["ciphertext"][:-4] + "AAAA"
    with pytest.raises(Exception):
        pqc.recover_artifact(manifest, secret)


# ---------------------------------------------------------------------------
# Fusion logic
# ---------------------------------------------------------------------------
def test_correlation_boost_applied():
    fused = fuse_scores(cyber=80, fraud=80, quantum=10)
    assert fused["cross_domain_correlated"] is True
    assert fused["correlation_boost"] > 0


def test_no_boost_for_single_signal():
    fused = fuse_scores(cyber=90, fraud=10, quantum=10)
    assert fused["cross_domain_correlated"] is False
    assert fused["correlation_boost"] == 0


# ---------------------------------------------------------------------------
# ML engine + full pipeline
# ---------------------------------------------------------------------------
def test_engine_scores_in_range():
    data = data_generator.generate(seed=7)
    feats = build_features(data.sessions, data.transactions)
    engine = AnomalyEngine(random_state=7).fit(feats)
    scores = engine.score(feats)
    assert scores["cyber_score"].between(0, 100).all()
    assert scores["fraud_score"].between(0, 100).all()


def test_pipeline_fused_beats_single_signal_on_f1():
    st = pipeline.run(seed=42)
    m = st.metrics
    assert m["fused"]["f1"] >= m["cyber_only"]["f1"]
    assert m["fused"]["false_positives"] <= m["fraud_only"]["false_positives"]
    assert m["fused"]["precision"] >= 0.9


# ---------------------------------------------------------------------------
# API smoke tests
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_api_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_api_alerts_and_detail(client):
    r = client.get("/api/alerts?limit=5&min_score=60")
    assert r.status_code == 200
    alerts = r.json()["alerts"]
    assert len(alerts) >= 1
    sid = alerts[0]["session_id"]
    d = client.get(f"/api/alerts/{sid}")
    assert d.status_code == 200
    assert "narrative" in d.json()["alert"]


def test_api_quantum_and_protect(client):
    q = client.get("/api/quantum")
    assert q.status_code == 200
    assert "pqc_module" in q.json()
    p = client.post("/api/protect-top-case")
    assert p.status_code == 200
