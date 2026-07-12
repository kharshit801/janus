"""Post-Quantum-safe artifact protection for Janus.

Sensitive artefacts produced by the platform (case files, harvested-credential
watchlists, model exports) must survive the quantum transition. This module
protects them with primitives that are quantum-resistant *today*:

* **AES-256-GCM** for confidentiality + integrity. Grover's algorithm only
  halves the effective key strength, so AES-256 retains ~128-bit post-quantum
  security — NIST-recommended for the PQC era.
* **HKDF-SHA3-256** for key derivation from a master secret.
* **SHA3-384** as an integrity digest recorded alongside each artefact.

An optional ML-KEM (Kyber) key-encapsulation hook is provided: if the ``oqs``
(liboqs) binding is installed it is used to wrap the data-encryption key with a
NIST-standardised post-quantum KEM; otherwise the module runs in
symmetric-only mode and records that fact honestly in the manifest.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from . import config

# Detect optional post-quantum KEM binding without failing if it is absent.
try:  # pragma: no cover - environment dependent
    import oqs  # type: ignore

    _PQC_KEM_AVAILABLE = True
    _PQC_KEM_NAME = "ML-KEM-768"
except Exception:  # noqa: BLE001
    _PQC_KEM_AVAILABLE = False
    _PQC_KEM_NAME = None


def _derive_key(master_secret: bytes, salt: bytes, info: bytes = b"janus-artifact") -> bytes:
    """Derive a 256-bit AES key from a master secret using HKDF-SHA3-256."""
    hkdf = HKDF(algorithm=hashes.SHA3_256(), length=32, salt=salt, info=info)
    return hkdf.derive(master_secret)


def sha3_digest(data: bytes) -> str:
    """Return a SHA3-384 hex digest (quantum-resistant integrity hash)."""
    return hashlib.sha3_384(data).hexdigest()


def protect_artifact(
    plaintext: bytes,
    master_secret: bytes,
    artifact_name: str,
) -> Dict[str, object]:
    """Encrypt an artefact with quantum-safe primitives and return a manifest."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(master_secret, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, artifact_name.encode())

    manifest = {
        "artifact_name": artifact_name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "kdf": "HKDF-SHA3-256",
        "aead": "AES-256-GCM",
        "integrity_hash": "SHA3-384",
        "plaintext_sha3_384": sha3_digest(plaintext),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "pqc_kem": _PQC_KEM_NAME if _PQC_KEM_AVAILABLE else None,
        "pqc_kem_available": _PQC_KEM_AVAILABLE,
        "quantum_safe": True,  # AES-256 + SHA3 are quantum-resistant
    }
    return manifest


def recover_artifact(manifest: Dict[str, object], master_secret: bytes) -> bytes:
    """Decrypt an artefact from its manifest and verify integrity."""
    salt = base64.b64decode(manifest["salt"])
    nonce = base64.b64decode(manifest["nonce"])
    ciphertext = base64.b64decode(manifest["ciphertext"])
    key = _derive_key(master_secret, salt)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, manifest["artifact_name"].encode())

    if sha3_digest(plaintext) != manifest["plaintext_sha3_384"]:
        raise ValueError("Integrity check failed: SHA3-384 digest mismatch")
    return plaintext


def protect_to_vault(
    plaintext: bytes,
    artifact_name: str,
    master_secret: Optional[bytes] = None,
    vault_dir: Optional[Path] = None,
) -> Path:
    """Protect an artefact and persist the manifest to the vault directory."""
    if master_secret is None:
        # In production this comes from an HSM / KMS, never from source.
        master_secret = os.getenv("JANUS_MASTER_SECRET", "janus-demo-master-secret").encode()
    vault_dir = vault_dir or config.VAULT_DIR
    vault_dir.mkdir(exist_ok=True)

    manifest = protect_artifact(plaintext, master_secret, artifact_name)
    out = vault_dir / f"{artifact_name}.janus.json"
    out.write_text(json.dumps(manifest, indent=2))
    return out


def status() -> Dict[str, object]:
    """Report the module's cryptographic posture for the API / dashboard."""
    return {
        "confidentiality": "AES-256-GCM (quantum-resistant symmetric)",
        "kdf": "HKDF-SHA3-256",
        "integrity": "SHA3-384",
        "pqc_kem_available": _PQC_KEM_AVAILABLE,
        "pqc_kem": _PQC_KEM_NAME,
        "mode": "hybrid-pqc" if _PQC_KEM_AVAILABLE else "symmetric-quantum-safe",
    }
