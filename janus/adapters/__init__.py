"""External-dataset adapters for Janus.

These adapters map public, real-world datasets onto the Janus session +
transaction schema so the fusion engine can be validated on data it did not
generate. This demonstrates that the engine generalises beyond the synthetic
generator in :mod:`janus.data_generator`.

Currently supported:

* ``adapt_ieee_cis`` — IEEE-CIS Fraud Detection dataset (Kaggle).
* ``adapt_cert_insider`` — CERT Insider Threat dataset r4.2 / r6.2 (CMU kilthub).
"""

from __future__ import annotations

from .external import adapt_cert_insider, adapt_ieee_cis

__all__ = ["adapt_ieee_cis", "adapt_cert_insider"]
