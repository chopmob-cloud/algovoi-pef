"""Validate the package against the bundled PEF v1 conformance vectors.

Every vector in ``vectors/pef_v1.json`` is rebuilt with :func:`build_pef` and
checked against its expected ``frame_id`` and ``receipt_hash``. This makes the
conformance corpus a first-class part of the test suite. The vectors are
mirrored from the authoritative corpus repo
(chopmob-cloud/algovoi-jcs-conformance-vectors, set ``pef_v1``), where the same
set is validated byte for byte across eight independent JCS implementations.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from algovoi_pef import build_pef, pef_frame_id, verify_pef

VECTORS_FILE = Path(__file__).resolve().parents[1] / "vectors" / "pef_v1.json"
_DATA = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
_VECTORS = _DATA["vectors"]


def test_vector_file_present_and_nonempty() -> None:
    assert _VECTORS, "no vectors loaded from vectors/pef_v1.json"
    assert _DATA["canon_pin"] == "urn:x402:canonicalisation:jcs-rfc8785-v1"


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["vector_id"] for v in _VECTORS])
def test_vector_reproduces_byte_for_byte(vector: dict) -> None:
    pre = vector["preimage"]
    frame = build_pef(
        claim_type=pre["claim_type"],
        receipt=pre["receipt"],
        frame_provider_did=pre["frame_provider_did"],
        frame_timestamp_ms=pre["frame_timestamp_ms"],
    )
    assert frame["receipt_hash"] == vector["expected_receipt_hash"]
    assert frame["frame_id"] == vector["expected_frame_id"]
    assert pef_frame_id(frame) == vector["expected_frame_id"]
    assert verify_pef(frame)["valid"] is True
