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


_NEGATIVE_VECTORS = [v for v in _VECTORS if v.get("negative")]


def test_negative_transport_vector_present() -> None:
    """At least one negative A2A-transport signature vector must exist."""
    assert _NEGATIVE_VECTORS, "no negative transport-signature vector in pef_v1.json"


@pytest.mark.parametrize(
    "vector", _NEGATIVE_VECTORS, ids=[v["vector_id"] for v in _NEGATIVE_VECTORS]
)
def test_negative_transport_signature_unverified(vector: dict) -> None:
    """A signed frame delivered with no HTTP context (A2A DataPart) must keep
    frame_id and receipt_hash valid (portability preserved) while the carried
    RFC 9421 transport signature is reported unverified at the frame layer.

    This asserts the reviewer-requested property (A2A PR #1898): a frame-layer
    verifier does not, and must not, treat the embedded signature as valid.
    """
    pre = vector["preimage"]
    signature = vector["signature"]

    # Build the frame exactly as delivered: with the carried signature.
    signed = build_pef(
        claim_type=pre["claim_type"],
        receipt=pre["receipt"],
        frame_provider_did=pre["frame_provider_did"],
        frame_timestamp_ms=pre["frame_timestamp_ms"],
        signature=signature,
    )
    assert signed.get("signature") == signature

    # Portability property: the signature is excluded from frame_id, so the
    # frame_id and receipt_hash still validate byte-for-byte.
    assert signed["receipt_hash"] == vector["expected_receipt_hash"]
    assert signed["frame_id"] == vector["expected_frame_id"]
    assert pef_frame_id(signed) == vector["expected_frame_id"]

    # An unsigned build of the same preimage yields the SAME frame_id, proving
    # the transport signature is not covered by the frame identity.
    unsigned = build_pef(
        claim_type=pre["claim_type"],
        receipt=pre["receipt"],
        frame_provider_did=pre["frame_provider_did"],
        frame_timestamp_ms=pre["frame_timestamp_ms"],
    )
    assert unsigned["frame_id"] == signed["frame_id"]

    # Frame-layer verification: structurally valid, signature reported
    # present-but-unverified -- never valid.
    result = verify_pef(signed)
    exp = vector["expected"]
    assert result["valid"] is exp["frame_id_valid"] is exp["receipt_hash_valid"] is True
    assert result["signature_present"] is exp["signature_present"] is True
    assert result["signature_verified"] is exp["signature_verified"] is False
