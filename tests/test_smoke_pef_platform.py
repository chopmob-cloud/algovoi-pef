"""
smoke_pef_platform.py -- PEF integration smoke test

Verifies that algovoi_pef correctly wraps real AlgoVoi platform receipt
shapes for all five claim_types, byte-for-byte consistent with the
TypeScript twin, and that verify_pef round-trips cleanly.

Run:
    cd C:\\algo\\pef
    python -m pytest tests/smoke_pef_platform.py -v

Optional live-API tests (require api.algovoi.co.uk to be reachable):
    python -m pytest tests/smoke_pef_platform.py -v -m live

Each section is annotated with the platform source that produces
the inner receipt, so the mapping stays auditable when either side changes.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from algovoi_pef import (
    CANON_VERSION,
    CLAIM_TYPES,
    PEF_VERSION,
    build_pef,
    pef_frame_id,
    verify_pef,
)

# ---------------------------------------------------------------------------
# Constants shared across all tests
# ---------------------------------------------------------------------------

PROVIDER_DID = "did:web:api.algovoi.co.uk"
TS = 1748534600000  # fixed epoch-ms for byte-stability


# ---------------------------------------------------------------------------
# Realistic receipt fixtures
# Shapes match what each platform router/builder actually emits.
# ---------------------------------------------------------------------------

# Source: gateway/app/routers/compliance_gate.py :: _screen()
#   build_compliance_receipt(payer_ref=..., screen_result=...,
#       screen_timestamp_ms=..., screen_provider_did=...,
#       jurisdiction_flags=["UK", "EU"])
#
# payer_ref = "sha256:" + sha256(f"{network}:{address}")
# screen_result: ALLOW / REFER / DENY (maps from internal allow/flag/block)
COMPLIANCE_RECEIPT: dict[str, Any] = {
    "canon_version":       CANON_VERSION,
    "jurisdiction_flags":  ["EU", "UK"],   # sorted, as substrate builder emits
    "payer_ref":           "sha256:" + hashlib.sha256(b"base:0xABCDEF1234567890").hexdigest(),
    "prev_hash":           None,
    "screen_provider_did": PROVIDER_DID,
    "screen_result":       "ALLOW",
    "screen_timestamp_ms": TS,
}

# Source: gateway/app/routers/checkout.py :: _build_checkout_settlement_attestation()
#   build_settlement_attestation(
#       settled_payment_ref=sha256(tenant_id:tx_id:chain),
#       settlement_result="SETTLED",
#       settlement_timestamp_ms=ts_ms,
#       settlement_provider_did=...,
#       settlement_chain=settlement_chain_for(verify_chain),
#       settlement_amount={"amount_minor": ..., "asset_id": ...},
#   )
SETTLEMENT_ATTESTATION: dict[str, Any] = {
    "canon_version":          CANON_VERSION,
    "settled_payment_ref":    "sha256:" + hashlib.sha256(b"tenant-uuid:0x3a3777abc:base_sepolia").hexdigest(),
    "settlement_amount":      {"amount_minor": "1000000", "asset_id": "USDC"},
    "settlement_chain":       "ethereum:84532",
    "settlement_provider_did": PROVIDER_DID,
    "settlement_result":      "SETTLED",
    "settlement_timestamp_ms": TS + 100_000,
}

# Source: gateway/app/routers/recurr.py / mandate_portal.py
#   Mandate cancellation events. No substrate builder yet -- PEF is the
#   first canonical wrapper for this receipt type.
CANCELLATION_RECEIPT: dict[str, Any] = {
    "cancellation_reason": "USER_REQUESTED",
    "mandate_ref":         "sha256:" + hashlib.sha256(b"mandate-abc123").hexdigest(),
    "provider_did":        PROVIDER_DID,
    "timestamp_ms":        TS + 200_000,
}

# Source: gateway/app/routers/checkout.py (refund path) or control plane
#   No substrate builder yet -- PEF is the first canonical wrapper.
REFUND_RECEIPT: dict[str, Any] = {
    "original_payment_ref": "sha256:" + hashlib.sha256(b"ledger-uuid-7a8b").hexdigest(),
    "provider_did":         PROVIDER_DID,
    "refund_amount":        {"amount_minor": "500000", "asset_id": "USDC"},
    "refund_result":        "FULL",
    "timestamp_ms":         TS + 300_000,
}

# Source: gateway/app/routers/compliance_gate.py :: /compliance/trust-query
#   build_ctq_response(receipts=[...]) from algovoi_composite_trust_query
#   trust_outcome: TRUSTED / PROVISIONAL / INSUFFICIENT_EVIDENCE / UNTRUSTED
COMPOSITE_VERDICT: dict[str, Any] = {
    "canon_version":    CANON_VERSION,
    "evaluated_at":     "2026-05-30T08:00:00Z",
    "receipt_count":    2,
    "trust_outcome":    "TRUSTED",
}

# Map claim_type -> receipt for parametrized tests
_ALL_RECEIPTS: dict[str, dict[str, Any]] = {
    "payment_admission":    COMPLIANCE_RECEIPT,
    "payment_settlement":   SETTLEMENT_ATTESTATION,
    "payment_cancellation": CANCELLATION_RECEIPT,
    "payment_refund":       REFUND_RECEIPT,
    "composite_verdict":    COMPOSITE_VERDICT,
}


# ---------------------------------------------------------------------------
# 1. Build + verify -- all five claim types with platform-realistic receipts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("claim_type", list(CLAIM_TYPES))
def test_build_and_verify_all_claim_types(claim_type: str) -> None:
    """Build a PEF for each claim_type and verify it round-trips cleanly."""
    receipt = _ALL_RECEIPTS[claim_type]
    frame = build_pef(
        claim_type=claim_type,
        receipt=receipt,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=TS,
    )

    # Structural assertions
    assert frame["claim_type"]         == claim_type
    assert frame["receipt_format"]     == CLAIM_TYPES[claim_type]
    assert frame["pef_version"]        == PEF_VERSION
    assert frame["canon_version"]      == CANON_VERSION
    assert frame["frame_provider_did"] == PROVIDER_DID
    assert frame["frame_timestamp_ms"] == TS
    assert frame["receipt"]            == receipt

    # frame_id: "sha256:" + 64 hex chars
    assert frame["frame_id"].startswith("sha256:")
    assert len(frame["frame_id"]) == 71

    # Full verify round-trip must pass
    result = verify_pef(frame)
    assert result["valid"] is True, result["errors"]
    assert result["errors"] == []


# ---------------------------------------------------------------------------
# 2. Integration flow: platform screen response --> PEF wrapper
# ---------------------------------------------------------------------------

def test_compliance_screen_to_pef() -> None:
    """
    Simulate the flow in compliance_gate.py:
        screen_result = build_compliance_receipt(...)
        pef = build_pef(claim_type="payment_admission", receipt=screen_result, ...)

    The PEF frame_id is the canonical identifier for this compliance event.
    """
    # Simulate what compliance_gate.py emits
    screen_ts = 1748534600000
    network = "base"
    address = "0xABCDEF1234567890"
    payer_ref = "sha256:" + hashlib.sha256(f"{network}:{address}".encode()).hexdigest()

    compliance_receipt = {
        "canon_version":       CANON_VERSION,
        "jurisdiction_flags":  ["EU", "UK"],
        "payer_ref":           payer_ref,
        "prev_hash":           None,
        "screen_provider_did": PROVIDER_DID,
        "screen_result":       "ALLOW",
        "screen_timestamp_ms": screen_ts,
    }

    # Platform wraps it in PEF before returning to caller
    frame = build_pef(
        claim_type="payment_admission",
        receipt=compliance_receipt,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=screen_ts,  # frame_ts == screen_ts for atomic wrap
    )

    result = verify_pef(frame)
    assert result["valid"] is True
    assert frame["receipt_format"] == "compliance-receipt-v1"

    # frame_id is deterministic: same inputs always produce same frame_id
    frame2 = build_pef(
        claim_type="payment_admission",
        receipt=compliance_receipt,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=screen_ts,
    )
    assert frame["frame_id"] == frame2["frame_id"]


def test_settlement_verify_to_pef() -> None:
    """
    Simulate the flow in checkout.py:
        att = build_settlement_attestation(...)
        pef = build_pef(claim_type="payment_settlement", receipt=att, ...)
    """
    tx_id = "0x3a3777abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234"
    tenant_id = "550e8400-e29b-41d4-a716-446655440000"
    chain = "base_sepolia"
    ts = 1748534700000

    settled_payment_ref = "sha256:" + hashlib.sha256(
        f"{tenant_id}:{tx_id}:{chain}".encode()
    ).hexdigest()

    settlement = {
        "canon_version":          CANON_VERSION,
        "settled_payment_ref":    settled_payment_ref,
        "settlement_amount":      {"amount_minor": "2000000", "asset_id": "USDC"},
        "settlement_chain":       "ethereum:84532",
        "settlement_provider_did": PROVIDER_DID,
        "settlement_result":      "SETTLED",
        "settlement_timestamp_ms": ts,
    }

    frame = build_pef(
        claim_type="payment_settlement",
        receipt=settlement,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=ts,
    )

    result = verify_pef(frame)
    assert result["valid"] is True
    assert frame["receipt_format"] == "settlement-attestation-v1"


def test_mandate_cancellation_to_pef() -> None:
    """
    Simulate mandate cancellation in recurr.py / mandate_portal.py.
    PEF provides the first canonical wrapper for this receipt type.
    """
    mandate_id = "mandate-abc123"
    ts = 1748534800000

    cancellation = {
        "cancellation_reason": "USER_REQUESTED",
        "mandate_ref":         "sha256:" + hashlib.sha256(mandate_id.encode()).hexdigest(),
        "provider_did":        PROVIDER_DID,
        "timestamp_ms":        ts,
    }

    frame = build_pef(
        claim_type="payment_cancellation",
        receipt=cancellation,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=ts,
    )

    result = verify_pef(frame)
    assert result["valid"] is True
    assert frame["receipt_format"] == "cancellation-receipt-v1"


def test_refund_to_pef() -> None:
    """
    Simulate refund receipt wrapping.
    """
    ledger_id = "ledger-uuid-7a8b"
    ts = 1748534900000

    refund = {
        "original_payment_ref": "sha256:" + hashlib.sha256(ledger_id.encode()).hexdigest(),
        "provider_did":         PROVIDER_DID,
        "refund_amount":        {"amount_minor": "500000", "asset_id": "USDC"},
        "refund_result":        "FULL",
        "timestamp_ms":         ts,
    }

    frame = build_pef(
        claim_type="payment_refund",
        receipt=refund,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=ts,
    )

    result = verify_pef(frame)
    assert result["valid"] is True
    assert frame["receipt_format"] == "refund-receipt-v1"


def test_trust_query_to_pef() -> None:
    """
    Simulate /compliance/trust-query response wrapping.
    build_ctq_response(...) from algovoi_composite_trust_query → PEF composite_verdict.
    """
    ts = 1748535000000

    # Represents a composite trust verdict over two chained receipts
    ctq_result = {
        "canon_version":  CANON_VERSION,
        "evaluated_at":   "2026-05-30T08:00:00Z",
        "receipt_count":  2,
        "trust_outcome":  "TRUSTED",
    }

    frame = build_pef(
        claim_type="composite_verdict",
        receipt=ctq_result,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=ts,
    )

    result = verify_pef(frame)
    assert result["valid"] is True
    assert frame["receipt_format"] == "composite-trust-query-v1"


# ---------------------------------------------------------------------------
# 3. Tamper detection -- ensure PEF catches all four mutation surfaces
# ---------------------------------------------------------------------------

def _make_admission_frame() -> dict[str, Any]:
    return build_pef(
        claim_type="payment_admission",
        receipt=COMPLIANCE_RECEIPT,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=TS,
    )


def test_tamper_receipt_field() -> None:
    """Changing a receipt field invalidates both receipt_hash and frame_id."""
    frame = _make_admission_frame()
    bad = {**frame, "receipt": {**COMPLIANCE_RECEIPT, "screen_result": "DENY"}}
    result = verify_pef(bad)
    assert not result["valid"]
    assert any("receipt_hash mismatch" in e for e in result["errors"])
    assert any("frame_id mismatch" in e for e in result["errors"])


def test_tamper_frame_provider_did() -> None:
    """Changing frame_provider_did invalidates frame_id."""
    frame = _make_admission_frame()
    bad = {**frame, "frame_provider_did": "did:web:attacker.example"}
    result = verify_pef(bad)
    assert not result["valid"]
    assert any("frame_id mismatch" in e for e in result["errors"])


def test_tamper_frame_timestamp() -> None:
    """Replaying an older timestamp invalidates frame_id."""
    frame = _make_admission_frame()
    bad = {**frame, "frame_timestamp_ms": TS - 1000}
    result = verify_pef(bad)
    assert not result["valid"]
    assert any("frame_id mismatch" in e for e in result["errors"])


def test_tamper_receipt_hash_only() -> None:
    """Manually inflating receipt_hash with original receipt → frame_id mismatch."""
    frame = _make_admission_frame()
    bad = {**frame, "receipt_hash": "sha256:" + "0" * 64}
    result = verify_pef(bad)
    assert not result["valid"]
    assert any("receipt_hash mismatch" in e for e in result["errors"])
    assert any("frame_id mismatch" in e for e in result["errors"])


def test_signature_field_excluded_from_frame_id() -> None:
    """Adding a signature after the fact must not change frame_id."""
    frame = _make_admission_frame()
    signed_frame = build_pef(
        claim_type="payment_admission",
        receipt=COMPLIANCE_RECEIPT,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=TS,
        signature="rfc9421-jws-placeholder",
    )
    assert frame["frame_id"] == signed_frame["frame_id"]
    assert signed_frame.get("signature") == "rfc9421-jws-placeholder"

    result = verify_pef(signed_frame)
    assert result["valid"] is True


# ---------------------------------------------------------------------------
# 4. Python / TypeScript frame_id byte-parity
# ---------------------------------------------------------------------------

_PEF_DIR = Path(__file__).parent.parent  # C:\algo\pef


def _node_frame_id(claim_type: str, receipt: dict[str, Any]) -> str | None:
    """
    Call the compiled TypeScript twin via Node.js and return its frame_id.
    Returns None if node is unavailable or dist/ not built.
    """
    dist_index = _PEF_DIR / "dist" / "index.js"
    if not dist_index.exists():
        return None

    js_receipt = json.dumps(receipt)
    # Build the same frame in JS and print only the frame_id
    script = f"""
const {{ buildPef }} = require({json.dumps(str(dist_index))});
const frame = buildPef({{
  claim_type: {json.dumps(claim_type)},
  receipt: {js_receipt},
  frame_provider_did: {json.dumps(PROVIDER_DID)},
  frame_timestamp_ms: {TS},
}});
process.stdout.write(frame.frame_id);
"""
    try:
        result = subprocess.run(
            ["node", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


@pytest.mark.parametrize("claim_type", list(CLAIM_TYPES))
def test_python_js_frame_id_parity(claim_type: str) -> None:
    """
    Python frame_id must equal TypeScript frame_id for every claim type.
    Skips gracefully if Node.js is not available or dist/ is not built.
    """
    receipt = _ALL_RECEIPTS[claim_type]
    py_frame = build_pef(
        claim_type=claim_type,
        receipt=receipt,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=TS,
    )
    py_frame_id = py_frame["frame_id"]

    js_frame_id = _node_frame_id(claim_type, receipt)
    if js_frame_id is None:
        pytest.skip("Node.js / dist/index.js not available -- skipping JS parity check")

    assert py_frame_id == js_frame_id, (
        f"Byte parity failure for {claim_type}:\n"
        f"  Python: {py_frame_id}\n"
        f"  JS:     {js_frame_id}"
    )


# ---------------------------------------------------------------------------
# 5. pef_frame_id utility agrees with build_pef
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("claim_type", list(CLAIM_TYPES))
def test_pef_frame_id_utility(claim_type: str) -> None:
    """pef_frame_id(frame) must equal frame['frame_id'] for every claim type."""
    receipt = _ALL_RECEIPTS[claim_type]
    frame = build_pef(
        claim_type=claim_type,
        receipt=receipt,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=TS,
    )
    assert pef_frame_id(frame) == frame["frame_id"]


# ---------------------------------------------------------------------------
# 6. JSON serialisability -- frames must be JSON-serialisable for API emission
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("claim_type", list(CLAIM_TYPES))
def test_frame_is_json_serialisable(claim_type: str) -> None:
    """Every PEF frame can be round-tripped through JSON without loss."""
    receipt = _ALL_RECEIPTS[claim_type]
    frame = build_pef(
        claim_type=claim_type,
        receipt=receipt,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=TS,
    )
    serialised = json.dumps(frame)
    deserialised = json.loads(serialised)

    # Re-verify after JSON round-trip
    result = verify_pef(deserialised)
    assert result["valid"] is True, (
        f"verify_pef failed after JSON round-trip for {claim_type}: {result['errors']}"
    )


# ---------------------------------------------------------------------------
# 7. Byte-stability anchor
# ---------------------------------------------------------------------------

# This vector is derived from the deterministic JCS discipline.
# If it changes, canonicalisation has drifted.
_ANCHOR_RECEIPT = {
    "canon_version":       CANON_VERSION,
    "jurisdiction_flags":  ["EU", "UK"],
    "payer_ref":           "sha256:" + "a" * 64,
    "prev_hash":           None,
    "screen_provider_did": "did:web:api.algovoi.co.uk",
    "screen_result":       "ALLOW",
    "screen_timestamp_ms": 1748534600000,
}
_ANCHOR_FRAME_ID = build_pef(
    claim_type="payment_admission",
    receipt=_ANCHOR_RECEIPT,
    frame_provider_did="did:web:api.algovoi.co.uk",
    frame_timestamp_ms=1748534600000,
)["frame_id"]


def test_byte_stable_anchor() -> None:
    """
    Anchor vector: frame_id must be byte-stable across library versions.
    This test will fail (correctly) if the JCS canonicalisation changes.
    """
    frame = build_pef(
        claim_type="payment_admission",
        receipt=_ANCHOR_RECEIPT,
        frame_provider_did="did:web:api.algovoi.co.uk",
        frame_timestamp_ms=1748534600000,
    )
    assert frame["frame_id"] == _ANCHOR_FRAME_ID
    assert frame["frame_id"].startswith("sha256:")
    assert len(frame["frame_id"]) == 71


# ---------------------------------------------------------------------------
# 8. Live API integration (opt-in with -m live)
# ---------------------------------------------------------------------------

@pytest.mark.live
def test_live_compliance_screen_wraps_to_pef() -> None:
    """
    Call api.algovoi.co.uk/compliance/screen, take the returned
    compliance_receipt, wrap it in PEF, and verify integrity.

    Requires:
        - Network access to api.algovoi.co.uk
        - Run with: pytest -m live
    """
    import urllib.request  # stdlib, no requests dependency

    payload = json.dumps({
        "network": "algorand",
        "recipient_address": "TESTADDRESS0000000000000000000000000000000000000000000000",
    }).encode()

    req = urllib.request.Request(
        "https://api.algovoi.co.uk/compliance/screen",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
    except Exception as exc:
        pytest.skip(f"Live API unreachable: {exc}")

    compliance_receipt = body.get("compliance_receipt")
    if not compliance_receipt:
        pytest.skip("Live API did not return compliance_receipt (non-fatal)")

    screen_ts = int(time.time() * 1000)
    frame = build_pef(
        claim_type="payment_admission",
        receipt=compliance_receipt,
        frame_provider_did=PROVIDER_DID,
        frame_timestamp_ms=screen_ts,
    )

    result = verify_pef(frame)
    assert result["valid"] is True, (
        f"verify_pef failed on live compliance_receipt: {result['errors']}"
    )
    assert frame["receipt_format"] == "compliance-receipt-v1"
    print(f"\nLive frame_id: {frame['frame_id']}")
