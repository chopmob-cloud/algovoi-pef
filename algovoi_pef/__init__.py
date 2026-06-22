"""
algovoi-pef -- Payment Evidence Frame (PEF) v1

A canonical wrapper format that frames a single AlgoVoi payment-lifecycle
receipt under a named claim_type taxonomy, with a byte-deterministic
frame_id and optional RFC 9421 transport-layer signature.

Normative spec: draft-hopley-x402-payment-evidence-frame (IETF I-D)
Canonicalisation pin: urn:x402:canonicalisation:jcs-rfc8785-v1
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

try:
    from rfc8785 import dumps as _jcs_dumps
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "algovoi-pef requires rfc8785>=0.1.4 -- pip install rfc8785"
    ) from exc

__version__ = "0.1.2"
__all__ = [
    "build_pef",
    "verify_pef",
    "pef_frame_id",
    "CLAIM_TYPES",
    "CANON_VERSION",
    "PEF_VERSION",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PEF_VERSION = "1"
CANON_VERSION = "urn:x402:canonicalisation:jcs-rfc8785-v1"

# Closed enum: claim_type -> receipt_format
CLAIM_TYPES: dict[str, str] = {
    "payment_admission":   "compliance-receipt-v1",
    "payment_settlement":  "settlement-attestation-v1",
    "payment_cancellation": "cancellation-receipt-v1",
    "payment_refund":      "refund-receipt-v1",
    "composite_verdict":   "composite-trust-query-v1",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _jcs_bytes(obj: Any) -> bytes:
    """Return RFC 8785 JCS canonical bytes for obj."""
    return _jcs_dumps(obj)


def _sha256_jcs(obj: Any) -> str:
    """Return 'sha256:<hex>' of the JCS canonical bytes of obj."""
    return "sha256:" + hashlib.sha256(_jcs_bytes(obj)).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_pef(
    *,
    claim_type: str,
    receipt: dict[str, Any],
    frame_provider_did: str,
    frame_timestamp_ms: int,
    signature: str | None = None,
) -> dict[str, Any]:
    """
    Build a Payment Evidence Frame.

    Parameters
    ----------
    claim_type : str
        One of the five closed-enum values in CLAIM_TYPES.
    receipt : dict
        The inner receipt object in its native AlgoVoi format.
    frame_provider_did : str
        DID URI of the party asserting this frame.
    frame_timestamp_ms : int
        Integer Unix epoch milliseconds of frame generation.
    signature : str, optional
        Detached RFC 9421 signature over the frame_id, if the caller
        has already computed it. The field is appended last so it does
        not affect frame_id derivation.

    Returns
    -------
    dict
        The complete PEF object, with frame_id set.

    Raises
    ------
    ValueError
        If claim_type is not in CLAIM_TYPES or frame_timestamp_ms is
        not a non-negative integer.
    TypeError
        If receipt is not a dict.
    """
    if claim_type not in CLAIM_TYPES:
        raise ValueError(
            f"Unknown claim_type {claim_type!r}. "
            f"Must be one of: {sorted(CLAIM_TYPES)}"
        )
    if not isinstance(receipt, dict):
        raise TypeError(f"receipt must be a dict, got {type(receipt).__name__}")
    if not isinstance(frame_timestamp_ms, int) or frame_timestamp_ms < 0:
        raise ValueError("frame_timestamp_ms must be a non-negative integer")

    receipt_format = CLAIM_TYPES[claim_type]
    receipt_hash = _sha256_jcs(receipt)

    # Build the preimage (everything except frame_id and signature).
    # Key order is irrelevant for JCS, but we sort for readability.
    preimage: dict[str, Any] = {
        "canon_version":      CANON_VERSION,
        "claim_type":         claim_type,
        "frame_provider_did": frame_provider_did,
        "frame_timestamp_ms": frame_timestamp_ms,
        "pef_version":        PEF_VERSION,
        "receipt":            receipt,
        "receipt_format":     receipt_format,
        "receipt_hash":       receipt_hash,
    }

    frame_id = _sha256_jcs(preimage)
    frame = {**preimage, "frame_id": frame_id}

    if signature is not None:
        frame["signature"] = signature

    return frame


def pef_frame_id(frame: dict[str, Any]) -> str:
    """
    Re-derive the frame_id from a PEF object.

    Strips frame_id and signature before hashing, as per the spec.
    Useful for verification without full verify_pef.
    """
    stripped = {
        k: v for k, v in frame.items()
        if k not in ("frame_id", "signature")
    }
    return _sha256_jcs(stripped)


def verify_pef(frame: dict[str, Any]) -> dict[str, Any]:
    """
    Verify the structural integrity of a PEF.

    Checks:
    1. pef_version is "1"
    2. claim_type is in the closed enum
    3. receipt_format matches claim_type
    4. canon_version is correct
    5. receipt_hash matches sha256(JCS(receipt))
    6. frame_id matches sha256(JCS(preimage))

    Does NOT verify the RFC 9421 signature field -- that requires
    the algovoi-rfc9421-verifier package and the signer's public key.

    Returns
    -------
    dict
        {"valid": bool, "errors": list[str]}
    """
    errors: list[str] = []

    # 1. pef_version
    if frame.get("pef_version") != PEF_VERSION:
        errors.append(
            f"pef_version must be {PEF_VERSION!r}, got {frame.get('pef_version')!r}"
        )

    # 2. claim_type
    claim_type = frame.get("claim_type")
    if claim_type not in CLAIM_TYPES:
        errors.append(
            f"Unknown claim_type {claim_type!r}. "
            f"Must be one of: {sorted(CLAIM_TYPES)}"
        )

    # 3. receipt_format
    expected_format = CLAIM_TYPES.get(claim_type)
    if expected_format and frame.get("receipt_format") != expected_format:
        errors.append(
            f"receipt_format mismatch for claim_type {claim_type!r}: "
            f"expected {expected_format!r}, got {frame.get('receipt_format')!r}"
        )

    # 4. canon_version
    if frame.get("canon_version") != CANON_VERSION:
        errors.append(
            f"canon_version must be {CANON_VERSION!r}, "
            f"got {frame.get('canon_version')!r}"
        )

    # 5. receipt_hash
    receipt = frame.get("receipt", {})
    if not isinstance(receipt, dict):
        errors.append("receipt must be a dict")
    else:
        actual_receipt_hash = _sha256_jcs(receipt)
        if actual_receipt_hash != frame.get("receipt_hash"):
            errors.append(
                f"receipt_hash mismatch: "
                f"expected {actual_receipt_hash!r}, "
                f"got {frame.get('receipt_hash')!r}"
            )

    # 6. frame_id
    actual_frame_id = pef_frame_id(frame)
    if actual_frame_id != frame.get("frame_id"):
        errors.append(
            f"frame_id mismatch: "
            f"expected {actual_frame_id!r}, "
            f"got {frame.get('frame_id')!r}"
        )

    return {"valid": len(errors) == 0, "errors": errors}
