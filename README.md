> **AlgoVoi is available for acquisition** -- [docs.algovoi.co.uk/acquisition](https://docs.algovoi.co.uk/acquisition)

---

# algovoi-pef

[![PyPI](https://img.shields.io/pypi/v/algovoi-pef)](https://pypi.org/project/algovoi-pef/)
[![npm](https://img.shields.io/npm/v/@algovoi/pef)](https://www.npmjs.com/package/@algovoi/pef)
[![Cross-validated](https://img.shields.io/badge/cross--validated-64%2F64-brightgreen)](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors/blob/main/_attestations/2026-05-30-8-impl-pef-v1.md)
[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)](./LICENSE)

**Payment Evidence Frame (PEF) v1** -- a canonical wrapper format for
AlgoVoi payment-lifecycle receipts. Each frame carries a byte-deterministic
`frame_id` (SHA-256 of the JCS-canonical preimage) and an optional detached
RFC 9421 signature field.

Normative spec: `draft-hopley-x402-payment-evidence-frame` (IETF I-D, filing pending).  
Canonicalisation pin: `urn:x402:canonicalisation:jcs-rfc8785-v1`.

## Install

```bash
pip install algovoi-pef          # Python
npm install @algovoi/pef         # TypeScript / JavaScript
```

## Quick start

```python
from algovoi_pef import build_pef, verify_pef

# Wrap a compliance receipt in a PEF frame
frame = build_pef(
    claim_type="payment_admission",
    receipt={
        "canon_version": "urn:x402:canonicalisation:jcs-rfc8785-v1",
        "jurisdiction_flags": ["EU", "UK"],
        "payer_ref": "sha256:abc123...",
        "prev_hash": None,
        "screen_provider_did": "did:web:api.algovoi.co.uk",
        "screen_result": "ALLOW",
        "screen_timestamp_ms": 1748534600000,
    },
    frame_provider_did="did:web:api.algovoi.co.uk",
    frame_timestamp_ms=1748534600000,
)

result = verify_pef(frame)
assert result["valid"]
print(frame["frame_id"])
# sha256:09929082c83d5006f61f06bb12eb58cc2c21acebd70a31bca3cb26169c11b6bf
```

```typescript
import { buildPef, verifyPef } from "@algovoi/pef";

const frame = buildPef({
  claim_type: "payment_settlement",
  receipt: {
    canon_version: "urn:x402:canonicalisation:jcs-rfc8785-v1",
    settled_payment_ref: "sha256:abc123...",
    settlement_chain: "ethereum:84532",
    settlement_provider_did: "did:web:api.algovoi.co.uk",
    settlement_result: "SETTLED",
    settlement_timestamp_ms: 1748534700000,
  },
  frame_provider_did: "did:web:api.algovoi.co.uk",
  frame_timestamp_ms: 1748534700000,
});

const result = verifyPef(frame);
console.log(result.valid);   // true
console.log(frame.frame_id); // sha256:...
```

## Claim types

PEF defines five claim types, each mapping to an IETF I-D-anchored receipt format:

| `claim_type` | `receipt_format` | IETF I-D | Platform source |
|---|---|---|---|
| `payment_admission` | `compliance-receipt-v1` | `draft-hopley-x402-compliance-receipt` | `/compliance/screen` |
| `payment_settlement` | `settlement-attestation-v1` | `draft-hopley-x402-settlement-attestation` | `/checkout/{t}/verify` |
| `payment_cancellation` | `cancellation-receipt-v1` | `draft-hopley-x402-cancellation-receipt` | mandate cancel endpoints |
| `payment_refund` | `refund-receipt-v1` | `draft-hopley-x402-refund-receipt` | refund endpoints |
| `composite_verdict` | `composite-trust-query-v1` | `draft-hopley-x402-composite-trust-query` | `/compliance/trust-query` |

## Frame structure

```json
{
  "canon_version":      "urn:x402:canonicalisation:jcs-rfc8785-v1",
  "claim_type":         "payment_admission",
  "frame_id":           "sha256:<64-hex-chars>",
  "frame_provider_did": "did:web:api.algovoi.co.uk",
  "frame_timestamp_ms": 1748534600000,
  "pef_version":        "1",
  "receipt":            { "..." : "..." },
  "receipt_format":     "compliance-receipt-v1",
  "receipt_hash":       "sha256:<64-hex-chars>",
  "signature":          "<RFC 9421 detached JWS -- optional>"
}
```

### frame_id derivation

```
receipt_hash = "sha256:" + hex(sha256(JCS(receipt)))

preimage = {
  canon_version, claim_type, frame_provider_did,
  frame_timestamp_ms, pef_version, receipt,
  receipt_format, receipt_hash
}

frame_id = "sha256:" + hex(sha256(JCS(preimage)))
```

`signature` is appended after `frame_id` is set and is excluded from both
hash inputs. Signing the `frame_id` (rather than the full frame body) keeps
the signature stable across re-serialisations.

## API

### Python

```python
from algovoi_pef import build_pef, verify_pef, pef_frame_id, CLAIM_TYPES

# Build a frame
frame = build_pef(
    claim_type="payment_admission",   # str -- must be in CLAIM_TYPES
    receipt={...},                    # dict
    frame_provider_did="did:...",     # str
    frame_timestamp_ms=1748534600000, # int, epoch-ms
    signature="...",                  # str, optional RFC 9421 JWS
)

# Verify structural integrity (does NOT verify the RFC 9421 signature)
result = verify_pef(frame)
# {"valid": True, "errors": []}

# Re-derive frame_id from an existing frame
fid = pef_frame_id(frame)

# Inspect the closed enum
print(CLAIM_TYPES)
# {"payment_admission": "compliance-receipt-v1", ...}
```

### TypeScript

```typescript
import {
  buildPef, verifyPef, pefFrameId,
  CLAIM_TYPES, PEF_VERSION, CANON_VERSION,
  type BuildPefOptions, type Pef, type VerifyResult,
} from "@algovoi/pef";

const frame: Pef        = buildPef({ claim_type, receipt, frame_provider_did, frame_timestamp_ms });
const result: VerifyResult = verifyPef(frame);
const fid: string       = pefFrameId(frame);
```

## Platform integration

`shared.utils.pef_wrapper` in the AlgoVoi gateway provides soft-import helpers
so each router can emit PEF-wrapped receipts alongside existing fields:

```python
from shared.utils.pef_wrapper import (
    wrap_compliance_receipt,      # payment_admission
    wrap_settlement_attestation,  # payment_settlement
    wrap_cancellation_receipt,    # payment_cancellation
    wrap_refund_receipt,          # payment_refund
    wrap_trust_query_response,    # composite_verdict
)

# compliance_gate.py -- returns None gracefully if algovoi-pef not installed
pef_frame = wrap_compliance_receipt(
    compliance_receipt_dict,
    screen_timestamp_ms=screen_ts,
)
```

All wrappers use `pef_or_none()` -- they return `None` during a rolling deploy
before `algovoi-pef` is added to the platform requirements, so existing API
responses are unaffected.

## Cross-implementation validation

`frame_id` derivation has been independently validated across **eight JCS
implementations in eight programming languages** -- **64/64 byte-for-byte
agreements** across all five claim types (both `receipt_hash` and `frame_id`
layers per vector):

| Language | Runtime | JCS library | Author |
|---|---|---|---|
| Python | CPython 3.12 | `rfc8785` 0.1.4 | Trail of Bits |
| JavaScript | Node.js v24 | `canonicalize` 1.0.8 | Samuel Erdtman |
| Ruby | Ruby 3.4 | `json-canonicalization` 1.0.0 | RubyGems community |
| PHP | PHP 8.4 | inline pure-stdlib JCS | AlgoVoi |
| Go | Go 1.26 | `gowebpki/jcs` v1.0.1 | Web PKI Working Group |
| Rust | Rust 1.95 | `serde_jcs` 0.2.0 | l1h3r |
| Java | JDK 17 | `erdtman/java-json-canonicalization` 1.1 | Anders Rundgren (RFC 8785 author) + Samuel Erdtman |
| .NET | .NET 9 | `Baqhub.Packages.JsonCanonicalization` 1.0.1 | Baqhub |

Full attestation record and reproducible runner harnesses:
[`_attestations/2026-05-30-8-impl-pef-v1.md`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors/blob/main/_attestations/2026-05-30-8-impl-pef-v1.md)
in [`chopmob-cloud/algovoi-jcs-conformance-vectors`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors).

The same corpus now has **576/576 cumulative byte-for-byte agreements** across
eight vector sets covering the full AlgoVoi agentic-payment receipt stack
(admission, settlement, cancellation, refund, composite verdict, PEF).

## Tests

```bash
# Unit tests (24 tests)
python -m pytest tests/test_pef.py -v

# Integration smoke tests -- platform-realistic receipt shapes + JS parity (32 tests)
python -m pytest tests/test_smoke_pef_platform.py -v

# Full suite (56 tests)
python -m pytest tests/ -v

# Live API integration test (requires network access to api.algovoi.co.uk)
python -m pytest tests/test_smoke_pef_platform.py -v -m live

# TypeScript tests (20 tests)
npm run build && npm test
```

## Specification

- **Normative spec**: `draft-hopley-x402-payment-evidence-frame` (IETF I-D, filing pending)
- **Canonicalisation pin**: [`draft-hopley-x402-canonicalisation-jcs-v1`](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/)
- **Receipt format I-Ds**:
  - [`draft-hopley-x402-compliance-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/)
  - [`draft-hopley-x402-settlement-attestation`](https://datatracker.ietf.org/doc/draft-hopley-x402-settlement-attestation/)
  - [`draft-hopley-x402-cancellation-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-cancellation-receipt/)
  - [`draft-hopley-x402-refund-receipt`](https://datatracker.ietf.org/doc/draft-hopley-x402-refund-receipt/)
  - [`draft-hopley-x402-composite-trust-query`](https://datatracker.ietf.org/doc/draft-hopley-x402-composite-trust-query/)
- **Upstream x402 PRs**:
  [#2493](https://github.com/x402-foundation/x402/pull/2493) /
  [#2494](https://github.com/x402-foundation/x402/pull/2494) /
  [#2495](https://github.com/x402-foundation/x402/pull/2495) /
  [#2524](https://github.com/x402-foundation/x402/pull/2524) /
  [#2525](https://github.com/x402-foundation/x402/pull/2525)
- **Conformance vectors**: [`pef_v1`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors/tree/main/vectors/pef_v1) in `chopmob-cloud/algovoi-jcs-conformance-vectors`

## Acknowledgments

Cross-implementation validation is possible because of the independent JCS
libraries listed in the matrix above. AlgoVoi acknowledges with thanks:
Trail of Bits (`rfc8785`), Samuel Erdtman (`canonicalize` and
`java-json-canonicalization`), Anders Rundgren (RFC 8785 author, Java
implementation), Web PKI Working Group (`gowebpki/jcs`), l1h3r (`serde_jcs`),
Baqhub (`Baqhub.Packages.JsonCanonicalization`), and the RubyGems community
(`json-canonicalization`).

## Licence

Apache 2.0. See [LICENSE](./LICENSE).

## Author

AlgoVoi (Christopher Hopley, [`chopmob-cloud`](https://github.com/chopmob-cloud))
