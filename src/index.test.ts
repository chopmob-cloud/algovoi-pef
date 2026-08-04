/**
 * Tests for @algovoi/pef -- Payment Evidence Frame v1
 * Runs under Node.js built-in test runner (node --test).
 * 22 tests, byte-for-byte parity with Python suite.
 */

import { strict as assert } from "assert";
import { describe, it } from "node:test";
import { readFileSync } from "fs";
import { join } from "path";
import {
  CANON_VERSION,
  CLAIM_TYPES,
  PEF_VERSION,
  buildPef,
  pefFrameId,
  verifyPef,
} from "./index.js";

// ---------------------------------------------------------------------------
// Shared fixtures (must match Python test fixtures byte-for-byte)
// ---------------------------------------------------------------------------

const COMPLIANCE_RECEIPT = {
  canon_version: "urn:x402:canonicalisation:jcs-rfc8785-v1",
  content_hash: "sha256:abc123",
  jurisdiction_flags: ["UK"],
  payer_ref: "sha256:def456",
  prev_hash: null,
  screen_provider_did: "did:web:api.algovoi.co.uk",
  screen_timestamp_ms: 1748534400000,
  verdict: "ALLOW",
};

const SETTLEMENT_RECEIPT = {
  canon_version: "urn:x402:canonicalisation:jcs-rfc8785-v1",
  content_hash: "sha256:aaa111",
  payment_ref: "sha256:bbb222",
  settlement_chain: "base:84532",
  settlement_provider_did: "did:web:api.algovoi.co.uk",
  settlement_status: "SETTLED",
  settlement_timestamp_ms: 1748534500000,
};

const PROVIDER_DID = "did:web:api.algovoi.co.uk";
const TS = 1748534600000;

// ---------------------------------------------------------------------------
// 1. Build -- all five claim types
// ---------------------------------------------------------------------------

describe("buildPef -- all claim types", () => {
  const cases: [string, Record<string, unknown>][] = [
    ["payment_admission",    COMPLIANCE_RECEIPT],
    ["payment_settlement",   SETTLEMENT_RECEIPT],
    ["payment_cancellation", { reason: "USER_REQUESTED", timestamp_ms: TS }],
    ["payment_refund",       { refund_result: "FULL", timestamp_ms: TS }],
    ["composite_verdict",    { verdict: "TRUSTED", evaluated_at: "2026-05-30T00:00:00Z" }],
  ];
  for (const [claim_type, receipt] of cases) {
    it(`builds ${claim_type}`, () => {
      const frame = buildPef({ claim_type, receipt, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
      assert.equal(frame.claim_type, claim_type);
      assert.equal(frame.receipt_format, CLAIM_TYPES[claim_type]);
      assert.equal(frame.pef_version, PEF_VERSION);
      assert.equal(frame.canon_version, CANON_VERSION);
      assert.equal(frame.frame_provider_did, PROVIDER_DID);
      assert.equal(frame.frame_timestamp_ms, TS);
    });
  }
});

// ---------------------------------------------------------------------------
// 2. frame_id determinism
// ---------------------------------------------------------------------------

describe("frame_id", () => {
  it("is deterministic", () => {
    const f1 = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const f2 = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    assert.equal(f1.frame_id, f2.frame_id);
  });

  it("changes with timestamp", () => {
    const f1 = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const f2 = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS + 1 });
    assert.notEqual(f1.frame_id, f2.frame_id);
  });

  it("changes with claim_type", () => {
    const f1 = buildPef({ claim_type: "payment_admission",  receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const f2 = buildPef({ claim_type: "composite_verdict", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    assert.notEqual(f1.frame_id, f2.frame_id);
  });

  it("ignores signature field", () => {
    const f = buildPef({ claim_type: "payment_settlement", receipt: SETTLEMENT_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS, signature: "sig" });
    const fNoSig = { ...f } as Record<string, unknown>;
    delete fNoSig.signature;
    assert.equal(pefFrameId(f), pefFrameId(fNoSig as any));
  });
});

// ---------------------------------------------------------------------------
// 3. receipt_hash
// ---------------------------------------------------------------------------

describe("receipt_hash", () => {
  it("is load-bearing -- different receipts produce different hashes", () => {
    const r1 = { ...COMPLIANCE_RECEIPT, verdict: "ALLOW" };
    const r2 = { ...COMPLIANCE_RECEIPT, verdict: "DENY" };
    const f1 = buildPef({ claim_type: "payment_admission", receipt: r1, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const f2 = buildPef({ claim_type: "payment_admission", receipt: r2, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    assert.notEqual(f1.receipt_hash, f2.receipt_hash);
    assert.notEqual(f1.frame_id, f2.frame_id);
  });
});

// ---------------------------------------------------------------------------
// 4. verifyPef -- green
// ---------------------------------------------------------------------------

describe("verifyPef -- valid frames", () => {
  it("passes clean frame", () => {
    const f = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const r = verifyPef(f);
    assert.equal(r.valid, true);
    assert.deepEqual(r.errors, []);
  });

  it("passes frame with signature", () => {
    const f = buildPef({ claim_type: "payment_settlement", receipt: SETTLEMENT_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS, signature: "fake-sig" });
    assert.equal(verifyPef(f).valid, true);
  });
});

// ---------------------------------------------------------------------------
// 5. verifyPef -- error paths
// ---------------------------------------------------------------------------

describe("verifyPef -- error paths", () => {
  it("rejects unknown claim_type", () => {
    const f = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const bad = { ...f, claim_type: "unknown_type" };
    const r = verifyPef(bad);
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.includes("Unknown claim_type")));
  });

  it("rejects wrong receipt_format", () => {
    const f = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const bad = { ...f, receipt_format: "wrong-format-v1" };
    assert.equal(verifyPef(bad).valid, false);
  });

  it("rejects tampered receipt", () => {
    const f = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const bad = { ...f, receipt: { ...COMPLIANCE_RECEIPT, verdict: "DENY" } };
    const r = verifyPef(bad);
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.includes("receipt_hash mismatch")));
  });

  it("rejects tampered frame_id", () => {
    const f = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const bad = { ...f, frame_id: "sha256:" + "0".repeat(64) };
    const r = verifyPef(bad);
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.includes("frame_id mismatch")));
  });

  it("rejects wrong canon_version", () => {
    const f = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const bad = { ...f, canon_version: "urn:x402:canonicalisation:jcs-rfc8785-v2" };
    assert.equal(verifyPef(bad).valid, false);
  });

  it("rejects wrong pef_version", () => {
    const f = buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
    const bad = { ...f, pef_version: "2" };
    assert.equal(verifyPef(bad).valid, false);
  });
});

// ---------------------------------------------------------------------------
// 6. Build error paths
// ---------------------------------------------------------------------------

describe("buildPef -- error paths", () => {
  it("throws on unknown claim_type", () => {
    assert.throws(
      () => buildPef({ claim_type: "bogus", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS }),
      /Unknown claim_type/
    );
  });

  it("throws on negative timestamp", () => {
    assert.throws(
      () => buildPef({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: -1 }),
      /non-negative integer/
    );
  });
});

// ---------------------------------------------------------------------------
// 7. Negative A2A-transport vector -- carried RFC 9421 signature stays unverified
//
// Reviewer property (A2A PR #1898): a signed frame serialized through an A2A
// DataPart arrives with no HTTP message context. The frame-layer verifier must
// keep frame_id / receipt_hash valid (portability preserved) yet report the
// transport signature as unverified -- never valid.
// ---------------------------------------------------------------------------

const VECTORS = JSON.parse(
  readFileSync(join(__dirname, "..", "vectors", "pef_v1.json"), "utf-8")
) as { vectors: any[] };

const NEGATIVE_VECTORS = VECTORS.vectors.filter((v) => v.negative);

describe("negative A2A-transport signature vectors", () => {
  it("at least one negative vector is present", () => {
    assert.ok(NEGATIVE_VECTORS.length > 0, "no negative vector in pef_v1.json");
  });

  for (const v of NEGATIVE_VECTORS) {
    it(`${v.vector_id}: carried signature reports unverified, frame_id parity holds`, () => {
      const pre = v.preimage;

      const signed = buildPef({
        claim_type: pre.claim_type,
        receipt: pre.receipt,
        frame_provider_did: pre.frame_provider_did,
        frame_timestamp_ms: pre.frame_timestamp_ms,
        signature: v.signature,
      });
      assert.equal(signed.signature, v.signature);

      // Portability: signature excluded from frame_id; matches Python vector.
      assert.equal(signed.receipt_hash, v.expected_receipt_hash);
      assert.equal(signed.frame_id, v.expected_frame_id);
      assert.equal(pefFrameId(signed), v.expected_frame_id);

      // Same preimage without signature yields the same frame_id.
      const unsigned = buildPef({
        claim_type: pre.claim_type,
        receipt: pre.receipt,
        frame_provider_did: pre.frame_provider_did,
        frame_timestamp_ms: pre.frame_timestamp_ms,
      });
      assert.equal(unsigned.frame_id, signed.frame_id);

      // Frame-layer verification: valid, signature present but unverified.
      const r = verifyPef(signed);
      assert.equal(r.valid, v.expected.frame_id_valid);
      assert.equal(r.valid, v.expected.receipt_hash_valid);
      assert.equal(r.signature_present, v.expected.signature_present);
      assert.equal(r.signature_verified, v.expected.signature_verified);
      assert.equal(r.signature_verified, false);
    });
  }
});
