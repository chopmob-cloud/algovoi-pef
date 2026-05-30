"use strict";
/**
 * Tests for @algovoi/pef -- Payment Evidence Frame v1
 * Runs under Node.js built-in test runner (node --test).
 * 22 tests, byte-for-byte parity with Python suite.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const assert_1 = require("assert");
const node_test_1 = require("node:test");
const index_js_1 = require("./index.js");
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
(0, node_test_1.describe)("buildPef -- all claim types", () => {
    const cases = [
        ["payment_admission", COMPLIANCE_RECEIPT],
        ["payment_settlement", SETTLEMENT_RECEIPT],
        ["payment_cancellation", { reason: "USER_REQUESTED", timestamp_ms: TS }],
        ["payment_refund", { refund_result: "FULL", timestamp_ms: TS }],
        ["composite_verdict", { verdict: "TRUSTED", evaluated_at: "2026-05-30T00:00:00Z" }],
    ];
    for (const [claim_type, receipt] of cases) {
        (0, node_test_1.it)(`builds ${claim_type}`, () => {
            const frame = (0, index_js_1.buildPef)({ claim_type, receipt, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
            assert_1.strict.equal(frame.claim_type, claim_type);
            assert_1.strict.equal(frame.receipt_format, index_js_1.CLAIM_TYPES[claim_type]);
            assert_1.strict.equal(frame.pef_version, index_js_1.PEF_VERSION);
            assert_1.strict.equal(frame.canon_version, index_js_1.CANON_VERSION);
            assert_1.strict.equal(frame.frame_provider_did, PROVIDER_DID);
            assert_1.strict.equal(frame.frame_timestamp_ms, TS);
        });
    }
});
// ---------------------------------------------------------------------------
// 2. frame_id determinism
// ---------------------------------------------------------------------------
(0, node_test_1.describe)("frame_id", () => {
    (0, node_test_1.it)("is deterministic", () => {
        const f1 = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const f2 = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        assert_1.strict.equal(f1.frame_id, f2.frame_id);
    });
    (0, node_test_1.it)("changes with timestamp", () => {
        const f1 = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const f2 = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS + 1 });
        assert_1.strict.notEqual(f1.frame_id, f2.frame_id);
    });
    (0, node_test_1.it)("changes with claim_type", () => {
        const f1 = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const f2 = (0, index_js_1.buildPef)({ claim_type: "composite_verdict", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        assert_1.strict.notEqual(f1.frame_id, f2.frame_id);
    });
    (0, node_test_1.it)("ignores signature field", () => {
        const f = (0, index_js_1.buildPef)({ claim_type: "payment_settlement", receipt: SETTLEMENT_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS, signature: "sig" });
        const fNoSig = { ...f };
        delete fNoSig.signature;
        assert_1.strict.equal((0, index_js_1.pefFrameId)(f), (0, index_js_1.pefFrameId)(fNoSig));
    });
});
// ---------------------------------------------------------------------------
// 3. receipt_hash
// ---------------------------------------------------------------------------
(0, node_test_1.describe)("receipt_hash", () => {
    (0, node_test_1.it)("is load-bearing -- different receipts produce different hashes", () => {
        const r1 = { ...COMPLIANCE_RECEIPT, verdict: "ALLOW" };
        const r2 = { ...COMPLIANCE_RECEIPT, verdict: "DENY" };
        const f1 = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: r1, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const f2 = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: r2, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        assert_1.strict.notEqual(f1.receipt_hash, f2.receipt_hash);
        assert_1.strict.notEqual(f1.frame_id, f2.frame_id);
    });
});
// ---------------------------------------------------------------------------
// 4. verifyPef -- green
// ---------------------------------------------------------------------------
(0, node_test_1.describe)("verifyPef -- valid frames", () => {
    (0, node_test_1.it)("passes clean frame", () => {
        const f = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const r = (0, index_js_1.verifyPef)(f);
        assert_1.strict.equal(r.valid, true);
        assert_1.strict.deepEqual(r.errors, []);
    });
    (0, node_test_1.it)("passes frame with signature", () => {
        const f = (0, index_js_1.buildPef)({ claim_type: "payment_settlement", receipt: SETTLEMENT_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS, signature: "fake-sig" });
        assert_1.strict.equal((0, index_js_1.verifyPef)(f).valid, true);
    });
});
// ---------------------------------------------------------------------------
// 5. verifyPef -- error paths
// ---------------------------------------------------------------------------
(0, node_test_1.describe)("verifyPef -- error paths", () => {
    (0, node_test_1.it)("rejects unknown claim_type", () => {
        const f = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const bad = { ...f, claim_type: "unknown_type" };
        const r = (0, index_js_1.verifyPef)(bad);
        assert_1.strict.equal(r.valid, false);
        assert_1.strict.ok(r.errors.some(e => e.includes("Unknown claim_type")));
    });
    (0, node_test_1.it)("rejects wrong receipt_format", () => {
        const f = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const bad = { ...f, receipt_format: "wrong-format-v1" };
        assert_1.strict.equal((0, index_js_1.verifyPef)(bad).valid, false);
    });
    (0, node_test_1.it)("rejects tampered receipt", () => {
        const f = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const bad = { ...f, receipt: { ...COMPLIANCE_RECEIPT, verdict: "DENY" } };
        const r = (0, index_js_1.verifyPef)(bad);
        assert_1.strict.equal(r.valid, false);
        assert_1.strict.ok(r.errors.some(e => e.includes("receipt_hash mismatch")));
    });
    (0, node_test_1.it)("rejects tampered frame_id", () => {
        const f = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const bad = { ...f, frame_id: "sha256:" + "0".repeat(64) };
        const r = (0, index_js_1.verifyPef)(bad);
        assert_1.strict.equal(r.valid, false);
        assert_1.strict.ok(r.errors.some(e => e.includes("frame_id mismatch")));
    });
    (0, node_test_1.it)("rejects wrong canon_version", () => {
        const f = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const bad = { ...f, canon_version: "urn:x402:canonicalisation:jcs-rfc8785-v2" };
        assert_1.strict.equal((0, index_js_1.verifyPef)(bad).valid, false);
    });
    (0, node_test_1.it)("rejects wrong pef_version", () => {
        const f = (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS });
        const bad = { ...f, pef_version: "2" };
        assert_1.strict.equal((0, index_js_1.verifyPef)(bad).valid, false);
    });
});
// ---------------------------------------------------------------------------
// 6. Build error paths
// ---------------------------------------------------------------------------
(0, node_test_1.describe)("buildPef -- error paths", () => {
    (0, node_test_1.it)("throws on unknown claim_type", () => {
        assert_1.strict.throws(() => (0, index_js_1.buildPef)({ claim_type: "bogus", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: TS }), /Unknown claim_type/);
    });
    (0, node_test_1.it)("throws on negative timestamp", () => {
        assert_1.strict.throws(() => (0, index_js_1.buildPef)({ claim_type: "payment_admission", receipt: COMPLIANCE_RECEIPT, frame_provider_did: PROVIDER_DID, frame_timestamp_ms: -1 }), /non-negative integer/);
    });
});
