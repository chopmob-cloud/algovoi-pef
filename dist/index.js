"use strict";
/**
 * algovoi-pef -- Payment Evidence Frame (PEF) v1
 *
 * TypeScript reference implementation. Byte-for-byte parity with the
 * Python reference implementation under rfc8785 JCS canonicalization.
 *
 * Normative spec: draft-hopley-x402-payment-evidence-frame (IETF I-D)
 * Canonicalisation pin: urn:x402:canonicalisation:jcs-rfc8785-v1
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CLAIM_TYPES = exports.CANON_VERSION = exports.PEF_VERSION = void 0;
exports.buildPef = buildPef;
exports.pefFrameId = pefFrameId;
exports.verifyPef = verifyPef;
const canonicalize_1 = __importDefault(require("canonicalize"));
const crypto_1 = require("crypto");
exports.PEF_VERSION = "1";
exports.CANON_VERSION = "urn:x402:canonicalisation:jcs-rfc8785-v1";
/** Closed enum: claim_type -> receipt_format */
exports.CLAIM_TYPES = {
    payment_admission: "compliance-receipt-v1",
    payment_settlement: "settlement-attestation-v1",
    payment_cancellation: "cancellation-receipt-v1",
    payment_refund: "refund-receipt-v1",
    composite_verdict: "composite-trust-query-v1",
};
// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
function jcsBytes(obj) {
    const canonical = (0, canonicalize_1.default)(obj);
    if (canonical === undefined)
        throw new Error("canonicalize returned undefined");
    return canonical;
}
function sha256Jcs(obj) {
    const canonical = jcsBytes(obj);
    return "sha256:" + (0, crypto_1.createHash)("sha256").update(canonical, "utf8").digest("hex");
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
/**
 * Build a Payment Evidence Frame.
 *
 * @param options.claim_type         One of the five closed-enum values.
 * @param options.receipt            The inner receipt object.
 * @param options.frame_provider_did DID URI of the frame emitter.
 * @param options.frame_timestamp_ms Integer Unix epoch milliseconds.
 * @param options.signature          Optional detached RFC 9421 signature.
 */
function buildPef(options) {
    const { claim_type, receipt, frame_provider_did, frame_timestamp_ms, signature } = options;
    if (!(claim_type in exports.CLAIM_TYPES)) {
        throw new Error(`Unknown claim_type ${JSON.stringify(claim_type)}. ` +
            `Must be one of: ${Object.keys(exports.CLAIM_TYPES).sort().join(", ")}`);
    }
    if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) {
        throw new TypeError(`receipt must be a plain object`);
    }
    if (!Number.isInteger(frame_timestamp_ms) || frame_timestamp_ms < 0) {
        throw new Error("frame_timestamp_ms must be a non-negative integer");
    }
    const receipt_format = exports.CLAIM_TYPES[claim_type];
    const receipt_hash = sha256Jcs(receipt);
    const preimage = {
        canon_version: exports.CANON_VERSION,
        claim_type,
        frame_provider_did,
        frame_timestamp_ms,
        pef_version: exports.PEF_VERSION,
        receipt,
        receipt_format,
        receipt_hash,
    };
    const frame_id = sha256Jcs(preimage);
    const frame = { ...preimage, frame_id };
    if (signature !== undefined) {
        frame.signature = signature;
    }
    return frame;
}
/**
 * Re-derive frame_id from a PEF object (strips frame_id and signature).
 */
function pefFrameId(frame) {
    const stripped = {};
    for (const [k, v] of Object.entries(frame)) {
        if (k !== "frame_id" && k !== "signature")
            stripped[k] = v;
    }
    return sha256Jcs(stripped);
}
/**
 * Verify the structural integrity of a PEF.
 *
 * Does NOT verify the RFC 9421 signature -- use algovoi-rfc9421-verifier
 * with the signer's public key for that.
 */
function verifyPef(frame) {
    const errors = [];
    // 1. pef_version
    if (frame.pef_version !== exports.PEF_VERSION) {
        errors.push(`pef_version must be ${JSON.stringify(exports.PEF_VERSION)}, got ${JSON.stringify(frame.pef_version)}`);
    }
    // 2. claim_type
    const claim_type = frame.claim_type;
    if (!(claim_type in exports.CLAIM_TYPES)) {
        errors.push(`Unknown claim_type ${JSON.stringify(claim_type)}. ` +
            `Must be one of: ${Object.keys(exports.CLAIM_TYPES).sort().join(", ")}`);
    }
    // 3. receipt_format
    const expectedFormat = exports.CLAIM_TYPES[claim_type];
    if (expectedFormat && frame.receipt_format !== expectedFormat) {
        errors.push(`receipt_format mismatch for claim_type ${JSON.stringify(claim_type)}: ` +
            `expected ${JSON.stringify(expectedFormat)}, got ${JSON.stringify(frame.receipt_format)}`);
    }
    // 4. canon_version
    if (frame.canon_version !== exports.CANON_VERSION) {
        errors.push(`canon_version must be ${JSON.stringify(exports.CANON_VERSION)}, ` +
            `got ${JSON.stringify(frame.canon_version)}`);
    }
    // 5. receipt_hash
    const receipt = frame.receipt;
    if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) {
        errors.push("receipt must be a plain object");
    }
    else {
        const actualReceiptHash = sha256Jcs(receipt);
        if (actualReceiptHash !== frame.receipt_hash) {
            errors.push(`receipt_hash mismatch: expected ${actualReceiptHash}, got ${frame.receipt_hash}`);
        }
    }
    // 6. frame_id
    const actualFrameId = pefFrameId(frame);
    if (actualFrameId !== frame.frame_id) {
        errors.push(`frame_id mismatch: expected ${actualFrameId}, got ${frame.frame_id}`);
    }
    return { valid: errors.length === 0, errors };
}
