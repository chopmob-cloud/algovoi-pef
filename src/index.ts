/**
 * algovoi-pef -- Payment Evidence Frame (PEF) v1
 *
 * TypeScript reference implementation. Byte-for-byte parity with the
 * Python reference implementation under rfc8785 JCS canonicalization.
 *
 * Normative spec: draft-hopley-x402-payment-evidence-frame (IETF I-D)
 * Canonicalisation pin: urn:x402:canonicalisation:jcs-rfc8785-v1
 */

import canonicalize from "canonicalize";
import { createHash } from "crypto";

export const PEF_VERSION = "1" as const;
export const CANON_VERSION =
  "urn:x402:canonicalisation:jcs-rfc8785-v1" as const;

/** Closed enum: claim_type -> receipt_format */
export const CLAIM_TYPES: Record<string, string> = {
  payment_admission:    "compliance-receipt-v1",
  payment_settlement:   "settlement-attestation-v1",
  payment_cancellation: "cancellation-receipt-v1",
  payment_refund:       "refund-receipt-v1",
  composite_verdict:    "composite-trust-query-v1",
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function jcsBytes(obj: unknown): string {
  const canonical = canonicalize(obj);
  if (canonical === undefined) throw new Error("canonicalize returned undefined");
  return canonical;
}

function sha256Jcs(obj: unknown): string {
  const canonical = jcsBytes(obj);
  return "sha256:" + createHash("sha256").update(canonical, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BuildPefOptions {
  claim_type: string;
  receipt: Record<string, unknown>;
  frame_provider_did: string;
  frame_timestamp_ms: number;
  signature?: string;
}

export interface Pef {
  canon_version:      string;
  claim_type:         string;
  frame_id:           string;
  frame_provider_did: string;
  frame_timestamp_ms: number;
  pef_version:        string;
  receipt:            Record<string, unknown>;
  receipt_format:     string;
  receipt_hash:       string;
  signature?:         string;
  [key: string]:      unknown;
}

export interface VerifyResult {
  valid:  boolean;
  errors: string[];
  /** Whether the frame carries a detached RFC 9421 signature string. */
  signature_present: boolean;
  /**
   * Always false at the frame layer. A PEF carried as an A2A DataPart
   * arrives with no HTTP message context (no Signature-Input, no
   * @signature-params, no covered components), so a frame-layer verifier
   * MUST report the transport signature as unverified rather than
   * reconstruct that context or derive a key from frame_provider_did.
   */
  signature_verified: boolean;
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
export function buildPef(options: BuildPefOptions): Pef {
  const { claim_type, receipt, frame_provider_did, frame_timestamp_ms, signature } = options;

  if (!(claim_type in CLAIM_TYPES)) {
    throw new Error(
      `Unknown claim_type ${JSON.stringify(claim_type)}. ` +
      `Must be one of: ${Object.keys(CLAIM_TYPES).sort().join(", ")}`
    );
  }
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) {
    throw new TypeError(`receipt must be a plain object`);
  }
  if (!Number.isInteger(frame_timestamp_ms) || frame_timestamp_ms < 0) {
    throw new Error("frame_timestamp_ms must be a non-negative integer");
  }

  const receipt_format = CLAIM_TYPES[claim_type];
  const receipt_hash   = sha256Jcs(receipt);

  const preimage: Record<string, unknown> = {
    canon_version:      CANON_VERSION,
    claim_type,
    frame_provider_did,
    frame_timestamp_ms,
    pef_version:        PEF_VERSION,
    receipt,
    receipt_format,
    receipt_hash,
  };

  const frame_id = sha256Jcs(preimage);
  const frame: Pef = { ...preimage, frame_id } as Pef;

  if (signature !== undefined) {
    frame.signature = signature;
  }

  return frame;
}

/**
 * Re-derive frame_id from a PEF object (strips frame_id and signature).
 */
export function pefFrameId(frame: Partial<Pef>): string {
  const stripped: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(frame)) {
    if (k !== "frame_id" && k !== "signature") stripped[k] = v;
  }
  return sha256Jcs(stripped);
}

/**
 * Verify the structural integrity of a PEF.
 *
 * Does NOT verify the RFC 9421 signature -- use algovoi-rfc9421-verifier
 * with the signer's public key for that.
 */
export function verifyPef(frame: Record<string, unknown>): VerifyResult {
  const errors: string[] = [];

  // 1. pef_version
  if (frame.pef_version !== PEF_VERSION) {
    errors.push(
      `pef_version must be ${JSON.stringify(PEF_VERSION)}, got ${JSON.stringify(frame.pef_version)}`
    );
  }

  // 2. claim_type
  const claim_type = frame.claim_type as string;
  if (!(claim_type in CLAIM_TYPES)) {
    errors.push(
      `Unknown claim_type ${JSON.stringify(claim_type)}. ` +
      `Must be one of: ${Object.keys(CLAIM_TYPES).sort().join(", ")}`
    );
  }

  // 3. receipt_format
  const expectedFormat = CLAIM_TYPES[claim_type];
  if (expectedFormat && frame.receipt_format !== expectedFormat) {
    errors.push(
      `receipt_format mismatch for claim_type ${JSON.stringify(claim_type)}: ` +
      `expected ${JSON.stringify(expectedFormat)}, got ${JSON.stringify(frame.receipt_format)}`
    );
  }

  // 4. canon_version
  if (frame.canon_version !== CANON_VERSION) {
    errors.push(
      `canon_version must be ${JSON.stringify(CANON_VERSION)}, ` +
      `got ${JSON.stringify(frame.canon_version)}`
    );
  }

  // 5. receipt_hash
  const receipt = frame.receipt;
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) {
    errors.push("receipt must be a plain object");
  } else {
    const actualReceiptHash = sha256Jcs(receipt);
    if (actualReceiptHash !== frame.receipt_hash) {
      errors.push(
        `receipt_hash mismatch: expected ${actualReceiptHash}, got ${frame.receipt_hash}`
      );
    }
  }

  // 6. frame_id
  const actualFrameId = pefFrameId(frame as Partial<Pef>);
  if (actualFrameId !== frame.frame_id) {
    errors.push(
      `frame_id mismatch: expected ${actualFrameId}, got ${frame.frame_id}`
    );
  }

  return {
    valid: errors.length === 0,
    errors,
    // Transport signature is never verified at the frame layer: with no HTTP
    // message context (e.g. an A2A DataPart) it MUST be reported as unverified
    // rather than reconstructed or key-derived from the frame.
    signature_present: Object.prototype.hasOwnProperty.call(frame, "signature"),
    signature_verified: false,
  };
}
