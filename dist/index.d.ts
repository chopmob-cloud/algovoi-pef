/**
 * algovoi-pef -- Payment Evidence Frame (PEF) v1
 *
 * TypeScript reference implementation. Byte-for-byte parity with the
 * Python reference implementation under rfc8785 JCS canonicalization.
 *
 * Normative spec: draft-hopley-x402-payment-evidence-frame (IETF I-D)
 * Canonicalisation pin: urn:x402:canonicalisation:jcs-rfc8785-v1
 */
export declare const PEF_VERSION: "1";
export declare const CANON_VERSION: "urn:x402:canonicalisation:jcs-rfc8785-v1";
/** Closed enum: claim_type -> receipt_format */
export declare const CLAIM_TYPES: Record<string, string>;
export interface BuildPefOptions {
    claim_type: string;
    receipt: Record<string, unknown>;
    frame_provider_did: string;
    frame_timestamp_ms: number;
    signature?: string;
}
export interface Pef {
    canon_version: string;
    claim_type: string;
    frame_id: string;
    frame_provider_did: string;
    frame_timestamp_ms: number;
    pef_version: string;
    receipt: Record<string, unknown>;
    receipt_format: string;
    receipt_hash: string;
    signature?: string;
    [key: string]: unknown;
}
export interface VerifyResult {
    valid: boolean;
    errors: string[];
}
/**
 * Build a Payment Evidence Frame.
 *
 * @param options.claim_type         One of the five closed-enum values.
 * @param options.receipt            The inner receipt object.
 * @param options.frame_provider_did DID URI of the frame emitter.
 * @param options.frame_timestamp_ms Integer Unix epoch milliseconds.
 * @param options.signature          Optional detached RFC 9421 signature.
 */
export declare function buildPef(options: BuildPefOptions): Pef;
/**
 * Re-derive frame_id from a PEF object (strips frame_id and signature).
 */
export declare function pefFrameId(frame: Partial<Pef>): string;
/**
 * Verify the structural integrity of a PEF.
 *
 * Does NOT verify the RFC 9421 signature -- use algovoi-rfc9421-verifier
 * with the signer's public key for that.
 */
export declare function verifyPef(frame: Record<string, unknown>): VerifyResult;
//# sourceMappingURL=index.d.ts.map