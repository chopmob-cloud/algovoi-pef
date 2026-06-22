# PEF v1 conformance vectors

`pef_v1.json` holds the 8 Payment Evidence Frame conformance vectors, covering
all 5 claim types (`payment_admission`, `payment_settlement`,
`payment_cancellation`, `payment_refund`, `composite_verdict`).

Each vector carries the `preimage`, the inner `receipt`, and the expected
outputs: `expected_receipt_jcs_bytes_b64`, `expected_preimage_jcs_bytes_b64`,
`expected_receipt_hash`, and `expected_frame_id`. The hashes are SHA-256 over
JCS (RFC 8785) canonical bytes under the pin
`urn:x402:canonicalisation:jcs-rfc8785-v1`.

## Run them against this package

```bash
pip install -e .
python -m pytest tests/test_vectors.py -v
```

`tests/test_vectors.py` rebuilds every vector with `algovoi_pef.build_pef` and
asserts the `frame_id`, `receipt_hash`, and `verify_pef` result match the
expected values.

## Canonical source and cross language corpus

These vectors are mirrored from the authoritative corpus, where the same set is
validated byte for byte across eight independent JCS implementations in eight
languages (64 of 64 agreements):

- Corpus repo: [`chopmob-cloud/algovoi-jcs-conformance-vectors`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors), vector set `pef_v1`
- Cross validation attestation: `_attestations/2026-05-30-8-impl-pef-v1`
- The eight language harness and a one command validator are also bundled in the evaluation kit attached to the GitHub release.

If the two copies ever differ, the corpus repo is authoritative.
