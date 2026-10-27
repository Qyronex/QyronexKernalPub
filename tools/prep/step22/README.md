# Wave B validator

Run from the repository root:

```bash
python3 tools/prep/step22/validate_wave.py
python3 tests/prep/step22/test_validate_wave.py
python3 tests/prep/step22/test_secure_storage_runtime_proof.py
```

Expected markers:

- `PREP_WAVE_B_OK steps=22,23,24,25,26`
- `PREP_WAVE_B_TEST_OK`
- `STEP22_SECURE_PROOF_HARNESS_OK cases=8`

## Secure-storage runtime proof

`tools/prep/step22/validate_secure_storage_runtime_proof.py` validates a future exact-SHA runtime evidence bundle. It independently reads the supplied raw block-device image instead of trusting a reported plaintext metric.

The proof requires:

- exact 40-hex tested commit and `aarch64` architecture;
- declared storage/filesystem/crypto profiles and fixture hashes;
- authenticated data and authenticated metadata;
- at least two storage compartments and two effective key domains;
- every wrong-key attempt rejected;
- every ciphertext/metadata tamper attempt detected;
- zero cross-compartment read/write successes;
- zero silent unauthenticated recoveries;
- zero observed nonce reuse;
- zero declared plaintext-marker hits in the raw persistent-device image;
- a matching SHA-256 hash of the raw evidence artifact;
- no secret key material embedded in the evidence JSON.

The self-test includes one accepted synthetic bundle plus negative controls for plaintext leakage, cross-compartment reads, wrong-key acceptance, missed integrity tampering, nonce reuse, unauthenticated metadata and raw-artifact hash drift.

When the runtime secure-storage owner exists, capture the real raw device image and evidence JSON, then run:

```bash
python3 tools/prep/step22/validate_secure_storage_runtime_proof.py path/to/evidence.json
```

Expected real-proof marker:

`STEP22_SECURE_RUNTIME_PROOF_OK commit=<sha> compartments=<n> key_domains=<n> plaintext_hits=0`

Passing the PREP checks proves only that the evidence contract and proof harness are executable. A real `STEP22_SECURE_RUNTIME_PROOF_OK` claim requires runtime-generated evidence from the exact tested commit; it is not established by the synthetic self-test.
