# Wave A validator

Run from the repository root:

```bash
python3 tools/prep/step17/validate_wave.py
python3 tests/prep/step17/test_validate_wave.py
```

Expected markers:

- `PREP_WAVE_A_OK steps=17,18,19,20,21`
- `PREP_WAVE_A_TEST_OK`

Passing these checks proves only PREP manifest consistency. It is not runtime acceptance for Steps 17–21.
