---
paths: ["**/test_*.py", "**/tests/**"]
---
# Testing Rules
Every code file needs a corresponding test file. `python -m pytest` must be green.
Attestation tests: byte-identical output for same inputs must be verified.
Optional-dependency tests must be gated behind feature flags or env vars.
