---
paths: ["**/benchmarks/**", "**/bench_*.py"]
---
# Benchmarking Rules
- Minimum 5 warmup runs. Report p50/p95/p99/stddev.
- Attestation artifacts must be byte-identical across runs given the same inputs.
- Results in `benchmarks/results/<timestamp>/`. Never overwrite.
