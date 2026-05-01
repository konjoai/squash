#!/usr/bin/env bash
# Phase G — Bulletproof Edition · Sprint 1.1 — Coverage baseline runner
#
# What this does
# --------------
# 1. Installs the audit toolchain (`pip install -e .[dev,audit]`) if not present.
# 2. Runs the full test suite under `coverage` with branch coverage enabled.
# 3. Emits machine-readable artefacts (XML/JSON/HTML) for the CI badge step.
# 4. Prints the per-tier roll-up using the classification in TIER_MAP.md.
# 5. Runs `radon cc` and writes the D/E/F roll-up to `audit/cc_report.txt`.
#
# This is a *baseline* recorder, not a gate. Phase 4 raises `fail_under` per
# tier in pyproject.toml. Phase 1's job is to know where we stand.
#
# Usage
# -----
#   scripts/coverage_baseline.sh                # run everything
#   scripts/coverage_baseline.sh --quick        # tier-0 modules only (smoke)
#   scripts/coverage_baseline.sh --no-install   # skip pip install step
#
# Output goes to `audit/` (gitignored after Phase 1.1 commits the first run).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

QUICK=0
INSTALL=1
for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=1 ;;
        --no-install) INSTALL=0 ;;
        -h|--help) sed -n '2,/^$/p' "$0"; exit 0 ;;
    esac
done

mkdir -p audit

if [[ $INSTALL -eq 1 ]]; then
    echo "==> [1/4] Installing audit toolchain"
    python3 -m pip install --quiet -e ".[dev,audit]" 2>&1 | tail -5 || true
fi

echo "==> [2/4] Running pytest under coverage (branch=true)"
COVERAGE_FILE="$ROOT/.coverage" \
    python3 -m coverage run -m pytest -q \
        $( [[ $QUICK -eq 1 ]] && echo "tests/test_squash_attest.py tests/test_anchor.py" ) \
        2>&1 | tee audit/pytest.log

echo "==> [3/4] Generating reports (XML + JSON + HTML + terminal)"
python3 -m coverage xml  -o audit/coverage.xml
python3 -m coverage json -o audit/coverage.json
python3 -m coverage html -d audit/htmlcov
python3 -m coverage report --skip-covered=false --precision=2 \
    | tee audit/coverage.txt

echo "==> [4/4] Cyclomatic complexity report (radon cc -nc -a)"
python3 -m radon cc squash/ -nc -a > audit/cc_report.txt 2>&1 || true
echo "    Functions at grade D/E/F:"
grep -cE ' [DEF]$' audit/cc_report.txt || true
echo "    Functions at grade F (worst):"
grep -E ' F$' audit/cc_report.txt || true

# Per-tier roll-up — best-effort grep against TIER_MAP.md.
# Phase 5 replaces this with `scripts/check_tier_map.py`.
echo
echo "==> Per-tier coverage (Tier 0 only, indicative):"
python3 - <<'PY'
import json, pathlib, re
data = json.loads(pathlib.Path("audit/coverage.json").read_text())
tier0 = [
    "squash/oms_signer.py", "squash/anchor.py", "squash/attest.py",
    "squash/slsa.py", "squash/chain_attest.py",
]
print(f"{'file':<40} {'lines':>6} {'cov%':>7} {'br%':>7}")
print("-" * 64)
for fname in tier0:
    f = data["files"].get(fname)
    if not f:
        print(f"{fname:<40} {'(missing from coverage.json)':>30}")
        continue
    s = f["summary"]
    line_pct = s.get("percent_covered", 0.0)
    br = f.get("summary", {})
    br_total = br.get("num_branches", 0)
    br_cov = br.get("covered_branches", 0)
    br_pct = (100.0 * br_cov / br_total) if br_total else 0.0
    print(f"{fname:<40} {s['num_statements']:>6} {line_pct:>7.2f} {br_pct:>7.2f}")
PY

echo
echo "==> Done. Artefacts in audit/."
echo "    Next: commit audit/coverage.txt + audit/cc_report.txt as the Phase 1 baseline."
